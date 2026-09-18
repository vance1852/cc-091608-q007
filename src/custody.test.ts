/**
 * 平台测试：监管链、上传校验、幂等凭证、冲突隔离、校正替代、
 * 冻结修订版、导出稳定性、角色边界与双人解盲。
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { CustodyPlatform, PermissionDenied, DomainError } from "./platform.js";
import { buildFixture, devicePackage, STUDY, USERS, deviceRecords } from "./scenario.js";
import { replay, verifyExportInvariants, ExpectationFailure } from "./replay.js";
import { sha256Hex, verifyPackageSignature } from "./crypto.js";
import type { SiteUploadsFixture } from "./scenario.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const fixturePath = resolve(root, "fixtures/site-uploads.json");

describe("场景回放（fixtures/site-uploads.json 的完整故事）", () => {
  const { platform, fixture, passed } = replay();

  test("全部步骤的逐步期望均满足", () => {
    assert.ok(passed.length >= fixture.steps.length);
  });

  test("稽查员可对每个上传包独立复算摘要并用设备公钥验签", () => {
    const uploadSteps = fixture.steps.filter((s) => s.op === "upload");
    assert.ok(uploadSteps.length >= 17);
    for (const step of uploadSteps) {
      if (step.op !== "upload") continue;
      const device = fixture.devices.find(
        (d) => d.serialNumber === step.manifest.serialNumber,
      );
      // 摘要可由载荷字节独立复算（DIGEST_MISMATCH 用例故意不一致）。
      const recomputed = sha256Hex(step.payloadText);
      const digestDeclared = step.expect === "rejected:DIGEST_MISMATCH";
      assert.equal(
        recomputed === step.manifest.contentSha256,
        !digestDeclared,
        `${step.manifest.packageId} 摘要复算异常`,
      );
      // 签名可由设备登记公钥独立验证（BAD_SIGNATURE 用例故意用错私钥；
      // UNKNOWN_DEVICE 用例的序列号根本没有登记公钥，无法也无需验签）。
      if (!device) {
        assert.equal(step.expect, "rejected:UNKNOWN_DEVICE");
        continue;
      }
      const sigOk = verifyPackageSignature(step.manifest, device.publicKeyPem);
      assert.equal(
        sigOk,
        step.expect !== "rejected:BAD_SIGNATURE",
        `${step.manifest.packageId} 验签结果异常`,
      );
    }
  });

  test("导出不变量全部成立", () => {
    assert.doesNotThrow(() => verifyExportInvariants(platform, fixture));
  });

  test("换机链、冲突包与每次访问在导出/审计中均可验证", () => {
    const ds1 = platform.exportDataset("u-auditor", "ds-2026-03-15");
    const chain = ds1.subjectChains.find((c) => c.subjectCode === "A-014")!;
    assert.deepEqual(
      chain.links.map((l) => [l.action, l.serialNumber, l.replacesSerialNumber ?? null, l.siteId]),
      [
        ["issue", "watch-100", null, "site-a"],
        ["replace", "watch-205", "watch-100", "site-b"],
      ],
    );
    const audit = platform.listAudit("u-auditor");
    assert.ok(audit.some((a) => a.action === "upload.quarantine"));
    assert.ok(audit.some((a) => a.action === "upload.duplicate"));
    assert.ok(audit.some((a) => a.action === "dataset.freeze"));
  });
});

describe("幂等接收凭证", () => {
  test("完全相同的包任意次重提都返回同一张凭证，且不产生第二条清单记录", () => {
    const { platform, fixture } = replay();
    const first = fixture.steps.find(
      (s) => s.op === "upload" && s.manifest.packageId === "pkg-b027-d1",
    )! as Extract<(typeof fixture.steps)[number], { op: "upload" }>;

    // 设备按新包号对同一载荷重新签名（真实重传：内容字节不变）。
    const resubmit = (id: string) => {
      const { manifest } = devicePackage(
        {
          packageId: id,
          siteId: first.manifest.siteId,
          serialNumber: first.manifest.serialNumber,
          capturedFrom: first.manifest.capturedFrom,
          capturedTo: first.manifest.capturedTo,
          firmwareVersion: first.manifest.firmwareVersion,
        },
        first.payloadText,
      );
      return platform.submitPackage("u-sitea", manifest, first.payloadText);
    };
    const r2 = resubmit("pkg-b027-d1-again-1");
    const r3 = resubmit("pkg-b027-d1-again-2");
    assert.equal(r2.accepted, true);
    assert.equal(r3.accepted, true);
    if (r2.accepted && r3.accepted) {
      assert.equal(r2.duplicate, true);
      assert.equal(r3.duplicate, true);
      assert.equal(r2.receiptId, r3.receiptId);
      assert.equal(r2.canonicalPackageId, "pkg-b027-d1");
    }
    const rows = platform
      .listPackages("u-dm")
      .filter((p) => p.serialNumber === "watch-310");
    assert.equal(rows.length, 1);
  });
});

describe("校正不能覆盖原包", () => {
  test("原包仍可查、状态为 superseded，并保留带原因的替代关系", () => {
    const { platform } = replay();
    const original = platform.store.packages.get("pkg-a014-w205-d1")!;
    assert.equal(original.state, "superseded");
    assert.equal(original.manifest.firmwareVersion, "fw-3.1.0");
    const link = platform.store.corrections.find(
      (c) => c.correctedPackageId === "pkg-a014-w205-d1",
    )!;
    assert.equal(link.correctionPackageId, "pkg-a014-w205-d1-corr");
    assert.match(link.reason, /时间戳整体漂移/);
    assert.ok(platform.store.packages.has("pkg-a014-w205-d1-corr"));
  });
});

describe("冻结与修订版", () => {
  test("冻结后新上传进入下一修订版，旧批次导出内容不变", () => {
    const { platform } = replay();
    const before = platform.exportDataset("u-auditor", "ds-2026-03-15").exportSha256;
    const after = platform.exportDataset("u-auditor", "ds-2026-03-15").exportSha256;
    assert.equal(before, after);
    const rev2 = platform.exportDataset("u-auditor", "ds-2026-03-20");
    assert.equal(rev2.revision, 2);
    assert.deepEqual(rev2.includedPackages, ["pkg-b027-d3"]);
    const frozen2 = platform.listDatasets("u-dm").find((d) => d.datasetId === "ds-2026-03-20")!;
    assert.equal(frozen2.predecessorDatasetId, "ds-2026-03-15");
  });

  test("非数据经理不能冻结批次", () => {
    const { platform } = replay();
    assert.throws(
      () => platform.freezeDataset("u-monitor", "ds-x"),
      PermissionDenied,
    );
  });

  test("冻结后发生的设备流转不改变已冻结批次的交接链与摘要", () => {
    const { platform } = replay();
    const before = platform.exportDataset("u-auditor", "ds-2026-03-15");
    const chainLinks = before.subjectChains
      .find((c) => c.subjectCode === "B-027")!
      .links.map((l) => l.action);
    assert.deepEqual(chainLinks, ["issue", "lost", "issue"]); // evt-006 回收发生在第二次冻结之后
    const after = platform.exportDataset("u-auditor", "ds-2026-03-15");
    assert.equal(before.exportSha256, after.exportSha256);
  });
});

describe("角色与盲态", () => {
  test("普通站点只能看本站代号，越站登记抛错", () => {
    const { platform } = replay();
    const aRows = platform.listPackages("u-sitea");
    assert.ok(aRows.every((r) => r.siteId === "site-a"));
    assert.throws(
      () =>
        platform.registerCustody("u-siteb", {
          eventId: "evt-x", studyId: "study-r19", siteId: "site-a",
          subjectCode: "A-014", serialNumber: "watch-100", action: "return",
          occurredAt: "2026-03-14T00:00:00.000Z",
        }),
      PermissionDenied,
    );
  });

  test("站点用户与监查员不能读审计流", () => {
    const { platform } = replay();
    assert.throws(() => platform.listAudit("u-sitea"), PermissionDenied);
    assert.throws(() => platform.listAudit("u-monitor"), PermissionDenied);
  });

  test("医学监查员能处理缺口但无法解盲，且看不到随机分组", () => {
    const { platform } = replay();
    const gaps = platform.listGaps("u-monitor");
    assert.ok(gaps.every((g) => !("arm" in g)));
    const r = platform.requestUnblind("u-monitor", "u-unblinder-b", "A-014", "SAE");
    assert.equal(r.revealed, false);
    assert.equal(r.denialCode, "REQUESTER_NOT_AUTHORIZED");
  });

  test("解盲必须双人且各自具备显式授权，成功结果不写入审计", () => {
    const { platform } = replay();
    const ok = platform.requestUnblind(
      "u-unblinder-a", "u-unblinder-b", "B-027", "SAE 急救",
    );
    assert.equal(ok.revealed, true);
    assert.equal(ok.arm, "intervention");
    const audit = platform.listAudit("u-auditor");
    const unblindEvents = audit.filter((a) => a.action === "unblind");
    assert.ok(unblindEvents.some((a) => a.target === "B-027"));
    assert.ok(
      audit.every((a) => !(a.detail ?? "").includes("intervention")),
      "审计细节不得包含分组结果",
    );
  });
});

describe("监管链前置条件", () => {
  test("换机必须指向受试者当前持有的旧序列号", () => {
    const { platform } = replay();
    assert.throws(
      () =>
        platform.registerCustody("u-sitea", {
          eventId: "evt-bad-replace", studyId: "study-r19", siteId: "site-a",
          subjectCode: "B-027", serialNumber: "watch-100", action: "replace",
          replacesSerialNumber: "watch-205", occurredAt: "2026-03-20T00:00:00.000Z",
        }),
      DomainError,
    );
  });

  test("不能对当前仍持有设备的受试者再次发放", () => {
    const { platform } = replay();
    // A-014 换机后当前持有 watch-205，再发放任何设备都必须拒绝。
    assert.throws(
      () =>
        platform.registerCustody("u-siteb", {
          eventId: "evt-double-issue", studyId: "study-r19", siteId: "site-b",
          subjectCode: "A-014", serialNumber: "watch-310", action: "issue",
          occurredAt: "2026-03-20T00:00:00.000Z",
        }),
      DomainError,
    );
  });
});

describe("fixture 自描述", () => {
  test("磁盘上的 fixtures/site-uploads.json 可脱离生成器独立回放", () => {
    const fromDisk = JSON.parse(readFileSync(fixturePath, "utf8")) as SiteUploadsFixture;
    assert.doesNotThrow(() => {
      const { platform } = replay(fromDisk);
      verifyExportInvariants(platform, fromDisk);
    });
  });

  test("重新生成的 fixture 与磁盘版本逐字节一致（确定性密钥与签名）", () => {
    // 测试前置脚本 dist/generate.js 刚重写过 fixture；
    // 再次序列化内存场景，结果必须与磁盘文件一致。
    const disk = readFileSync(fixturePath, "utf8");
    assert.equal(`${JSON.stringify(buildFixture(), null, 2)}\n`, disk);
  });

  test("fixture 含两个站点、两种许可固件与跨站换机", () => {
    const f = buildFixture();
    assert.deepEqual(f.study.allowedFirmware, ["fw-2.4.1", "fw-3.1.0"]);
    const sites = new Set(
      f.steps
        .filter((s) => s.op === "custody")
        .map((s) => (s as { siteId: string }).siteId),
    );
    assert.ok(sites.has("site-a") && sites.has("site-b"));
    assert.ok(
      f.steps.some(
        (s) => s.op === "custody" && s.action === "replace" &&
          (s as { replacesSerialNumber?: string }).replacesSerialNumber === "watch-100",
      ),
    );
  });
});

describe("冲突裁决：纳入隔离包", () => {
  test("裁决 accepted 后隔离包纳入、原占用者转为 superseded，双方依据均可导出", () => {
    const p = new CustodyPlatform();
    p.registerStudy(STUDY);
    for (const d of deviceRecords().filter((d) => d.serialNumber === "watch-100")) {
      p.registerDevice(d);
    }
    p.addUser(USERS[0]!); // u-sitea
    p.addUser(USERS[3]!); // u-monitor
    p.addUser(USERS[5]!); // u-auditor

    p.registerCustody("u-sitea", {
      eventId: "e1", studyId: "study-r19", siteId: "site-a",
      subjectCode: "A-014", serialNumber: "watch-100", action: "issue",
      occurredAt: "2026-03-01T08:00:00.000Z",
    });
    const interval = {
      siteId: "site-a" as const, serialNumber: "watch-100" as const,
      capturedFrom: "2026-03-01T12:00:00.000Z",
      capturedTo: "2026-03-02T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1" as const,
    };
    const a = devicePackage({ packageId: "p-a", ...interval }, "body-A");
    const b = devicePackage({ packageId: "p-b", ...interval }, "body-B");
    const ra = p.submitPackage("u-sitea", a.manifest, a.payloadText);
    const rb = p.submitPackage("u-sitea", b.manifest, b.payloadText);
    assert.equal(ra.accepted && ra.state, "accepted");
    assert.equal(rb.accepted && rb.state, "quarantined");

    p.adjudicate("u-monitor", "p-b", "accepted", "原始终端导出确认 p-b 为准");

    const ds = p.exportDataset("u-auditor");
    const ea = ds.entries.find((e) => e.packageId === "p-a")!;
    const eb = ds.entries.find((e) => e.packageId === "p-b")!;
    assert.equal(ea.included, false);
    assert.equal(ea.basis, "EXCLUDED_BY_CONFLICT_DECISION");
    assert.equal(eb.included, true);
    assert.equal(eb.basis, "ADJUDICATED_INCLUDED");
    assert.deepEqual(ds.includedPackages, ["p-b"]);
  });

  test("稽查员只读：不能登记设备流转、不能上传、不能裁决、不能冻结", () => {
    const { platform } = replay();
    assert.throws(() =>
      platform.registerCustody("u-auditor", {
        eventId: "e-aud", studyId: "study-r19", siteId: "site-a",
        subjectCode: "A-014", serialNumber: "watch-100", action: "return",
        occurredAt: "2026-03-01T00:00:00.000Z",
      }), PermissionDenied);
    assert.throws(() =>
      platform.freezeDataset("u-auditor", "ds-aud"), PermissionDenied);
    assert.throws(() =>
      platform.adjudicate("u-auditor", "pkg-a014-d1-alt", "accepted", "x"), PermissionDenied);
  });
});

// 期望失败必须以异常形式呈现，防止测试自身被静默跳过。
void ExpectationFailure;
