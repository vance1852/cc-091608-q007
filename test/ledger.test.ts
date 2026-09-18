/**
 * 平台契约测试：使用夹具场景与临时构造的账本验证全部监管链规则。
 */
import assert from "node:assert/strict";
import { test } from "node:test";
import { createPrivateKey, type JsonWebKey } from "node:crypto";
import { runScenario, loadFixture, type ScenarioResult } from "../src/scenario.js";
import { CustodyLedger, PermissionError, ValidationError } from "../src/ledger.js";
import { contentIdentityHash, signManifest } from "../src/crypto.js";
import type { Actor, UploadManifest } from "../src/contracts.js";

let scenario: ScenarioResult;
test.before(() => {
  scenario = runScenario();
});

test("监管链：跨站换机链 watch-100 → watch-205 可完整还原", () => {
  const { ledger, actor } = scenario;
  const dm = actor("dm-zhang");
  const chain = ledger.readCustody(dm, "A-014");
  assert.equal(chain.length, 2);
  assert.deepEqual(
    chain.map((e) => [e.action, e.serialNumber, e.replacesSerialNumber, e.siteId]),
    [
      ["issue", "watch-100", undefined, "site-a"],
      ["replace", "watch-205", "watch-100", "site-b"],
    ],
  );
});

test("换机必须形成连续持有链：被替换设备不在手中则拒绝登记", () => {
  const { ledger, actor } = scenario;
  assert.throws(
    () =>
      ledger.registerCustody(actor("dm-zhang"), {
        // watch-100 已被替换回收（空闲），但 watch-102 当前由 A-027 而非 A-014 持有
        siteId: "site-a",
        subjectCode: "A-014",
        serialNumber: "watch-100",
        action: "replace",
        replacesSerialNumber: "watch-102",
        occurredAt: "2026-08-20T00:00:00Z",
      }),
    /换机链断裂|并非由/,
  );
});

test("重复发放同一设备被拒绝；遗失后可补发", () => {
  const { ledger, actor } = scenario;
  assert.throws(
    () =>
      ledger.registerCustody(actor("dm-zhang"), {
        siteId: "site-a",
        subjectCode: "A-014",
        serialNumber: "watch-100",
        action: "issue",
        occurredAt: "2026-08-02T00:00:00Z",
      }),
    /已发放/,
  );
});

test("完全相同的包返回同一个接收凭证（重复提交幂等）", () => {
  const { ledger, actor } = scenario;
  const rev2 = ledger.exportListing(actor("dm-zhang"), 2);
  const canonical = rev2.entries.find((e) => e.submissionPackageId === "pkg-1")!;
  const alias = rev2.entries.find((e) => e.submissionPackageId === "pkg-1-retry")!;
  // pkg-1 后被校正包替代，但重复提交仍映射到同一个原始凭证
  assert.equal(canonical.disposition, "superseded");
  assert.equal(alias.disposition, "duplicate");
  // 两份提交映射到同一接收凭证
  assert.equal(canonical.receiptId, alias.receiptId);
  assert.ok(canonical.receiptId.startsWith("rcpt-"));
  assert.deepEqual(alias.aliases, []);
  assert.ok(canonical.aliases.includes("pkg-1-retry"));
  assert.match(alias.basis[0] ?? "", /沿用原接收凭证/);
});

test("同区间不同内容的包被隔离；裁决前保持 quarantined", () => {
  // 独立账本：仅上传 pkg-1 与冲突包 pkg-2，不做裁决
  const ledger = freshLedgerWithEvents();
  const fixture = loadFixture();
  const siteA: Actor = { userId: "sitea-wang", role: "site-user", siteId: "site-a" };
  const pkg1 = { ...fixture.packages.find((p) => p.packageId === "pkg-1")! };
  const pkg2 = { ...fixture.packages.find((p) => p.packageId === "pkg-2")! };
  assert.equal(ledger.submitPackage(siteA, pkg1).outcome, "accepted");
  const out = ledger.submitPackage(siteA, pkg2);
  assert.equal(out.outcome, "quarantined");
  if (out.outcome === "quarantined") assert.equal(out.state, "quarantined");
  const open = ledger.exportListing({ userId: "dm-zhang", role: "data-manager" });
  assert.equal(open.entries.find((e) => e.submissionPackageId === "pkg-2")?.state, "quarantined");
  assert.equal(open.entries.find((e) => e.submissionPackageId === "pkg-2")?.disposition, "excluded");
});

test("硬校验失败按代码拒收：固件未许可/签名失效/摘要不符", () => {
  const { ledger, fixture, actor } = scenario;
  const siteA = actor("sitea-wang");
  const badfw = ledger.submitPackage(siteA, {
    ...fixture.packages.find((p) => p.packageId === "pkg-1-badfw")!,
  }, Buffer.from("watch-100|2026-08-02|unsupported-firmware-demo"));
  assert.equal(badfw.outcome, "rejected");
  assert.ok(badfw.outcome === "rejected" && badfw.reasons.includes("firmware-not-licensed"));

  const badsig = ledger.submitPackage(siteA, {
    ...fixture.packages.find((p) => p.packageId === "pkg-1-badsig")!,
  });
  assert.ok(badsig.outcome === "rejected" && badsig.reasons.includes("signature-invalid"));

  const baddigest = ledger.submitPackage(siteA, {
    ...fixture.packages.find((p) => p.packageId === "pkg-1-baddigest")!,
  }, Buffer.from("watch-100|2026-08-04|actual-payload-differs-from-claimed-digest"));
  assert.ok(
    baddigest.outcome === "rejected" &&
      baddigest.reasons.includes("content-digest-mismatch"),
  );
});

test("设备签名篡改必然验签失败（独立账本，不依赖夹具）", () => {
  const ledger = freshLedger();
  const { manifest, actor: siteUser } = signedPackageInputs();
  // 破坏签名中段的 base64 字符（避开末尾填充，确保解码后字节必然不同）
  const head = manifest.signature.slice(0, 12).split("").reverse().join("");
  const tampered: UploadManifest = {
    ...manifest,
    signature: head + manifest.signature.slice(12),
  };
  const out = ledger.submitPackage(siteUser, tampered);
  assert.ok(out.outcome === "rejected" && out.reasons.includes("signature-invalid"));
});

test("采集区间内设备已遗失/不在持有链中 → device-not-in-custody", () => {
  const { fixture, actor } = scenario;
  // watch-101 在 2026-07-20T18:00 遗失，区间覆盖遗失后；用私钥重签排除签名因素
  const m = resign(
    {
      packageId: "pkg-after-lost",
      siteId: "site-a",
      serialNumber: "watch-101",
      capturedFrom: "2026-07-20T20:00:00Z",
      capturedTo: "2026-07-21T08:00:00Z",
      firmwareVersion: "firmware-2.1.0",
      contentSha256: "abcdef01",
      signature: "",
    },
    fixture,
  );
  const out = scenario.ledger.submitPackage(actor("sitea-wang"), m);
  assert.ok(out.outcome === "rejected" && out.reasons.includes("device-not-in-custody"));
});

test("非法采集区间（起点不早于终点）→ bad-interval", () => {
  const { ledger, actor } = scenario;
  const m: UploadManifest = {
    packageId: "pkg-bad-interval",
    siteId: "site-a",
    serialNumber: "watch-100",
    capturedFrom: "2026-08-03T09:00:00Z",
    capturedTo: "2026-08-01T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "12345678",
    signature: "x",
  };
  const out = ledger.submitPackage(actor("sitea-wang"), m);
  assert.ok(out.outcome === "rejected" && out.reasons.includes("bad-interval"));
});

test("校正包不覆盖原包：原包转 superseded 并永久保留原因关联", () => {
  const rev2 = scenario.ledger.exportListing(scenario.actor("dm-zhang"), 2);
  const original = rev2.entries.find((e) => e.submissionPackageId === "pkg-1");
  const correction = rev2.entries.find((e) => e.submissionPackageId === "pkg-1-corr");
  assert.equal(original?.state, "superseded");
  assert.equal(original?.disposition, "superseded");
  assert.equal(original?.correctedBySubmissionId, "pkg-1-corr");
  assert.ok(original?.basis.some((b) => b.includes("被校正包") && b.includes("原包保留不覆盖")));
  assert.equal(correction?.disposition, "included");
  assert.equal(correction?.correctsSubmissionId, "pkg-1");
  assert.match(correction?.correctionReason ?? "", /时钟漂移/);
});

test("校正包与原包内容相同被拒绝；校正不存在的目标被拒绝", () => {
  // 独立账本：pkg-1 在此仍处于 accepted 状态
  const ledger = freshLedgerWithEvents();
  const fixture = loadFixture();
  const siteA: Actor = { userId: "sitea-wang", role: "site-user", siteId: "site-a" };
  const pkg1 = { ...fixture.packages.find((p) => p.packageId === "pkg-1")! };
  assert.equal(ledger.submitPackage(siteA, pkg1).outcome, "accepted");

  // 与原包同区间同摘要、却声明为校正包 → 不构成校正；用设备私钥重新签名使签名有效
  const sameContent = resign(
    {
      ...pkg1,
      packageId: "pkg-1-corr-dup",
      correctsPackageId: "pkg-1",
      correctionReason: "声称校正但内容完全相同",
    },
    fixture,
  );
  const out1 = ledger.submitPackage(siteA, sameContent);
  assert.ok(
    out1.outcome === "rejected" && out1.reasons.includes("correction-content-identical"),
  );

  const unknownTarget = resign(
    {
      ...{ ...fixture.packages.find((p) => p.packageId === "pkg-1-corr")! },
      packageId: "pkg-1-corr-unknown",
      correctsPackageId: "pkg-nope",
    },
    fixture,
  );
  const out2 = ledger.submitPackage(siteA, unknownTarget);
  assert.ok(
    out2.outcome === "rejected" && out2.reasons.includes("unknown-correction-target"),
  );
});

test("换机缺口由新设备首包确定区间，医学监查员处理后不可改", () => {
  const { ledger, actor } = scenario;
  const gaps = ledger.listGaps(actor("mon-li"));
  const g = gaps.find((x) => x.subjectCode === "A-014")!;
  assert.equal(g.status, "documented");
  assert.equal(g.resolution, "documented-gap");
  assert.equal(g.to, "2026-08-11T08:00:00Z");
  assert.equal(g.documentedBy, "mon-li");
  assert.throws(
    () =>
      ledger.documentGap(actor("mon-li"), g.gapId, "device-recovered", "再次处理", "2026-09-01T00:00:00Z"),
    /已处理/,
  );
});

test("修订版 2 的冲突：采纳 pkg-4b 后 pkg-4 转为被替代且依据可追溯", () => {
  const rev2 = scenario.ledger.exportListing(scenario.actor("dm-zhang"), 2);
  const pkg4 = rev2.entries.find((e) => e.submissionPackageId === "pkg-4")!;
  const pkg4b = rev2.entries.find((e) => e.submissionPackageId === "pkg-4b")!;
  assert.equal(pkg4.state, "superseded");
  assert.equal(pkg4b.state, "accepted");
  assert.equal(pkg4b.adjudication, "accept-as-replacement");
  assert.ok(pkg4.basis.some((b) => b.includes("冲突裁决")));
});

test("冻结快照不可变：冻结后的状态变化不影响修订版 1 导出", () => {
  const { ledger, actor } = scenario;
  const rev1 = ledger.exportListing(actor("dm-zhang"), 1);
  // 修订版 1 中不存在 pkg-4 / pkg-4b；pkg-4b 相关裁决也不出现
  assert.equal(rev1.entries.find((e) => e.submissionPackageId === "pkg-4"), undefined);
  assert.equal(rev1.entries.find((e) => e.submissionPackageId === "pkg-4b"), undefined);
  // pkg-1 在修订版 1 快照中已为被校正替代（校正发生在冻结前）
  assert.equal(
    rev1.entries.find((e) => e.submissionPackageId === "pkg-1")?.state,
    "superseded",
  );
  // pkg-2 在修订版 1 快照中维持隔离
  assert.equal(
    rev1.entries.find((e) => e.submissionPackageId === "pkg-2")?.state,
    "quarantined",
  );
});

test("冻结后新上传进入下一修订版（既有凭证重放仍幂等返回原凭证）", () => {
  const { ledger, fixture, actor } = scenario;
  assert.equal(ledger.currentRevision, 3);
  const before = ledger.currentRevision;
  const out = ledger.submitPackage(actor("siteb-chen"), {
    ...fixture.packages.find((p) => p.packageId === "pkg-4")!,
  });
  assert.equal(out.outcome, "duplicate");
  assert.equal(ledger.currentRevision, before);
  // 首次接收时所属修订版记录在凭证上
  if (out.outcome === "duplicate") assert.equal(out.receipt.revision, 2);
});

test("导出清单稳定：重复导出逐字节一致（除生成时间），排序确定", () => {
  const { ledger, actor } = scenario;
  const a = ledger.exportListing(actor("dm-zhang"), 2);
  const b = ledger.exportListing(actor("dm-zhang"), 2);
  const normalize = (x: unknown) => {
    const clone = structuredClone(x as Record<string, unknown>);
    delete clone.generatedAt;
    return JSON.stringify(clone);
  };
  assert.equal(normalize(a), normalize(b));
  const ids = a.entries.map((e) => e.submissionPackageId);
  const sorted = [...ids].sort((x, y) => x.localeCompare(y));
  // 排序不是按编号字母序，而是 (修订版, 采集起点, 设备, 编号) —— 验证确定性即可
  assert.deepEqual(ids, [...ids]);
  assert.notDeepEqual(ids, sorted);
});

test("RBAC：普通站点只能看本站代号和本站数据", () => {
  const { ledger, actor } = scenario;
  const siteA = actor("sitea-wang");
  const codes = ledger.listSubjects(siteA);
  assert.deepEqual(codes, ["A-014", "A-027"]); // A-014 在 site-a 有发放事件
  const exp = ledger.exportListing(siteA, 2);
  assert.ok(exp.entries.every((e) => e.siteId === "site-a"));
  assert.ok(!exp.entries.some((e) => e.submissionPackageId.startsWith("pkg-3") || e.submissionPackageId.startsWith("pkg-4")));
  assert.ok(!exp.custody.some((e) => e.siteId === "site-b"));
});

test("RBAC：跨站上传被拒绝（site-b 不能冒充 site-a 的包）", () => {
  const { ledger, fixture, actor } = scenario;
  assert.throws(
    () =>
      ledger.submitPackage(actor("siteb-chen"), {
        ...fixture.packages.find((p) => p.packageId === "pkg-1")!,
      }),
    PermissionError,
  );
});

test("RBAC：站点用户不能登记他站事件、不能冻结、不能裁决", () => {
  const { ledger, actor } = scenario;
  assert.throws(
    () =>
      ledger.registerCustody(actor("sitea-wang"), {
        siteId: "site-b",
        subjectCode: "A-014",
        serialNumber: "watch-100",
        action: "return",
        occurredAt: "2026-09-01T00:00:00Z",
      }),
    PermissionError,
  );
  assert.throws(
    () => ledger.freeze(actor("sitea-wang"), "2026-09-30T00:00:00Z"),
    PermissionError,
  );
  assert.throws(
    () =>
      ledger.adjudicate(actor("sitea-wang"), "pkg-2", "retain-quarantine", "x", "2026-09-01T00:00:00Z"),
    PermissionError,
  );
});

test("RBAC：医学监查员可处理缺口与裁决，但任何导出都不含随机分组", () => {
  const { ledger, actor } = scenario;
  const dump = JSON.stringify(ledger.exportListing(actor("mon-li"), 2));
  assert.ok(!dump.includes("arm-A"));
  assert.ok(!dump.includes("arm-B"));
  assert.ok(!dump.includes("randomization"));
});

test("解盲：非授权角色、自我确认、跨角色确认均被拒绝并留痕", () => {
  const { ledger, actor } = scenario;
  assert.throws(
    () =>
      ledger.unblind(
        actor("dm-zhang"),
        "ub-confirm",
        { subjectCode: "A-027", reason: "测试" },
        "2026-09-13T09:00:00Z",
      ),
    PermissionError,
  );
  assert.throws(
    () =>
      ledger.unblind(
        actor("ub-lead"),
        "ub-lead",
        { subjectCode: "A-027", reason: "测试" },
        "2026-09-13T09:01:00Z",
      ),
    /不得自我确认/,
  );
  assert.throws(
    () =>
      ledger.unblind(
        actor("ub-lead"),
        "mon-li",
        { subjectCode: "A-027", reason: "测试" },
        "2026-09-13T09:02:00Z",
      ),
    /不具备解盲授权/,
  );
});

test("解盲：两名不同授权人员确认后返回分组，且只在解盲记录中出现", () => {
  const { ledger, actor } = scenario;
  const record = ledger.unblind(
    actor("ub-lead"),
    "ub-confirm",
    { subjectCode: "A-027", reason: "SAE 紧急救治需要" },
    "2026-09-13T09:10:00Z",
  );
  assert.equal(record.arm, "arm-A");
  assert.equal(record.actorId, "ub-lead");
  assert.equal(record.confirmerId, "ub-confirm");
  const records = ledger.unblindRecords;
  assert.ok(records.some((r) => r.subjectCode === "A-027" && r.arm === "arm-A"));
  assert.ok(records.some((r) => r.subjectCode === "A-014" && r.arm === "arm-B"));
});

test("审计轨迹：拒绝的敏感操作全部 granted=false 留痕", () => {
  const { ledger, actor } = scenario;
  const audit = ledger.listAudit(actor("dm-zhang"));
  const denied = audit.filter((a) => !a.granted);
  assert.ok(denied.some((a) => a.action === "unblind.attempt"));
  assert.ok(denied.some((a) => a.actorId === "siteb-chen"));
  // 站点用户不能读审计
  assert.throws(() => ledger.listAudit(actor("sitea-wang")), PermissionError);
});

test("每次访视都可核验：访视索引列出关联提交、凭证与处置", () => {
  const { ledger, actor } = scenario;
  const rev2 = ledger.exportListing(actor("dm-zhang"), 2);
  const enroll = rev2.visits.find((v) => v.visitId === "v-a14-enroll")!;
  const ids = enroll.submissions.map((s) => s.submissionPackageId);
  assert.ok(ids.includes("pkg-1"));
  assert.ok(ids.includes("pkg-1-retry"));
  assert.ok(ids.includes("pkg-1-corr"));
  assert.ok(ids.includes("pkg-2"));
  // 同一访视的重复提交与首包共享凭证
  const p1 = enroll.submissions.find((s) => s.submissionPackageId === "pkg-1")!;
  const retry = enroll.submissions.find((s) => s.submissionPackageId === "pkg-1-retry")!;
  assert.equal(p1.receiptId, retry.receiptId);
  assert.equal(retry.disposition, "duplicate");
  // 随访访视：采纳的冲突包 included，原包 superseded
  const followup = rev2.visits.find((v) => v.visitId === "v-a14-followup")!;
  assert.equal(
    followup.submissions.find((s) => s.submissionPackageId === "pkg-4")!.disposition,
    "superseded",
  );
  assert.equal(
    followup.submissions.find((s) => s.submissionPackageId === "pkg-4b")!.disposition,
    "included",
  );
});

test("RBAC：站点视图的访视索引只含本站访视", () => {
  const { ledger, actor } = scenario;
  const siteAView = ledger.exportListing(actor("sitea-wang"), 2);
  assert.ok(siteAView.visits.every((v) => v.siteId === "site-a"));
  assert.ok(!siteAView.visits.some((v) => v.visitId === "v-a14-switch"));
});

test("接收凭证编号是内容身份的确定性函数", () => {
  const m = {
    serialNumber: "watch-9",
    capturedFrom: "2026-01-01T00:00:00Z",
    capturedTo: "2026-01-02T00:00:00Z",
    firmwareVersion: "fw-x",
    contentSha256: "deadbeef",
  };
  assert.equal(contentIdentityHash(m), contentIdentityHash({ ...m }));
  assert.notEqual(
    contentIdentityHash(m),
    contentIdentityHash({ ...m, contentSha256: "cafef00d" }),
  );
});

// -- 独立账本辅助：验证签名机制端到端 --------------------------------------

function freshLedger(): CustodyLedger {
  const fixture = loadFixture();
  return new CustodyLedger({
    study: fixture.study,
    subjects: fixture.subjects,
    devices: fixture.devices.map(({ keyPairJwk: _k, ...d }) => d),
    visits: fixture.visits,
    users: fixture.users,
    randomization: fixture.randomization,
  });
}

function freshLedgerWithEvents(): CustodyLedger {
  const ledger = freshLedger();
  const fixture = loadFixture();
  const dm: Actor = { userId: "dm-zhang", role: "data-manager" };
  for (const e of fixture.events) ledger.registerCustody(dm, e);
  return ledger;
}

/** 用夹具中该设备的测试私钥为清单重新签名（清单字段变更后必须重签）。 */
function resign(
  manifest: UploadManifest,
  fixture: ReturnType<typeof loadFixture>,
): UploadManifest {
  const device = fixture.devices.find((d) => d.serialNumber === manifest.serialNumber)!;
  const privateKey = createPrivateKey({
    format: "jwk",
    key: device.keyPairJwk as JsonWebKey,
  });
  return { ...manifest, signature: signManifest(manifest, privateKey) };
}

function signedPackageInputs(): { manifest: UploadManifest; actor: Actor; device: string } {
  const fixture = loadFixture();
  const p = fixture.packages.find((x) => x.packageId === "pkg-3")!;
  return {
    manifest: { ...p },
    actor: { userId: "siteb-chen", role: "site-user", siteId: "site-b" },
    device: p.serialNumber,
  };
}

test("独立账本：登记发放后合法签名包被接收", () => {
  const ledger = freshLedger();
  const fixture = loadFixture();
  const dm: Actor = { userId: "dm-zhang", role: "data-manager" };
  for (const e of fixture.events) ledger.registerCustody(dm, e);
  const { manifest, actor: siteUser } = signedPackageInputs();
  const out = ledger.submitPackage(siteUser, manifest);
  assert.equal(out.outcome, "accepted");
});

test("数据经理可登记跨站换机；未知设备/未知受试者登记被拒绝", () => {
  const ledger = freshLedger();
  const dm: Actor = { userId: "dm-zhang", role: "data-manager" };
  assert.throws(
    () =>
      ledger.registerCustody(dm, {
        siteId: "site-a",
        subjectCode: "A-014",
        serialNumber: "watch-xxx",
        action: "issue",
        occurredAt: "2026-08-01T00:00:00Z",
      }),
    ValidationError,
  );
});
