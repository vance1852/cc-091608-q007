/**
 * 场景回放：按 fixtures/site-uploads.json 的步骤顺序驱动平台，
 * 逐步对照期望结果，并在末尾验证导出清单的稳定性与监管链完整性。
 */
import {
  CustodyPlatform,
  PermissionDenied,
} from "./platform.js";
import type {
  DatasetExport,
  StudyConfig,
} from "./contracts.js";
import { sha256Hex } from "./crypto.js";
import {
  buildFixture,
  STUDY,
  type SiteUploadsFixture,
  type FixtureStep,
  type UploadExpectation,
} from "./scenario.js";

export class ExpectationFailure extends Error {}

export interface ReplayResult {
  platform: CustodyPlatform;
  fixture: SiteUploadsFixture;
  passed: string[];
}

/** 用确定性时钟回放，使 recordedAt/frozenAt 在多次回放间保持一致。 */
function replayClock(stepIndex: number): string {
  const base = Date.parse("2026-03-15T07:00:00.000Z");
  return new Date(base + stepIndex * 1000).toISOString();
}

export function replay(fixture: SiteUploadsFixture = buildFixture()): ReplayResult {
  // 平台每次取钟都推进一秒，保证同一操作内多次取时与导出时刻严格递增、可复现。
  let tick = 0;
  const platform = new CustodyPlatform(() => {
    tick += 1;
    return replayClock(tick);
  });

  const studyConfig: StudyConfig = {
    studyId: fixture.study.studyId,
    allowedFirmware: fixture.study.allowedFirmware,
    // 盲态随机表仅在平台内部装载；站点材料与导出均不可见。
    randomization: STUDY.randomization,
  };
  platform.registerStudy(studyConfig);
  for (const device of fixture.devices) platform.registerDevice(device);
  for (const user of fixture.users) platform.addUser(user);

  const passed: string[] = [];
  const check = (label: string, cond: boolean, detail?: string): void => {
    if (!cond) {
      throw new ExpectationFailure(
        `期望不符 [${label}]${detail ? `：${detail}` : ""}`,
      );
    }
    passed.push(label);
  };

  fixture.steps.forEach((step, idx) => {
    const label = `步骤 ${idx + 1} ${step.op}`;
    switch (step.op) {
      case "custody": {
        const ev = platform.registerCustody(step.by, {
          eventId: step.eventId,
          studyId: fixture.study.studyId,
          siteId: step.siteId,
          subjectCode: step.subjectCode,
          serialNumber: step.serialNumber,
          action: step.action,
          occurredAt: step.occurredAt,
          ...(step.replacesSerialNumber !== undefined
            ? { replacesSerialNumber: step.replacesSerialNumber }
            : {}),
        });
        check(`${label} ${step.eventId}/${step.action}`, ev.eventId === step.eventId);
        break;
      }
      case "upload": {
        const result = platform.submitPackage(step.by, step.manifest, step.payloadText);
        assertUploadExpectation(step, result, check);
        break;
      }
      case "adjudicate": {
        const rec = platform.adjudicate(
          step.by, step.packageId, step.decision, step.reason,
        );
        check(`${label} ${step.packageId}/${step.decision}`,
          rec.decision === step.decision && rec.decidedBy === step.by);
        break;
      }
      case "resolveGap": {
        const gaps = platform.listGaps(step.by);
        const gap = gaps.find((g) => g.serialNumber === step.subjectSerial && g.status === "open");
        if (!gap) throw new ExpectationFailure(`${label}：没有找到 ${step.subjectSerial} 的开放缺口`);
        const resolved = platform.resolveGap(step.by, gap.gapId, step.resolution);
        check(`${label} ${step.subjectSerial}`,
          resolved.status === "resolved" && resolved.resolvedBy === step.by);
        break;
      }
      case "freeze": {
        const ds = platform.freezeDataset(step.by, step.datasetId);
        check(`${label} ${step.datasetId}`,
          ds.datasetId === step.datasetId, `revision=${ds.revision}`);
        break;
      }
      case "unblind": {
        const r = platform.requestUnblind(
          step.requester, step.confirmer, step.subjectCode, step.reason,
        );
        if (step.expect === "revealed") {
          check(`${label} revealed`,
            r.revealed && r.arm === STUDY.randomization[step.subjectCode],
            `arm=${r.arm ?? r.denialCode}`);
        } else {
          const code = step.expect.slice("denied:".length);
          check(`${label} ${code}`,
            !r.revealed && r.denialCode === code,
            `got=${r.denialCode ?? "revealed"}`);
        }
        break;
      }
    }
  });

  return { platform, fixture, passed };
}

function assertUploadExpectation(
  step: Extract<FixtureStep, { op: "upload" }>,
  result: ReturnType<CustodyPlatform["submitPackage"]>,
  check: (label: string, cond: boolean, detail?: string) => void,
): void {
  const expect: UploadExpectation = step.expect;
  const label = `upload ${step.manifest.packageId}（${step.note}）`;
  if (expect.startsWith("rejected:")) {
    const code = expect.slice("rejected:".length);
    check(`${label} 被拒 ${code}`,
      !result.accepted && result.rejected === true && result.code === code,
      `got=${result.accepted ? "accepted" : result.code}`);
    return;
  }
  if (!result.accepted) {
    throw new ExpectationFailure(`${label}：意外被拒 ${result.code}`);
  }
  if (expect === "accepted") {
    check(`${label} 接收`,
      !result.duplicate && result.state === "accepted" &&
        result.canonicalPackageId === step.manifest.packageId,
      `duplicate=${result.duplicate} state=${result.state}`);
  } else if (expect === "duplicate") {
    check(`${label} 返回原接收凭证`,
      result.duplicate === true &&
        result.canonicalPackageId !== step.manifest.packageId &&
        result.receiptId === receiptOf(step),
      `canonical=${result.canonicalPackageId}`);
  } else {
    check(`${label} 隔离待裁决`,
      result.duplicate === false && result.state === "quarantined" &&
        Boolean(result.quarantinedReason),
      result.quarantinedReason);
  }
}

/** 凭证号由 设备:摘要 决定，重放可独立预测。 */
function receiptOf(step: Extract<FixtureStep, { op: "upload" }>): string {
  return `rcpt-${sha256Hex(
    `${step.manifest.serialNumber}:${step.manifest.contentSha256}`,
  ).slice(0, 16)}`;
}

/** 导出后的跨切面不变量：稳定性、盲态隔离、站点可见域、监管链可还原性。 */
export function verifyExportInvariants(
  platform: CustodyPlatform,
  fixture: SiteUploadsFixture,
): { ds1: DatasetExport; ds2: DatasetExport } {
  const check = (label: string, cond: boolean, detail?: string): void => {
    if (!cond) throw new ExpectationFailure(`导出不变量失败 [${label}]${detail ? `：${detail}` : ""}`);
  };

  const datasets = platform.listDatasets("u-auditor");
  check("存在两个冻结批次", datasets.length === 2, `n=${datasets.length}`);

  const ds1a = platform.exportDataset("u-auditor", "ds-2026-03-15");
  const ds1b = platform.exportDataset("u-dm", "ds-2026-03-15");
  const ds2 = platform.exportDataset("u-auditor", "ds-2026-03-20");

  // 稳定导出：不同人、不同时刻重新导出同一冻结批次，摘要一致。
  check("冻结批次导出摘要稳定", ds1a.exportSha256 === ds1b.exportSha256,
    `${ds1a.exportSha256.slice(0, 12)} vs ${ds1b.exportSha256.slice(0, 12)}`);
  check("条目顺序稳定",
    JSON.stringify(ds1a.entries.map((e) => e.packageId)) ===
      JSON.stringify(ds1b.entries.map((e) => e.packageId)));
  check("修订版号递增且隔离", ds1a.revision === 1 && ds2.revision === 2);
  check("锁库后包不在修订版 1",
    !ds1a.entries.some((e) => e.packageId === "pkg-b027-d3"));
  check("锁库后包在修订版 2",
    ds2.entries.some((e) => e.packageId === "pkg-b027-d3" && e.included));

  // 纳入/排除/替代依据齐全。
  for (const ds of [ds1a, ds2]) {
    const json = JSON.stringify(ds);
    check("导出不含任何随机分组字样",
      !json.includes("control") && !json.includes("intervention"));
    for (const e of ds.entries) {
      check(`条目 ${e.packageId} 有依据代码`, e.basis.length > 0);
      check(`条目 ${e.packageId} 有依据说明`, e.basisDetail.length > 0);
      check(`条目 ${e.packageId} 有设备密钥标识`, e.deviceKeyId.startsWith("key-watch-"));
      check(`条目 ${e.packageId} 有接收凭证`, e.receiptId.startsWith("rcpt-"));
    }
  }

  // 修订版 1：原包、冲突包、校正包、替代包的状态。
  const byId = new Map(ds1a.entries.map((e) => [e.packageId, e]));
  check("原始包纳入", byId.get("pkg-a014-w205-d1")?.included === false
    && byId.get("pkg-a014-w205-d1")?.basis === "SUPERSEDED_BY_CORRECTION");
  check("校正包纳入并记录原因",
    byId.get("pkg-a014-w205-d1-corr")?.included === true
      && (byId.get("pkg-a014-w205-d1-corr")?.basisDetail.includes("时间戳整体漂移") ?? false));
  check("校正关系在导出中可查",
    ds1a.corrections.some(
      (c) => c.correctedPackageId === "pkg-a014-w205-d1"
        && c.correctionPackageId === "pkg-a014-w205-d1-corr"));
  check("冲突包裁决排除",
    byId.get("pkg-a014-d1-alt")?.state === "quarantined"
      && byId.get("pkg-a014-d1-alt")?.basis === "ADJUDICATED_EXCLUDED");
  check("重复提交不产生第二张清单行",
    ds1a.entries.filter((e) => e.contentSha256 === byId.get("pkg-a014-d1")?.contentSha256
      && e.serialNumber === "watch-100").length === 1);

  // 换机链可独立还原：issue(watch-100) → replace(watch-205, replaces watch-100)。
  const chainA = ds1a.subjectChains.find((c) => c.subjectCode === "A-014");
  check("A-014 换机链存在", Boolean(chainA));
  const links = chainA!.links;
  check("换机链首环节为发放 watch-100",
    links[0]?.action === "issue" && links[0]?.serialNumber === "watch-100");
  const replaceLink = links.find((l) => l.action === "replace");
  check("换机链含 replace 且交接序列号为 watch-100",
    replaceLink?.serialNumber === "watch-205" &&
      replaceLink?.replacesSerialNumber === "watch-100" &&
      replaceLink?.siteId === "site-b");
  const chainB = ds1a.subjectChains.find((c) => c.subjectCode === "B-027");
  check("B-027 链含遗失与补发",
    chainB?.links.some((l) => l.action === "lost" && l.serialNumber === "watch-310") === true
      && chainB?.links.some((l) => l.action === "issue" && l.serialNumber === "watch-311") === true);

  // 拒绝提交全部留痕且不计入清单。
  const rejectedCodes = new Set(ds1a.rejectedSubmissions.map((r) => r.code));
  const requiredRejectCodes = [
    "DIGEST_MISMATCH", "BAD_SIGNATURE", "FIRMWARE_NOT_LICENSED", "BAD_INTERVAL",
    "OUTSIDE_CUSTODY", "WRONG_SITE", "UNKNOWN_CORRECTION_TARGET", "UNKNOWN_DEVICE",
  ] as const;
  for (const code of requiredRejectCodes) {
    check(`拒绝留痕 ${code}`, rejectedCodes.has(code));
  }

  // 站点可见域：site-a 只见 site-a，site-b 只见 site-b。
  const aPkgs = platform.listPackages("u-sitea");
  const bPkgs = platform.listPackages("u-siteb");
  check("site-a 不见 site-b 包", aPkgs.every((p) => p.siteId === "site-a")
    && aPkgs.some((p) => p.packageId === "pkg-a014-w205-d1") === false);
  check("site-b 只见本站包", bPkgs.every((p) => p.siteId === "site-b")
    && bPkgs.some((p) => p.packageId === "pkg-a014-w205-d1"));

  // 越站监管登记必须抛授权错误并留拒绝审计。
  let denied = false;
  try {
    platform.registerCustody("u-siteb", {
      eventId: "evt-cross", studyId: fixture.study.studyId, siteId: "site-a",
      subjectCode: "A-014", serialNumber: "watch-100", action: "return",
      occurredAt: "2026-03-14T00:00:00.000Z",
    });
  } catch (e) {
    denied = e instanceof PermissionDenied;
  }
  check("越站登记被拒", denied);

  // 医学监查员：能看缺口与包清单，但任何途径都不返回随机表。
  const monitorGaps = platform.listGaps("u-monitor");
  check("监查员可处理缺口", monitorGaps.length >= 2);
  const monitorExport = platform.exportDataset("u-monitor", "ds-2026-03-15");
  check("监查员导出不含分组",
    !JSON.stringify(monitorExport).includes("intervention")
      && !JSON.stringify(monitorExport).includes("control"));

  // 审计：每次访问都有记录，且含被拒绝的越权尝试。
  const audit = platform.listAudit("u-auditor");
  check("审计非空", audit.length > fixturesAuditMinimum(fixture));
  check("审计含上传拒绝", audit.some((a) => a.action === "upload.reject"));
  check("审计含越权拒绝", audit.some((a) => !a.allowed));
  check("审计不泄露分组",
    !audit.some((a) => (a.detail ?? "").includes("control") || (a.detail ?? "").includes("intervention")));

  return { ds1: ds1a, ds2 };
}

function fixturesAuditMinimum(fixture: SiteUploadsFixture): number {
  return fixture.steps.filter((s: FixtureStep) => s.op === "upload").length;
}
