/**
 * 场景定义与 fixture 生成器。
 *
 * 故事覆盖：跨站换机交接、站点重复提交（同凭证）、同区间异内容冲突隔离、
 * 八类上传拒绝、校正替代（原包保留）、设备遗失缺口与医学监查处理、
 * 两次冻结修订版、以及四种解盲尝试。
 *
 * 设备私钥由序列号确定性派生、仅用于在此处模拟设备端签名；
 * 写入 fixture 的只有公钥、摘要与签名，私钥从不出现在任何文件中。
 */
import type {
  CustodyAction,
  DeviceRecord,
  PackageRejectionCode,
  StudyConfig,
  UploadManifest,
  User,
} from "./contracts.js";
import { deriveDeviceIdentity, sha256Hex, signPackage } from "./crypto.js";

// ---------------------------------------------------------------------------
// Fixture 结构
// ---------------------------------------------------------------------------

export type UploadExpectation =
  | "accepted"
  | "duplicate"
  | "quarantined"
  | `rejected:${PackageRejectionCode}`;

export type FixtureStep =
  | {
      op: "custody";
      by: string;
      eventId: string;
      siteId: string;
      subjectCode: string;
      serialNumber: string;
      action: CustodyAction;
      occurredAt: string;
      replacesSerialNumber?: string;
    }
  | {
      op: "upload";
      by: string;
      expect: UploadExpectation;
      note: string;
      manifest: UploadManifest;
      payloadText: string;
    }
  | {
      op: "adjudicate";
      by: string;
      packageId: string;
      decision: "accepted" | "excluded";
      reason: string;
    }
  | { op: "resolveGap"; by: string; subjectSerial: string; resolution: string }
  | { op: "freeze"; by: string; datasetId: string }
  | {
      op: "unblind";
      requester: string;
      confirmer: string;
      subjectCode: string;
      reason: string;
      expect: "revealed" | `denied:${string}`;
    };

export interface SiteUploadsFixture {
  schemaVersion: 2;
  study: { studyId: string; allowedFirmware: string[] };
  users: User[];
  devices: DeviceRecord[];
  steps: FixtureStep[];
}

// ---------------------------------------------------------------------------
// 固定场景常量
// ---------------------------------------------------------------------------

export const STUDY: StudyConfig = {
  studyId: "study-r19",
  // 两站点使用不同固件，但均在研究许可名单内。
  allowedFirmware: ["fw-2.4.1", "fw-3.1.0"],
  // 盲态随机表由申办方单独密封装载，绝不进入站点上传材料。
  randomization: { "A-014": "control", "B-027": "intervention" },
};

export const USERS: User[] = [
  { userId: "u-sitea", displayName: "站点A协调员", role: "site-user", siteId: "site-a" },
  { userId: "u-siteb", displayName: "站点B协调员", role: "site-user", siteId: "site-b" },
  { userId: "u-sitec", displayName: "站点C协调员", role: "site-user", siteId: "site-c" },
  { userId: "u-monitor", displayName: "医学监查员", role: "medical-monitor" },
  { userId: "u-dm", displayName: "数据经理", role: "data-manager" },
  { userId: "u-auditor", displayName: "独立稽查员", role: "auditor" },
  // 解盲授权显式授予，与角色分离。
  { userId: "u-unblinder-a", displayName: "解盲授权人甲", role: "data-manager", permissions: ["UNBLIND"] },
  { userId: "u-unblinder-b", displayName: "解盲授权人乙", role: "medical-monitor", permissions: ["UNBLIND"] },
];

export const DEVICE_SERIALS = ["watch-100", "watch-205", "watch-310", "watch-311"];

export function deviceRecords(): DeviceRecord[] {
  return DEVICE_SERIALS.map((serialNumber) => {
    const id = deriveDeviceIdentity(serialNumber);
    return {
      serialNumber,
      keyId: id.keyId,
      publicKeyPem: id.publicKeyPem,
      registeredAt: "2026-02-20T00:00:00.000Z",
    };
  });
}

// ---------------------------------------------------------------------------
// 设备端模拟：由载荷文本计算摘要并签名
// ---------------------------------------------------------------------------

interface ManifestFields {
  packageId: string;
  siteId: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  correctsPackageId?: string;
  correctionReason?: string;
}

/** 模拟设备端：按载荷字节计算摘要并用设备私钥签名（换包号也必须重新签名）。 */
export function devicePackage(
  fields: ManifestFields,
  payloadText: string,
  signAsSerial = fields.serialNumber,
  digestOverride?: string,
): { manifest: UploadManifest; payloadText: string } {
  const contentSha256 = digestOverride ?? sha256Hex(payloadText);
  const { privateKey } = deriveDeviceIdentity(signAsSerial);
  const manifest: UploadManifest = {
    packageId: fields.packageId,
    siteId: fields.siteId,
    serialNumber: fields.serialNumber,
    capturedFrom: fields.capturedFrom,
    capturedTo: fields.capturedTo,
    firmwareVersion: fields.firmwareVersion,
    contentSha256,
    signature: signPackage(
      {
        packageId: fields.packageId,
        serialNumber: fields.serialNumber,
        capturedFrom: fields.capturedFrom,
        capturedTo: fields.capturedTo,
        firmwareVersion: fields.firmwareVersion,
        contentSha256,
        ...(fields.correctsPackageId !== undefined
          ? { correctsPackageId: fields.correctsPackageId }
          : {}),
      },
      privateKey,
    ),
  };
  if (fields.correctsPackageId !== undefined) {
    manifest.correctsPackageId = fields.correctsPackageId;
  }
  if (fields.correctionReason !== undefined) {
    manifest.correctionReason = fields.correctionReason;
  }
  return { manifest, payloadText };
}

function payload(body: string): string {
  return `wearable-export/v1\n${body}\n`;
}

// ---------------------------------------------------------------------------
// 场景装配
// ---------------------------------------------------------------------------

export function buildFixture(): SiteUploadsFixture {
  const steps: FixtureStep[] = [];
  const custody = (c: Omit<Extract<FixtureStep, { op: "custody" }>, "op">): void => {
    steps.push({ op: "custody", ...c });
  };
  const upload = (
    by: string,
    expect: UploadExpectation,
    note: string,
    fields: ManifestFields,
    payloadText: string,
    signAsSerial?: string,
    digestOverride?: string,
  ): void => {
    const { manifest } = devicePackage(fields, payloadText, signAsSerial, digestOverride);
    steps.push({ op: "upload", by, expect, note, manifest, payloadText });
  };

  // --- 设备发放 -----------------------------------------------------------
  custody({
    by: "u-sitea", eventId: "evt-001", siteId: "site-a", subjectCode: "A-014",
    serialNumber: "watch-100", action: "issue", occurredAt: "2026-03-01T08:00:00.000Z",
  });
  custody({
    by: "u-sitea", eventId: "evt-002", siteId: "site-a", subjectCode: "B-027",
    serialNumber: "watch-310", action: "issue", occurredAt: "2026-03-05T08:00:00.000Z",
  });

  // --- A-014：watch-100 首包、重复提交、冲突包、各类拒包 -------------------
  const p1Body = "subject=A-014|serial=watch-100|window=2026-03-01..03-02|seq=0001";
  upload("u-sitea", "accepted", "A-014 首访原始包",
    {
      packageId: "pkg-a014-d1", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-01T12:00:00.000Z", capturedTo: "2026-03-02T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    }, payload(p1Body));
  upload("u-sitea", "duplicate", "站点重复提交：完全相同的包（不同包号）",
    {
      packageId: "pkg-a014-d1-resubmit", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-01T12:00:00.000Z", capturedTo: "2026-03-02T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    }, payload(p1Body));
  upload("u-sitea", "quarantined", "同区间异内容：声明同一采集区间但数据不同，隔离",
    {
      packageId: "pkg-a014-d1-alt", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-01T12:00:00.000Z", capturedTo: "2026-03-02T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    }, payload("subject=A-014|serial=watch-100|window=2026-03-01..03-02|seq=0099"));
  upload("u-sitea", "rejected:DIGEST_MISMATCH", "传输后被改动：摘要与实际字节不符",
    {
      packageId: "pkg-a014-d1-tampered", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-02T12:00:00.000Z", capturedTo: "2026-03-03T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    },
    payload(p1Body + "\nTAMPERED"),
    "watch-100",
    sha256Hex(payload(p1Body)));
  upload("u-sitea", "rejected:BAD_SIGNATURE", "非本机签名：用 watch-205 的私钥签 watch-100 的包",
    {
      packageId: "pkg-a014-d1-foreignsig", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-03T12:00:00.000Z", capturedTo: "2026-03-04T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    },
    payload("subject=A-014|serial=watch-100|window=2026-03-03..03-04|seq=0002"),
    "watch-205");
  upload("u-sitea", "rejected:FIRMWARE_NOT_LICENSED", "未获研究许可的固件版本",
    {
      packageId: "pkg-a014-d1-badfw", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-04T12:00:00.000Z", capturedTo: "2026-03-05T12:00:00.000Z",
      firmwareVersion: "fw-0.0.9-beta",
    },
    payload("subject=A-014|serial=watch-100|window=2026-03-04..03-05|seq=0003"));
  upload("u-sitea", "rejected:BAD_INTERVAL", "采集区间起止颠倒",
    {
      packageId: "pkg-a014-d1-badinterval", siteId: "site-a", serialNumber: "watch-100",
      capturedFrom: "2026-03-06T12:00:00.000Z", capturedTo: "2026-03-05T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    },
    payload("subject=A-014|serial=watch-100|window=reversed|seq=0004"));

  // --- B-027：正常包与重复提交，随后设备遗失 --------------------------------
  const b1Body = "subject=B-027|serial=watch-310|window=2026-03-06..03-07|seq=0001";
  upload("u-sitea", "accepted", "B-027 随访包",
    {
      packageId: "pkg-b027-d1", siteId: "site-a", serialNumber: "watch-310",
      capturedFrom: "2026-03-06T12:00:00.000Z", capturedTo: "2026-03-07T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    }, payload(b1Body));
  upload("u-sitea", "duplicate", "重复提交批次中的第二份",
    {
      packageId: "pkg-b027-d1-copy", siteId: "site-a", serialNumber: "watch-310",
      capturedFrom: "2026-03-06T12:00:00.000Z", capturedTo: "2026-03-07T12:00:00.000Z",
      firmwareVersion: "fw-2.4.1",
    }, payload(b1Body));
  custody({
    by: "u-sitea", eventId: "evt-003", siteId: "site-a", subjectCode: "B-027",
    serialNumber: "watch-310", action: "lost", occurredAt: "2026-03-08T08:00:00.000Z",
  });
  custody({
    by: "u-sitea", eventId: "evt-004", siteId: "site-a", subjectCode: "B-027",
    serialNumber: "watch-311", action: "issue", occurredAt: "2026-03-09T08:00:00.000Z",
  });
  upload("u-sitea", "accepted", "补发设备 watch-311 的首批数据",
    {
      packageId: "pkg-b027-d2", siteId: "site-a", serialNumber: "watch-311",
      capturedFrom: "2026-03-09T12:00:00.000Z", capturedTo: "2026-03-10T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=B-027|serial=watch-311|window=2026-03-09..03-10|seq=0001"));

  // --- 跨站换机：换机前新序列号的数据必须落在占有窗口之外 ------------------
  upload("u-siteb", "rejected:OUTSIDE_CUSTODY", "换机尚未登记：watch-205 的采集区间无占有窗口支撑",
    {
      packageId: "pkg-a014-w205-early", siteId: "site-b", serialNumber: "watch-205",
      capturedFrom: "2026-03-05T12:00:00.000Z", capturedTo: "2026-03-06T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=A-014|serial=watch-205|window=2026-03-05..03-06|seq=0001"));
  custody({
    by: "u-siteb", eventId: "evt-005", siteId: "site-b", subjectCode: "A-014",
    serialNumber: "watch-205", action: "replace", replacesSerialNumber: "watch-100",
    occurredAt: "2026-03-10T09:00:00.000Z",
  });

  // --- 换机后：越站提交被拒；site-b 正常上传；校正包以原因替代 --------------
  upload("u-sitec", "rejected:WRONG_SITE", "无关站点 site-c 冒充提交 A-014 的换机数据",
    {
      packageId: "pkg-a014-w205-sitec", siteId: "site-c", serialNumber: "watch-205",
      capturedFrom: "2026-03-11T12:00:00.000Z", capturedTo: "2026-03-12T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=A-014|serial=watch-205|window=2026-03-11..03-12|seq=0001|from=c"));
  upload("u-siteb", "accepted", "换机后 watch-205 首批数据（不同固件 fw-3.1.0）",
    {
      packageId: "pkg-a014-w205-d1", siteId: "site-b", serialNumber: "watch-205",
      capturedFrom: "2026-03-11T12:00:00.000Z", capturedTo: "2026-03-12T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=A-014|serial=watch-205|window=2026-03-11..03-12|seq=0001"));
  upload("u-siteb", "accepted",
    "校正包：不覆盖原包，以原因建立替代关系（时间戳漂移重导出）",
    {
      packageId: "pkg-a014-w205-d1-corr", siteId: "site-b", serialNumber: "watch-205",
      capturedFrom: "2026-03-11T12:00:37.000Z", capturedTo: "2026-03-12T12:00:37.000Z",
      firmwareVersion: "fw-3.1.0",
      correctsPackageId: "pkg-a014-w205-d1",
      correctionReason: "设备时间戳整体漂移 +37 秒，按 SOP-WEAR-07 以平台时钟对齐后重新导出",
    },
    payload("subject=A-014|serial=watch-205|window=2026-03-11..03-12|seq=0001|realigned=-37s"));
  upload("u-siteb", "rejected:UNKNOWN_CORRECTION_TARGET", "校正目标包不存在",
    {
      packageId: "pkg-a014-corr-ghost", siteId: "site-b", serialNumber: "watch-205",
      capturedFrom: "2026-03-12T12:00:00.000Z", capturedTo: "2026-03-13T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
      correctsPackageId: "pkg-never-existed",
      correctionReason: "试图校正一个系统中不存在的包",
    },
    payload("subject=A-014|serial=watch-205|window=2026-03-12..03-13|seq=ghost"));
  upload("u-siteb", "rejected:UNKNOWN_DEVICE", "未登记设备序列号",
    {
      packageId: "pkg-unknown-device", siteId: "site-b", serialNumber: "watch-999",
      capturedFrom: "2026-03-12T12:00:00.000Z", capturedTo: "2026-03-13T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=X|serial=watch-999|window=2026-03-12..03-13"));

  // --- 医学监查员：裁决冲突包、关闭遗失缺口（全程不接触随机分组）-------------
  steps.push({
    op: "adjudicate", by: "u-monitor", packageId: "pkg-a014-d1-alt",
    decision: "excluded",
    reason: "站点无法提供该副本的设备原始导出凭证，与已接收包区间冲突，按 DMP 第 9.2 条排除",
  });
  steps.push({
    op: "resolveGap", by: "u-monitor", subjectSerial: "watch-310",
    resolution: "watch-310 遗失已备案，申办方于 2026-03-09 补发 watch-311，中断区间无采集数据可恢复",
  });

  // --- 第一次冻结：锁库 ---------------------------------------------------
  steps.push({ op: "freeze", by: "u-dm", datasetId: "ds-2026-03-15" });

  // --- 冻结后新上传自动进入修订版 2 ----------------------------------------
  upload("u-sitea", "accepted", "锁库后抵达的随访包，进入修订版 2",
    {
      packageId: "pkg-b027-d3", siteId: "site-a", serialNumber: "watch-311",
      capturedFrom: "2026-03-12T12:00:00.000Z", capturedTo: "2026-03-13T12:00:00.000Z",
      firmwareVersion: "fw-3.1.0",
    },
    payload("subject=B-027|serial=watch-311|window=2026-03-12..03-13|seq=0002"));
  steps.push({ op: "freeze", by: "u-dm", datasetId: "ds-2026-03-20" });

  // 研究结束：回收补发设备（四类监管动作 issue/return/lost/replace 至此全部演练）。
  custody({
    by: "u-sitea", eventId: "evt-006", siteId: "site-a", subjectCode: "B-027",
    serialNumber: "watch-311", action: "return", occurredAt: "2026-03-21T10:00:00.000Z",
  });

  // --- 解盲：四种控制路径 --------------------------------------------------
  steps.push({
    op: "unblind", requester: "u-monitor", confirmer: "u-dm",
    subjectCode: "A-014", reason: "监查员试图查看分组",
    expect: "denied:REQUESTER_NOT_AUTHORIZED",
  });
  steps.push({
    op: "unblind", requester: "u-unblinder-a", confirmer: "u-unblinder-a",
    subjectCode: "A-014", reason: "同一人兼任请求与确认",
    expect: "denied:SAME_USER",
  });
  steps.push({
    op: "unblind", requester: "u-unblinder-a", confirmer: "u-sitea",
    subjectCode: "A-014", reason: "确认人不具备授权",
    expect: "denied:CONFIRMER_NOT_AUTHORIZED",
  });
  steps.push({
    op: "unblind", requester: "u-unblinder-a", confirmer: "u-unblinder-b",
    subjectCode: "A-014", reason: "SAE 急救需获知治疗分组（24h 内补交书面报告）",
    expect: "revealed",
  });

  return {
    schemaVersion: 2,
    study: { studyId: STUDY.studyId, allowedFirmware: STUDY.allowedFirmware },
    users: USERS,
    devices: deviceRecords(),
    steps,
  };
}
