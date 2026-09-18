/**
 * 腕戴数据监管链平台契约
 *
 * 本文件只定义跨模块共享的数据结构与枚举，不包含业务逻辑。
 * 受试者全程以研究代号表示；随机分组（盲态）信息不进入任何常规视图，
 * 只能通过经授权的双人解盲流程读取。
 */

// ---------------------------------------------------------------------------
// 监管链与数据包（基线契约，保持原有字段，仅追加可选字段）
// ---------------------------------------------------------------------------

export type CustodyAction = "issue" | "return" | "lost" | "replace";
export type PackageState = "accepted" | "quarantined" | "superseded";

/** 设备发放/回收/遗失/换机事件，构成每台设备与每位受试者的监管链 */
export interface DeviceCustodyEvent {
  eventId: string;
  studyId: string;
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  action: CustodyAction;
  occurredAt: string;
  /** 被替换的旧设备序列号（仅 action=replace） */
  replacesSerialNumber?: string;
  /** 事件发生时的访视编号 */
  visitId?: string;
}

/**
 * 站点上传的数据包清单（manifest）。
 * 设备对“除 signature 外的全部字段”做 Ed25519 签名。
 */
export interface UploadManifest {
  packageId: string;
  siteId: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  /** 设备对规范化报文的 Ed25519 签名（base64） */
  signature: string;
  /** 若本包是校正包，指向被校正的原始提交编号 */
  correctsPackageId?: string;
  /** 校正原因（校正包必填，随替代关系永久保留） */
  correctionReason?: string;
  /** 采集所属访视 */
  visitId?: string;
}

/** 冻结批次：某一修订版下各接收凭证的裁决快照 */
export interface FrozenDataset {
  datasetId: string;
  revision: number;
  frozenAt: string;
  /** receiptId -> 冻结时刻状态 */
  packageDecisions: Record<string, PackageState>;
  /** 冻结时刻完整清单快照（冻结后不可变） */
  entries: ListingEntry[];
  /** 被拒收提交 -> 拒收代码（固件未许可等） */
  rejectedPackages: Record<string, RejectCode>;
  /** 冻结时刻的缺口及医学监查员的处理记录 */
  gaps: GapRecord[];
}

// ---------------------------------------------------------------------------
// 研究、受试者、设备、访视、用户与角色
// ---------------------------------------------------------------------------

export type Role =
  | "site-user" // 普通站点：仅本站代号与本站数据
  | "medical-monitor" // 医学监查员：可处理缺口/裁决，看不到随机分组
  | "data-manager" // 数据经理：登记、冻结批次、导出
  | "unblinded-user"; // 授权解盲人员（仅可参与解盲）

export interface Actor {
  userId: string;
  role: Role;
  /** site-user 所属站点 */
  siteId?: string;
}

export interface StudyConfig {
  studyId: string;
  title: string;
  /** 本研究许可的固件版本白名单 */
  firmwareAllowlist: string[];
  siteIds: string[];
}

export interface SubjectRecord {
  subjectCode: string;
  /** 受试者归属站点（跨站随访时数据仍可由其他站点产生） */
  homeSiteId: string;
}

/** Ed25519 公钥（JWK）。私钥只出现在测试夹具中，生产环境应驻留于设备。 */
export interface DeviceKeyJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
  d?: string;
}

export interface DeviceRecord {
  serialNumber: string;
  label: string;
  publicKey: DeviceKeyJwk;
}

export interface Visit {
  visitId: string;
  subjectCode: string;
  siteId: string;
  /** 计划访视窗口 */
  plannedFrom: string;
  plannedTo: string;
  /** 实际访视时间 */
  occurredAt: string;
}

// ---------------------------------------------------------------------------
// 接收凭证、拒收、隔离裁决与替代关系
// ----------------------------------------------------------------===========

export interface Receipt {
  /** 同一内容（序列号+摘要+区间+固件）的提交永远映射到同一凭证 */
  receiptId: string;
  /** 首次被接收的提交编号 */
  packageId: string;
  studyId: string;
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  receivedAt: string;
  /** 进入的开放修订版 */
  revision: number;
}

/** 拒收代码：硬性校验失败，与“内容冲突隔离”相区分 */
export type RejectCode =
  | "unknown-device"
  | "device-not-in-custody"
  | "site-mismatch"
  | "signature-invalid"
  | "content-digest-mismatch"
  | "firmware-not-licensed"
  | "bad-interval"
  | "unknown-visit"
  | "unknown-correction-target"
  | "correction-target-not-accepted"
  | "correction-content-identical"
  | "forbidden";

export interface RejectedSubmission {
  manifest: UploadManifest;
  reasons: RejectCode[];
  rejectedAt: string;
}

/** 隔离包裁决结果 */
export type AdjudicationDecision =
  | "retain-quarantine" // 维持排除
  | "accept-as-replacement"; // 采纳冲突包，原接收包转为被替代

export interface Adjudication {
  submissionPackageId: string;
  decision: AdjudicationDecision;
  reason: string;
  adjudicatedBy: string;
  adjudicatedAt: string;
  /** 裁决发生时所在的开放修订版 */
  revision: number;
}

/** 替代关系（校正或裁决产生）。原包永不被覆盖，只追加关系。 */
export interface Supersession {
  replacedBySubmissionId: string;
  reason: string;
  at: string;
  /** 关系生效所在修订版 */
  revision: number;
  kind: "correction" | "adjudication";
}

// ---------------------------------------------------------------------------
// 采集缺口
// ---------------------------------------------------------------------------

export type GapResolution = "documented-gap" | "device-recovered";

export interface GapRecord {
  gapId: string;
  subjectCode: string;
  /** 缺口登记/处理站点 */
  siteId: string;
  /** 旧设备持有窗口结束 ~ 新设备持有窗口开始 */
  from: string;
  to: string;
  status: "open" | "documented";
  resolution?: GapResolution;
  note?: string;
  documentedBy?: string;
  documentedAt?: string;
}

// ---------------------------------------------------------------------------
// 导出清单（稳定、可逐条还原来路）
// ---------------------------------------------------------------------------

export type Disposition = "included" | "excluded" | "superseded" | "duplicate";

export interface ListingEntry {
  receiptId: string;
  submissionPackageId: string;
  /** 同一接收凭证下的其他提交编号（重复提交） */
  aliases: string[];
  /** 首次进入的修订版 */
  introducedRevision: number;
  /** 被排除/替代等状态变化最近一次生效的修订版（如有） */
  changedAtRevision?: number;
  disposition: Disposition;
  /** 冻结快照时刻状态；开放修订版导出现算 */
  state: PackageState | "rejected" | "duplicate";
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  visitId?: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  receivedAt: string;
  /** 纳入/排除/替代依据（人类可读，按追加顺序排列） */
  basis: string[];
  /** 拒收代码（机器可读） */
  rejectCodes?: RejectCode[];
  conflictWithSubmissionId?: string;
  correctsSubmissionId?: string;
  correctedBySubmissionId?: string;
  correctionReason?: string;
  adjudication?: AdjudicationDecision;
}

export interface VisitVerification {
  visitId: string;
  subjectCode: string;
  siteId: string;
  plannedFrom: string;
  plannedTo: string;
  occurredAt: string;
  /** 该访视关联的每个提交编号及其凭证与处置（含重复/拒收/隔离） */
  submissions: Array<{
    submissionPackageId: string;
    receiptId: string;
    disposition: Disposition;
  }>;
}

export interface DatasetExport {
  studyId: string;
  revision: number;
  datasetId?: string;
  frozenAt?: string;
  generatedAt: string;
  /** 稳定排序：introducedRevision、采集起点、序列号、提交编号 */
  entries: ListingEntry[];
  /** 每次访视的来实验证：访视 → 关联提交/凭证/处置 */
  visits: VisitVerification[];
  gaps: GapRecord[];
  /** 导出时刻的完整设备监管链（按受试者、时间排序） */
  custody: DeviceCustodyEvent[];
}

// ---------------------------------------------------------------------------
// 审计轨迹与解盲
// ---------------------------------------------------------------------------

export type AuditAction =
  | "custody.register"
  | "package.submit"
  | "package.duplicate"
  | "package.quarantine"
  | "package.reject"
  | "package.adjudicate"
  | "gap.document"
  | "dataset.freeze"
  | "export.read"
  | "chain.read"
  | "site.data.read"
  | "unblind.attempt";

export interface AuditEntry {
  auditId: string;
  at: string;
  actorId: string;
  actorRole: Role;
  action: AuditAction;
  target: string;
  granted: boolean;
  detail?: string;
}

/** 随机分组密封信息：构造账本时注入，除成功解盲外不可读取 */
export type RandomizationEnvelope = Record<string, string>;

export interface UnblindRecord {
  subjectCode: string;
  arm: string;
  reason: string;
  actorId: string;
  confirmerId: string;
  at: string;
}
