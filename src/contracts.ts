/**
 * 腕戴数据监管链平台 —— 领域契约
 *
 * 这些类型同时约束平台实现、fixtures/site-uploads.json 与导出产物，
 * 使稽查员可以仅凭导出清单与审计记录独立还原每份数据的来路。
 */

// ---------------------------------------------------------------------------
// 设备监管链
// ---------------------------------------------------------------------------

export type CustodyAction = "issue" | "return" | "lost" | "replace";
export type PackageState = "accepted" | "quarantined" | "superseded";

/** 一次设备占有关系变更：发放、回收、遗失、换机。 */
export interface DeviceCustodyEvent {
  eventId: string;
  studyId: string;
  /** 登记该事件的站点；跨站换机时新设备由接收站点登记。 */
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  action: CustodyAction;
  /** 事件实际发生时间（设备物理流转时间，可能早于登记时间）。 */
  occurredAt: string;
  /** 仅 action=replace：被替换的旧设备序列号，即跨站交接记录。 */
  replacesSerialNumber?: string;
  /** 平台接收登记的时间，由平台时钟加盖。 */
  recordedAt?: string;
  recordedBy?: string;
}

// ---------------------------------------------------------------------------
// 人员、角色与授权
// ---------------------------------------------------------------------------

export type Role =
  | "site-user"
  | "medical-monitor"
  | "data-manager"
  | "auditor";

/** 细粒度权限；解盲不按角色隐式授予，必须显式具备 UNBLIND 授权。 */
export type Permission = "UNBLIND";

export interface User {
  userId: string;
  displayName: string;
  role: Role;
  /** 仅 site-user：绑定唯一站点，越站访问一律拒绝并记审计。 */
  siteId?: string;
  permissions?: Permission[];
}

// ---------------------------------------------------------------------------
// 研究与设备
// ---------------------------------------------------------------------------

export type TreatmentArm = "control" | "intervention";

export interface StudyConfig {
  studyId: string;
  /** 本研究许可的固件版本白名单（两站点可使用不同固件，但均须获许可）。 */
  allowedFirmware: string[];
  /**
   * 盲态随机分组表，与普通业务数据隔离存放。
   * 任何列表、导出、审计接口都不得读出该表，只有双人控制的解盲流程可以揭盲单个受试者。
   */
  randomization: Record<string, TreatmentArm>;
}

/** 设备出厂登记：序列号绑定公钥与密钥标识，私钥仅保存在设备端（fixture 生成器仅临时持有）。 */
export interface DeviceRecord {
  serialNumber: string;
  keyId: string;
  publicKeyPem: string;
  registeredAt: string;
}

// ---------------------------------------------------------------------------
// 上传包
// ---------------------------------------------------------------------------

export interface UploadManifest {
  packageId: string;
  siteId: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  /** 设备私钥对规范化报文（见 crypto.packageSigningPayload）的 Ed25519 签名，hex。 */
  signature: string;
  /** 若存在，表示本包是对该既有包的校正，而非覆盖。 */
  correctsPackageId?: string;
  /** 校正原因；correctsPackageId 存在时必填，构成“以原因关联的替代关系”。 */
  correctionReason?: string;
}

/** 业务层拒绝（请求本身合法，但包未通过监管链校验）。 */
export type PackageRejectionCode =
  | "UNKNOWN_DEVICE"
  | "DIGEST_MISMATCH"
  | "BAD_SIGNATURE"
  | "FIRMWARE_NOT_LICENSED"
  | "BAD_INTERVAL"
  | "OUTSIDE_CUSTODY"
  | "WRONG_SITE"
  | "UNKNOWN_CORRECTION_TARGET";

export interface UploadRejection {
  accepted: false;
  rejected: true;
  code: PackageRejectionCode;
  message: string;
  submittedPackageId: string;
  at: string;
}

/** 接收凭证；完全相同的重复提交返回同一张凭证（receiptId 不变）。 */
export interface UploadReceipt {
  accepted: true;
  receiptId: string;
  /** 平台保存的首个包号；重复提交时它可能与提交的 packageId 不同。 */
  canonicalPackageId: string;
  /** 本次提交使用的包号。 */
  submittedPackageId: string;
  state: PackageState;
  duplicate: boolean;
  subjectCode: string;
  contentSha256: string;
  revision: number;
  receivedAt: string;
  quarantinedReason?: string;
}

export type UploadResult = UploadReceipt | UploadRejection;

// ---------------------------------------------------------------------------
// 裁决与校正
// ---------------------------------------------------------------------------

/** 医学监查员对隔离包的裁决；不删除任何数据，只追加决定与原因。 */
export interface Adjudication {
  packageId: string;
  decision: "accepted" | "excluded";
  reason: string;
  decidedBy: string;
  decidedAt: string;
}

/** 校正替代关系：原包不被覆盖，永久保留并指向校正包。 */
export interface CorrectionLink {
  correctedPackageId: string;
  correctionPackageId: string;
  reason: string;
  linkedBy: string;
  linkedAt: string;
}

// ---------------------------------------------------------------------------
// 冻结批次与导出清单
// ---------------------------------------------------------------------------

export interface FrozenDataset {
  datasetId: string;
  studyId: string;
  /** 从 1 开始；冻结后新上传自动进入下一修订版。 */
  revision: number;
  frozenAt: string;
  frozenBy: string;
  predecessorDatasetId?: string;
  /** 快照：每个包在冻结时刻的状态。 */
  packageDecisions: Record<string, PackageState>;
  /** 排除/隔离依据（裁决原因或“冲突隔离待裁决”）。 */
  exclusionReasons: Record<string, string>;
  /** 快照时刻的校正替代关系。 */
  corrections: CorrectionLink[];
  /** 快照时刻的受试者设备交接链；冻结后即便发生新流转，本批次导出也不变。 */
  subjectChains: SubjectDeviceChain[];
  packageCount: number;
}

/** 导出清单中的单行：每个数据包及其纳入/排除/替代依据。 */
export interface ProvenanceEntry {
  packageId: string;
  subjectCode: string;
  siteId: string;
  serialNumber: string;
  deviceKeyId: string;
  firmwareVersion: string;
  capturedFrom: string;
  capturedTo: string;
  contentSha256: string;
  state: PackageState;
  included: boolean;
  /** 依据代码，见 EXPORT_BASIS。 */
  basis: string;
  /** 人类可读依据：裁决原因、校正关系、重复提交包号等。 */
  basisDetail: string;
  receiptId: string;
  revision: number;
}

export interface SubjectDeviceChain {
  subjectCode: string;
  links: Array<{
    eventId: string;
    action: CustodyAction;
    siteId: string;
    serialNumber: string;
    occurredAt: string;
    replacesSerialNumber?: string;
  }>;
}

export interface RejectedSubmission {
  packageId: string;
  siteId: string;
  serialNumber: string;
  submittedBy: string;
  code: PackageRejectionCode;
  at: string;
}

export interface DatasetExport {
  studyId: string;
  datasetId: string;
  /** 冻结修订版号；活动工作区导出为当前修订版号。 */
  revision: number;
  frozen: boolean;
  generatedAt: string;
  entries: ProvenanceEntry[];
  subjectChains: SubjectDeviceChain[];
  includedPackages: string[];
  excludedPackages: Array<{ packageId: string; basis: string; detail: string }>;
  corrections: CorrectionLink[];
  rejectedSubmissions: RejectedSubmission[];
  /** 对规范化导出内容计算的摘要，重新导出必须逐字节一致。 */
  exportSha256: string;
}

// ---------------------------------------------------------------------------
// 审计与解盲
// ---------------------------------------------------------------------------

export interface AuditEvent {
  eventId: string;
  at: string;
  actorId: string;
  actorRole: Role | "system";
  /** site-user 的站点范围，用于稽查越站尝试。 */
  siteScope?: string;
  action: string;
  target: string;
  allowed: boolean;
  detail?: string;
}

export interface UnblindResult {
  revealed: boolean;
  subjectCode: string;
  requesterId: string;
  confirmerId: string;
  reason: string;
  at: string;
  /** 仅成功时返回，绝不写入审计日志或导出清单。 */
  arm?: TreatmentArm;
  denialCode?: string;
}
