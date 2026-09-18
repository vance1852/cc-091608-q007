/**
 * 内存存储：所有记录只追加、不就地销毁。
 * 隔离、排除、替代都以状态与关联表达，原包永远保留。
 */
import type {
  Adjudication,
  AuditEvent,
  CorrectionLink,
  DeviceCustodyEvent,
  DeviceRecord,
  PackageRejectionCode,
  PackageState,
  StudyConfig,
  UploadManifest,
  User,
} from "./contracts.js";

export interface StoredPackage {
  packageId: string;
  studyId: string;
  siteId: string;
  subjectCode: string;
  manifest: UploadManifest;
  state: PackageState;
  /** 隔离时与之冲突的已存包号。 */
  conflictWith?: string;
  quarantineReason?(): string | undefined;
  receiptId: string;
  revision: number;
  receivedAt: string;
  receivedBy: string;
}

export interface PossessionWindow {
  subjectCode: string;
  from: string;
  to?: string;
  endedBy?: "return" | "lost" | "replace";
}

export interface GapRecord {
  gapId: string;
  studyId: string;
  subjectCode: string;
  serialNumber: string;
  from: string;
  to?: string;
  kind: "device-lost" | "content-conflict" | "manual";
  note: string;
  status: "open" | "resolved";
  reportedAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
  resolution?: string;
}

export interface RejectedRecord {
  packageId: string;
  studyId: string;
  siteId: string;
  serialNumber: string;
  submittedBy: string;
  code: PackageRejectionCode;
  at: string;
}

export interface DuplicateSubmission {
  receiptId: string;
  canonicalPackageId: string;
  submittedPackageId: string;
  submittedBy: string;
  at: string;
}

export class Store {
  readonly studies = new Map<string, StudyConfig>();
  readonly devices = new Map<string, DeviceRecord>();
  readonly users = new Map<string, User>();

  readonly custodyEvents: DeviceCustodyEvent[] = [];
  /** serial -> 占有历史（按时间排列）。 */
  readonly deviceWindows = new Map<string, PossessionWindow[]>();
  /** subjectCode -> 当前/最近一次持有设备序列号。 */
  readonly subjectCurrent = new Map<string, { serial: string; active: boolean }>();
  /** subjectCode -> 出现过该受试者的站点集合（跨站换机后为两个站）。 */
  readonly subjectSites = new Map<string, Set<string>>();

  readonly packages = new Map<string, StoredPackage>();
  /** 完全相同内容键 -> 首个接收凭证。 */
  readonly contentIndex = new Map<string, StoredPackage>();
  /** 同设备同采集区间键 -> 占用该区间的已存包。 */
  readonly intervalIndex = new Map<string, StoredPackage>();

  readonly adjudications: Adjudication[] = [];
  readonly corrections: CorrectionLink[] = [];
  readonly gaps: GapRecord[] = [];
  readonly rejected: RejectedRecord[] = [];
  readonly duplicates: DuplicateSubmission[] = [];
  readonly audit: AuditEvent[] = [];

  /** 已冻结批次快照（追加）。 */
  datasets: import("./contracts.js").FrozenDataset[] = [];
  /** 当前开放修订版号（首个为 1，每次冻结后 +1）。 */
  currentRevision = 1;

  deviceWindowsFor(serial: string): PossessionWindow[] {
    let w = this.deviceWindows.get(serial);
    if (!w) {
      w = [];
      this.deviceWindows.set(serial, w);
    }
    return w;
  }

  subjectSiteSet(subjectCode: string): Set<string> {
    let s = this.subjectSites.get(subjectCode);
    if (!s) {
      s = new Set();
      this.subjectSites.set(subjectCode, s);
    }
    return s;
  }
}
