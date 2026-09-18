/**
 * 监管链状态机：设备发放/回收/遗失/换机、上传校验与接收凭证、
 * 冲突隔离与裁决、校正替代、采集缺口、冻结修订版、基于角色的视图、
 * 双人解盲以及只增的审计轨迹。
 */
import {
  contentIdentityHash,
  deterministicId,
  newId,
  sha256,
  verifyManifestSignature,
} from "./crypto.js";
import type {
  Actor,
  Adjudication,
  AdjudicationDecision,
  AuditAction,
  AuditEntry,
  CustodyAction,
  DatasetExport,
  DeviceCustodyEvent,
  DeviceRecord,
  Disposition,
  FrozenDataset,
  GapRecord,
  GapResolution,
  ListingEntry,
  PackageState,
  RandomizationEnvelope,
  Receipt,
  RejectCode,
  RejectedSubmission,
  Role,
  StudyConfig,
  SubjectRecord,
  Supersession,
  UnblindRecord,
  UploadManifest,
  Visit,
  VisitVerification,
} from "./contracts.js";

export class PermissionError extends Error {
  readonly code = "forbidden";
  constructor(message: string) {
    super(message);
    this.name = "PermissionError";
  }
}

export class ValidationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ValidationError";
  }
}

const REJECT_TEXT: Record<RejectCode, string> = {
  "unknown-device": "设备序列号未登记",
  "device-not-in-custody": "采集区间内设备不在受试者持有链中",
  "site-mismatch": "提交站点与设备当前持有站点不一致",
  "signature-invalid": "设备 Ed25519 签名验证失败",
  "content-digest-mismatch": "实际载荷 SHA-256 与清单摘要不一致",
  "firmware-not-licensed": "固件版本不在研究许可清单内",
  "bad-interval": "采集区间非法（起止时间无法解析或起点不早于终点）",
  "unknown-visit": "访视不存在，或访视受试者/站点与提交不符",
  "unknown-correction-target": "校正目标提交不存在或不属于同一设备",
  "correction-target-not-accepted": "校正目标当前不处于接收状态（不得校正隔离/拒收/已替代包）",
  "correction-content-identical": "校正包与原包内容摘要完全相同，不构成校正",
  forbidden: "无执行权限",
};

interface ReceiptRecord {
  receipt: Receipt;
  visitId?: string;
  aliases: Set<string>;
  state: PackageState;
  introducedRevision: number;
  changedAtRevision?: number;
  basis: string[];
  conflictWithSubmissionId?: string;
  correctsSubmissionId?: string;
  correctedBySubmissionId?: string;
  correctionReason?: string;
  adjudication?: AdjudicationDecision;
  supersession?: Supersession;
}

interface SubmissionRecord {
  packageId: string;
  manifest: UploadManifest;
  /** 空串表示拒收（无凭证） */
  receiptId: string;
  kind: "canonical" | "alias" | "quarantined" | "rejected";
  at: string;
  revision: number;
  reasons?: RejectCode[];
  adjudication?: Adjudication;
}

interface InternalGap extends GapRecord {
  serialNumber: string;
  /** 换机发生后、新设备首包到达前，区间终点待定 */
  finalized: boolean;
}

interface Holding {
  subject: string | null;
  site: string | null;
  lost: boolean;
}

export type SubmitOutcome =
  | {
      outcome: "accepted" | "duplicate" | "quarantined";
      receiptId: string;
      state: PackageState;
      receipt: Receipt;
    }
  | { outcome: "rejected"; packageId: string; reasons: RejectCode[] };

export interface CustodyInput {
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  action: CustodyAction;
  occurredAt: string;
  replacesSerialNumber?: string;
  visitId?: string;
  eventId?: string;
}

export interface LedgerConfig {
  study: StudyConfig;
  subjects: SubjectRecord[];
  devices: DeviceRecord[];
  visits: Visit[];
  /** 用户注册表（解盲确认人必须在册） */
  users: Actor[];
  /** 随机分组密封信息，除成功解盲外任何接口都不会读出 */
  randomization: RandomizationEnvelope;
}

const EMPTY_HOLDING: Holding = { subject: null, site: null, lost: false };

export class CustodyLedger {
  private readonly study: StudyConfig;
  private readonly subjects = new Map<string, SubjectRecord>();
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly visits = new Map<string, Visit>();
  private readonly users = new Map<string, Actor>();
  private readonly randomization: RandomizationEnvelope;

  private events: DeviceCustodyEvent[] = [];
  private receipts = new Map<string, ReceiptRecord>();
  private submissions = new Map<string, SubmissionRecord>();
  private identityIndex = new Map<string, string>(); // content identity -> receiptId
  private rejected: SubmissionRecord[] = [];
  private gaps: InternalGap[] = [];
  private datasets: FrozenDataset[] = [];
  private auditLog: AuditEntry[] = [];
  private unblindLog: UnblindRecord[] = [];
  private auditSeq = 0;
  private openRevision = 1;

  constructor(cfg: LedgerConfig) {
    this.study = cfg.study;
    for (const s of cfg.subjects) this.subjects.set(s.subjectCode, s);
    for (const d of cfg.devices) this.devices.set(d.serialNumber, d);
    for (const v of cfg.visits) this.visits.set(v.visitId, v);
    for (const u of cfg.users) {
      if (this.users.has(u.userId)) {
        throw new ValidationError(`重复用户编号 ${u.userId}`);
      }
      this.users.set(u.userId, u);
    }
    this.randomization = { ...cfg.randomization };
  }

  // -- 公开只读视图 --------------------------------------------------------

  get currentRevision(): number {
    return this.openRevision;
  }

  get frozenDatasets(): FrozenDataset[] {
    return this.datasets.map((d) => structuredClone(d));
  }

  get unblindRecords(): UnblindRecord[] {
    return this.unblindLog.map((r) => ({ ...r }));
  }

  // -- 审计与权限 ----------------------------------------------------------

  private resolveActor(actor: Actor): Actor {
    const known = this.users.get(actor.userId);
    if (!known || known.role !== actor.role) {
      throw new PermissionError(`用户 ${actor.userId} 未注册或角色不符`);
    }
    return known;
  }

  private audit(
    actor: Actor,
    action: AuditAction,
    target: string,
    granted: boolean,
    detail?: string,
  ): void {
    this.auditLog.push({
      auditId: `aud-${String(++this.auditSeq).padStart(5, "0")}`,
      at: new Date().toISOString(),
      actorId: actor.userId,
      actorRole: actor.role,
      action,
      target,
      granted,
      ...(detail !== undefined ? { detail } : {}),
    });
  }

  private deny(actor: Actor, action: AuditAction, target: string, detail: string): never {
    this.audit(actor, action, target, false, detail);
    throw new PermissionError(detail);
  }

  // -- 设备监管链 ----------------------------------------------------------

  /**
   * 登记发放/回收/遗失/换机。站点用户只能登记本站事件；数据经理可代任一站登记。
   * 换机事件由接收站点登记（跨站交接），旧设备持有随即终止。
   */
  registerCustody(actor: Actor, input: CustodyInput): DeviceCustodyEvent {
    const me = this.resolveActor(actor);
    const allowed: Role[] = ["site-user", "data-manager"];
    if (!allowed.includes(me.role)) {
      this.deny(me, "custody.register", input.serialNumber, "只有站点用户或数据经理可登记监管链事件");
    }
    if (me.role === "site-user" && me.siteId !== input.siteId) {
      this.deny(me, "custody.register", input.serialNumber, "站点用户只能登记本站事件");
    }
    if (!this.study.siteIds.includes(input.siteId)) {
      throw new ValidationError(`站点 ${input.siteId} 不在研究 ${this.study.studyId} 中`);
    }
    if (!this.subjects.has(input.subjectCode)) {
      throw new ValidationError(`受试者代号 ${input.subjectCode} 未登记`);
    }
    if (!this.devices.has(input.serialNumber)) {
      throw new ValidationError(`设备 ${input.serialNumber} 未登记`);
    }
    if (Number.isNaN(Date.parse(input.occurredAt))) {
      throw new ValidationError("事件时间无法解析");
    }
    const eventId =
      input.eventId ??
      deterministicId("cev", [
        this.study.studyId,
        input.subjectCode,
        input.serialNumber,
        input.action,
        input.occurredAt,
        input.replacesSerialNumber ?? "",
      ]);
    if (this.events.some((e) => e.eventId === eventId)) {
      throw new ValidationError(`事件编号 ${eventId} 已存在`);
    }

    const holding = this.holdingAt(input.serialNumber, input.occurredAt);
    switch (input.action) {
      case "issue": {
        if (holding.subject !== null) {
          throw new ValidationError(`设备 ${input.serialNumber} 在该时间已发放给 ${holding.subject}`);
        }
        break;
      }
      case "return": {
        if (holding.subject !== input.subjectCode) {
          throw new ValidationError(
            `设备 ${input.serialNumber} 在该时间并非由 ${input.subjectCode} 持有`,
          );
        }
        break;
      }
      case "lost": {
        if (holding.subject !== input.subjectCode) {
          throw new ValidationError(
            `设备 ${input.serialNumber} 在该时间并非由 ${input.subjectCode} 持有`,
          );
        }
        if (holding.lost) {
          throw new ValidationError(`设备 ${input.serialNumber} 已登记遗失，不得重复登记`);
        }
        break;
      }
      case "replace": {
        if (!input.replacesSerialNumber) {
          throw new ValidationError("换机事件必须给出 replacesSerialNumber");
        }
        if (!this.devices.has(input.replacesSerialNumber)) {
          throw new ValidationError(`被替换设备 ${input.replacesSerialNumber} 未登记`);
        }
        const oldHolding = this.holdingAt(input.replacesSerialNumber, input.occurredAt);
        // 旧设备当前由该受试者持有，或遗失前最后由其持有（遗失补发），链才连续
        if (oldHolding.subject !== input.subjectCode) {
          throw new ValidationError(
            `被替换设备 ${input.replacesSerialNumber} 在该时间并非由 ${input.subjectCode} 持有，换机链断裂`,
          );
        }
        if (holding.subject !== null) {
          throw new ValidationError(`新设备 ${input.serialNumber} 在该时间已在他人手中`);
        }
        break;
      }
    }

    const event: DeviceCustodyEvent = {
      eventId,
      studyId: this.study.studyId,
      siteId: input.siteId,
      subjectCode: input.subjectCode,
      serialNumber: input.serialNumber,
      action: input.action,
      occurredAt: input.occurredAt,
      ...(input.replacesSerialNumber !== undefined
        ? { replacesSerialNumber: input.replacesSerialNumber }
        : {}),
      ...(input.visitId !== undefined ? { visitId: input.visitId } : {}),
    };
    this.events.push(event);

    if (input.action === "replace" && input.replacesSerialNumber) {
      // 跨站/站内换机都会产生一段采集缺口，等待新设备首包来确定区间终点，
      // 随后由医学监查员书面处理。
      this.gaps.push({
        gapId: deterministicId("gap", [
          this.study.studyId,
          input.subjectCode,
          input.replacesSerialNumber,
          input.serialNumber,
          input.occurredAt,
        ]),
        subjectCode: input.subjectCode,
        siteId: input.siteId,
        from: input.occurredAt,
        to: input.occurredAt,
        status: "open",
        serialNumber: input.serialNumber,
        finalized: false,
      });
    }

    this.audit(
      me,
      "custody.register",
      input.serialNumber,
      true,
      `${input.action} @ ${input.siteId} / ${input.subjectCode}${
        input.replacesSerialNumber ? ` replaces ${input.replacesSerialNumber}` : ""
      }`,
    );
    return { ...event };
  }

  /** 截至某时刻，按时间重放该设备相关的全部监管链事件得到持有状态。 */
  private holdingAt(serial: string, at: string): Holding {
    const relevant = this.events
      .filter(
        (e) =>
          (e.serialNumber === serial || e.replacesSerialNumber === serial) &&
          e.occurredAt <= at,
      )
      .sort((a, b) => a.occurredAt.localeCompare(b.occurredAt));
    let state: Holding = { ...EMPTY_HOLDING };
    for (const e of relevant) {
      if (e.action === "issue" && e.serialNumber === serial) {
        state = { subject: e.subjectCode, site: e.siteId, lost: false };
      } else if (e.action === "replace" && e.serialNumber === serial) {
        state = { subject: e.subjectCode, site: e.siteId, lost: false };
      } else if (e.action === "replace" && e.replacesSerialNumber === serial) {
        state = { ...EMPTY_HOLDING };
      } else if (e.action === "return" && e.serialNumber === serial) {
        state = { ...EMPTY_HOLDING };
      } else if (e.action === "lost" && e.serialNumber === serial) {
        // 遗失不改变“最后持有人”的归属，只置遗失标记：
        // 持有链据此允许遗失后的换机补发，同时拒绝遗失期间的数据上传。
        state = { subject: state.subject, site: state.site, lost: true };
      }
    }
    return state;
  }

  // -- 上传与四类命运 ------------------------------------------------------

  /**
   * 上传数据包。硬校验失败 -> 拒收；内容完全相同 -> 原凭证；
   * 同区间不同内容 -> 隔离；否则 -> 接收（校正包以替代关系关联原包）。
   */
  submitPackage(actor: Actor, manifest: UploadManifest, content?: Buffer): SubmitOutcome {
    const me = this.resolveActor(actor);
    if (me.role !== "site-user") {
      this.deny(me, "package.submit", manifest.packageId, "只有站点用户可上传数据包");
    }
    if (me.siteId !== manifest.siteId) {
      this.deny(me, "package.submit", manifest.packageId, "站点用户只能上传本站数据包");
    }

    const at = new Date().toISOString();
    const reasons: RejectCode[] = [];

    const device = this.devices.get(manifest.serialNumber);
    if (!device) reasons.push("unknown-device");

    if (!this.study.siteIds.includes(manifest.siteId)) reasons.push("site-mismatch");

    const fromOk = !Number.isNaN(Date.parse(manifest.capturedFrom));
    const toOk = !Number.isNaN(Date.parse(manifest.capturedTo));
    const orderOk =
      fromOk && toOk && Date.parse(manifest.capturedFrom) < Date.parse(manifest.capturedTo);
    if (!orderOk) reasons.push("bad-interval");

    const holdFrom = device ? this.holdingAt(manifest.serialNumber, manifest.capturedFrom) : undefined;
    const holdTo = device ? this.holdingAt(manifest.serialNumber, manifest.capturedTo) : undefined;
    const held =
      holdFrom !== undefined &&
      holdTo !== undefined &&
      holdFrom.subject !== null &&
      holdTo.subject !== null &&
      !holdFrom.lost &&
      !holdTo.lost &&
      holdFrom.subject === holdTo.subject;
    if (device && !held) reasons.push("device-not-in-custody");

    if (device && held && holdTo && holdTo.site !== manifest.siteId) {
      reasons.push("site-mismatch");
    }

    if (device && !verifyManifestSignature(manifest, device.publicKey)) {
      reasons.push("signature-invalid");
    }

    if (content !== undefined && sha256(content) !== manifest.contentSha256) {
      reasons.push("content-digest-mismatch");
    }

    if (!this.study.firmwareAllowlist.includes(manifest.firmwareVersion)) {
      reasons.push("firmware-not-licensed");
    }

    let subjectCode: string | null = holdTo?.subject ?? null;

    if (manifest.visitId !== undefined) {
      const visit = this.visits.get(manifest.visitId);
      const visitOk =
        visit !== undefined &&
        visit.subjectCode === subjectCode &&
        visit.siteId === manifest.siteId &&
        orderOk &&
        Date.parse(manifest.capturedFrom) <= Date.parse(visit.plannedTo) &&
        Date.parse(manifest.capturedTo) >= Date.parse(visit.plannedFrom);
      if (!visitOk) reasons.push("unknown-visit");
    }

    // 校正语义校验（目标必须是同设备、当前接收状态、且内容确实不同）
    let correctionTarget: ReceiptRecord | undefined;
    if (manifest.correctsPackageId !== undefined) {
      if (!manifest.correctionReason?.trim()) {
        throw new ValidationError("校正包必须给出 correctionReason");
      }
      const targetSubmission = this.submissions.get(manifest.correctsPackageId);
      correctionTarget = targetSubmission?.receiptId
        ? this.receipts.get(targetSubmission.receiptId)
        : undefined;
      if (
        !correctionTarget ||
        correctionTarget.receipt.serialNumber !== manifest.serialNumber
      ) {
        reasons.push("unknown-correction-target");
      } else if (correctionTarget.state !== "accepted") {
        reasons.push("correction-target-not-accepted");
      } else if (correctionTarget.receipt.contentSha256 === manifest.contentSha256) {
        reasons.push("correction-content-identical");
      }
    }

    // 同提交编号重放：内容身份必须一致；一致时落入下方幂等分支，
    // 不一致（同编号被用于不同内容）直接拒绝，防止覆盖既有凭证。
    const identity = contentIdentityHash(manifest);
    const priorSubmission = this.submissions.get(manifest.packageId);
    if (
      priorSubmission &&
      priorSubmission.kind !== "rejected" &&
      contentIdentityHash(priorSubmission.manifest) !== identity
    ) {
      throw new ValidationError(`提交编号 ${manifest.packageId} 已用于不同内容的包`);
    }

    if (reasons.length > 0) {
      const record: SubmissionRecord = {
        packageId: manifest.packageId,
        manifest,
        receiptId: "",
        kind: "rejected",
        at,
        revision: this.openRevision,
        reasons: [...reasons],
      };
      if (!priorSubmission) this.submissions.set(manifest.packageId, record);
      this.rejected.push(record);
      this.audit(
        me,
        "package.reject",
        manifest.packageId,
        true,
        reasons.map((r) => REJECT_TEXT[r]).join("；"),
      );
      return { outcome: "rejected", packageId: manifest.packageId, reasons };
    }

    const existingId = this.identityIndex.get(identity);

    // 1) 完全相同的包：返回原接收凭证（仅登记新别名）
    if (existingId) {
      const existing = this.receipts.get(existingId);
      if (!existing) throw new Error("凭证索引不一致");
      if (!existing.aliases.has(manifest.packageId) && manifest.packageId !== existing.receipt.packageId) {
        existing.aliases.add(manifest.packageId);
        this.submissions.set(manifest.packageId, {
          packageId: manifest.packageId,
          manifest,
          receiptId: existingId,
          kind: "alias",
          at,
          revision: this.openRevision,
        });
        this.audit(
          me,
          "package.duplicate",
          manifest.packageId,
          true,
          `内容与 ${existing.receipt.packageId} 完全一致，沿用凭证 ${existingId}`,
        );
      }
      return {
        outcome: "duplicate",
        receiptId: existingId,
        state: existing.state,
        receipt: { ...existing.receipt },
      };
    }

    const basis: string[] = [];
    basis.push(
      `修订版 ${this.openRevision} 首次接收，接收凭证 ${identity}`,
      `设备 ${manifest.serialNumber} 的 Ed25519 签名验证通过`,
      `采集区间 ${manifest.capturedFrom} 至 ${manifest.capturedTo} 内设备由受试者 ${subjectCode} 持有`,
      `固件 ${manifest.firmwareVersion} 在研究许可清单内`,
      `内容摘要 SHA-256=${manifest.contentSha256}`,
    );
    if (manifest.visitId) basis.push(`关联访视 ${manifest.visitId}`);

    const receipt: Receipt = {
      receiptId: identity,
      packageId: manifest.packageId,
      studyId: this.study.studyId,
      siteId: manifest.siteId,
      subjectCode: subjectCode as string,
      serialNumber: manifest.serialNumber,
      capturedFrom: manifest.capturedFrom,
      capturedTo: manifest.capturedTo,
      firmwareVersion: manifest.firmwareVersion,
      contentSha256: manifest.contentSha256,
      receivedAt: at,
      revision: this.openRevision,
    };

    // 2) 同区间不同内容（或同区间不同固件）：隔离待裁决
    const conflict = this.findConflict(manifest);
    const initialState: PackageState = conflict ? "quarantined" : "accepted";
    if (conflict) {
      basis.push(
        `与已登记提交 ${conflict.receipt.packageId} 声明同一采集区间但内容摘要不同` +
          `（${manifest.contentSha256} ≠ ${conflict.receipt.contentSha256}），隔离等待裁决`,
      );
    }

    const record: ReceiptRecord = {
      receipt,
      ...(manifest.visitId !== undefined ? { visitId: manifest.visitId } : {}),
      aliases: new Set<string>(),
      state: initialState,
      introducedRevision: this.openRevision,
      basis,
      ...(conflict ? { conflictWithSubmissionId: conflict.receipt.packageId } : {}),
    };
    this.receipts.set(identity, record);
    this.identityIndex.set(identity, identity);
    this.submissions.set(manifest.packageId, {
      packageId: manifest.packageId,
      manifest,
      receiptId: identity,
      kind: conflict ? "quarantined" : "canonical",
      at,
      revision: this.openRevision,
    });

    if (!conflict) {
      // 3) 接收。校正包不覆盖原包，只追加替代关系。
      if (correctionTarget) {
        correctionTarget.state = "superseded";
        correctionTarget.changedAtRevision = this.openRevision;
        correctionTarget.correctedBySubmissionId = manifest.packageId;
        correctionTarget.supersession = {
          replacedBySubmissionId: manifest.packageId,
          reason: manifest.correctionReason as string,
          at,
          revision: this.openRevision,
          kind: "correction",
        };
        correctionTarget.basis.push(
          `修订版 ${this.openRevision} 被校正包 ${manifest.packageId} 替代（原包保留不覆盖）：${manifest.correctionReason}`,
        );
        record.correctsSubmissionId = correctionTarget.receipt.packageId;
        record.correctionReason = manifest.correctionReason as string;
        record.basis.push(
          `校正包：以原因“${manifest.correctionReason}”关联替代 ${correctionTarget.receipt.packageId}，原包保留`,
        );
      }
      this.linkGap(manifest);
      this.audit(me, "package.submit", manifest.packageId, true, `接收凭证 ${identity}`);
    } else {
      this.audit(
        me,
        "package.quarantine",
        manifest.packageId,
        true,
        `同区间内容冲突，隔离；冲突对象 ${conflict.receipt.packageId}`,
      );
    }

    return {
      outcome: conflict ? "quarantined" : "accepted",
      receiptId: identity,
      state: initialState,
      receipt: { ...receipt },
    };
  }

  /**
   * 同设备、完全相同采集区间、但内容身份不同（摘要或固件不同）的已登记凭证。
   * 显式声明 correctsPackageId 的包走校正（替代）路径，不得再被当作冲突隔离。
   */
  private findConflict(manifest: UploadManifest): ReceiptRecord | undefined {
    for (const rec of this.receipts.values()) {
      const r = rec.receipt;
      if (
        r.serialNumber === manifest.serialNumber &&
        r.capturedFrom === manifest.capturedFrom &&
        r.capturedTo === manifest.capturedTo &&
        r.contentSha256 !== manifest.contentSha256 &&
        r.packageId !== manifest.correctsPackageId
      ) {
        return rec;
      }
    }
    return undefined;
  }

  /** 新设备首包到达时，将换机缺口区间终点固定为首包起点（仍保持 open 待监查员处理）。 */
  private linkGap(manifest: UploadManifest): void {
    const gap = this.gaps.find(
      (g) =>
        g.serialNumber === manifest.serialNumber &&
        g.status === "open" &&
        !g.finalized,
    );
    if (!gap) return;
    if (Date.parse(manifest.capturedFrom) > Date.parse(gap.from)) {
      gap.to = manifest.capturedFrom;
    }
    gap.finalized = true;
  }

  // -- 裁决与缺口 ----------------------------------------------------------

  /** 医学监查员对隔离包裁决；冻结后裁决落在新修订版，历史快照不变。 */
  adjudicate(
    actor: Actor,
    submissionPackageId: string,
    decision: AdjudicationDecision,
    reason: string,
    at: string,
  ): Adjudication {
    const me = this.resolveActor(actor);
    if (me.role !== "medical-monitor") {
      this.deny(me, "package.adjudicate", submissionPackageId, "只有医学监查员可裁决冲突包");
    }
    if (!reason.trim()) throw new ValidationError("裁决必须给出理由");
    const sub = this.submissions.get(submissionPackageId);
    if (!sub || sub.kind !== "quarantined") {
      throw new ValidationError(`提交 ${submissionPackageId} 不是隔离待裁决包`);
    }
    const quarantined = this.receipts.get(sub.receiptId);
    if (!quarantined) throw new Error("隔离凭证缺失");
    if (quarantined.state !== "quarantined") {
      throw new ValidationError("该隔离包已有生效裁决");
    }

    const adjudication: Adjudication = {
      submissionPackageId,
      decision,
      reason,
      adjudicatedBy: me.userId,
      adjudicatedAt: at,
      revision: this.openRevision,
    };
    sub.adjudication = adjudication;
    quarantined.adjudication = decision;
    quarantined.changedAtRevision = this.openRevision;

    if (decision === "accept-as-replacement") {
      const conflictId = quarantined.conflictWithSubmissionId;
      const priorSub = conflictId ? this.submissions.get(conflictId) : undefined;
      const prior = priorSub?.receiptId ? this.receipts.get(priorSub.receiptId) : undefined;
      quarantined.state = "accepted";
      quarantined.basis.push(
        `修订版 ${this.openRevision} 冲突裁决采纳（${me.userId}）：${reason}`,
      );
      if (prior) {
        prior.state = "superseded";
        prior.changedAtRevision = this.openRevision;
        prior.supersession = {
          replacedBySubmissionId: submissionPackageId,
          reason,
          at,
          revision: this.openRevision,
          kind: "adjudication",
        };
        prior.basis.push(
          `修订版 ${this.openRevision} 冲突裁决：原接收包被 ${submissionPackageId} 替代（${me.userId}）：${reason}`,
        );
      }
    } else {
      quarantined.basis.push(
        `修订版 ${this.openRevision} 裁决维持隔离排除（${me.userId}）：${reason}`,
      );
    }

    this.audit(me, "package.adjudicate", submissionPackageId, true, `${decision}: ${reason}`);
    return { ...adjudication };
  }

  /** 医学监查员书面处理采集缺口。 */
  documentGap(
    actor: Actor,
    gapId: string,
    resolution: GapResolution,
    note: string,
    at: string,
  ): GapRecord {
    const me = this.resolveActor(actor);
    if (me.role !== "medical-monitor") {
      this.deny(me, "gap.document", gapId, "只有医学监查员可处理采集缺口");
    }
    const gap = this.gaps.find((g) => g.gapId === gapId);
    if (!gap) throw new ValidationError(`缺口 ${gapId} 不存在`);
    if (gap.status === "documented") {
      throw new ValidationError(`缺口 ${gapId} 已处理，记录不可修改`);
    }
    gap.status = "documented";
    gap.resolution = resolution;
    gap.note = note;
    gap.documentedBy = me.userId;
    gap.documentedAt = at;
    this.audit(me, "gap.document", gapId, true, `${resolution}: ${note}`);
    return this.stripGap(gap);
  }

  listGaps(actor: Actor): GapRecord[] {
    const me = this.resolveActor(actor);
    if (me.role === "unblinded-user") {
      this.deny(me, "chain.read", "gaps", "解盲账户不得浏览监管数据");
    }
    return this.gaps.map((g) => this.stripGap(g));
  }

  // -- 冻结与导出 ----------------------------------------------------------

  /** 数据经理冻结当前开放修订版；此后新上传进入下一修订版。 */
  freeze(actor: Actor, at: string, datasetId?: string): FrozenDataset {
    const me = this.resolveActor(actor);
    if (me.role !== "data-manager") {
      this.deny(me, "dataset.freeze", `revision-${this.openRevision}`, "只有数据经理可冻结批次");
    }
    const entries = this.buildListingRows();
    const rejectedPackages: Record<string, RejectCode> = {};
    for (const sub of this.rejected.filter((s) => s.revision <= this.openRevision)) {
      rejectedPackages[sub.packageId] = sub.reasons?.[0] ?? "content-digest-mismatch";
    }
    const dataset: FrozenDataset = {
      datasetId: datasetId ?? newId("ds"),
      revision: this.openRevision,
      frozenAt: at,
      packageDecisions: Object.fromEntries(
        [...this.receipts.values()].map((r) => [r.receipt.receiptId, r.state]),
      ),
      entries: structuredClone(entries),
      rejectedPackages,
      gaps: this.gaps.map((g) => this.stripGap(g)),
    };
    this.datasets.push(dataset);
    this.audit(
      me,
      "dataset.freeze",
      dataset.datasetId,
      true,
      `修订版 ${this.openRevision} 冻结，条目 ${entries.length} 条`,
    );
    this.openRevision += 1;
    return structuredClone(dataset);
  }

  /**
   * 导出清单。不给修订版 -> 开放修订版现算；给定修订版 -> 冻结时刻不可变快照。
   * 站点用户只能看到本站条目与本站事件；任何角色都看不到随机分组。
   */
  exportListing(actor: Actor, revision?: number): DatasetExport {
    const me = this.resolveActor(actor);
    if (!["site-user", "medical-monitor", "data-manager"].includes(me.role)) {
      this.deny(me, "export.read", "listing", "无导出权限");
    }

    let entries: ListingEntry[];
    let gaps: GapRecord[];
    let frozenAt: string | undefined;
    let datasetId: string | undefined;
    let rev: number;
    let custodyCutoff: string | undefined;

    if (revision !== undefined) {
      const ds = this.datasets.find((d) => d.revision === revision);
      if (!ds) throw new ValidationError(`修订版 ${revision} 未冻结`);
      entries = structuredClone(ds.entries);
      gaps = ds.gaps.map((g) => ({ ...g }));
      frozenAt = ds.frozenAt;
      datasetId = ds.datasetId;
      rev = ds.revision;
      custodyCutoff = ds.frozenAt;
    } else {
      entries = this.buildListingRows();
      gaps = this.gaps.map((g) => this.stripGap(g));
      rev = this.openRevision;
    }

    let custody = [...this.events]
      .sort((a, b) =>
        a.subjectCode.localeCompare(b.subjectCode) ||
        a.occurredAt.localeCompare(b.occurredAt),
      )
      .map((e) => ({ ...e }));
    if (custodyCutoff) custody = custody.filter((e) => e.occurredAt <= custodyCutoff);

    if (me.role === "site-user") {
      const site = me.siteId as string;
      const visibleSubjects = new Set(
        custody.filter((e) => e.siteId === site).map((e) => e.subjectCode),
      );
      entries = entries.filter((e) => e.siteId === site);
      gaps = gaps.filter((g) => visibleSubjects.has(g.subjectCode));
      custody = custody.filter((e) => e.siteId === site);
    }

    const visits = this.buildVisitVerifications(entries, me.role === "site-user" ? (me.siteId as string) : undefined);

    this.audit(
      me,
      "export.read",
      datasetId ?? `revision-${rev}`,
      true,
      revision === undefined ? "开放修订版导出" : `冻结修订版 ${revision} 导出`,
    );

    return {
      studyId: this.study.studyId,
      revision: rev,
      ...(datasetId !== undefined ? { datasetId } : {}),
      ...(frozenAt !== undefined ? { frozenAt } : {}),
      generatedAt: new Date().toISOString(),
      entries,
      visits,
      gaps,
      custody,
    };
  }

  /** 访视核验索引：每次访视关联了哪些提交、对应哪个凭证、最终什么处置。 */
  private buildVisitVerifications(
    entries: ListingEntry[],
    siteScope?: string,
  ): VisitVerification[] {
    const result: VisitVerification[] = [];
    for (const v of [...this.visits.values()].sort((a, b) =>
      a.occurredAt.localeCompare(b.occurredAt),
    )) {
      if (siteScope !== undefined && v.siteId !== siteScope) continue;
      const submissions = entries
        .filter((e) => e.visitId === v.visitId)
        .map((e) => ({
          submissionPackageId: e.submissionPackageId,
          receiptId: e.receiptId,
          disposition: e.disposition,
        }))
        .sort((a, b) => a.submissionPackageId.localeCompare(b.submissionPackageId));
      result.push({
        visitId: v.visitId,
        subjectCode: v.subjectCode,
        siteId: v.siteId,
        plannedFrom: v.plannedFrom,
        plannedTo: v.plannedTo,
        occurredAt: v.occurredAt,
        submissions,
      });
    }
    return result;
  }

  /** 每个提交编号一行：纳入/排除/替代/重复，依据只增不改，排序稳定。 */
  private buildListingRows(): ListingEntry[] {
    const rows: ListingEntry[] = [];

    for (const rec of this.receipts.values()) {
      const r = rec.receipt;
      const disposition: Disposition =
        rec.state === "superseded"
          ? "superseded"
          : rec.state === "quarantined"
            ? "excluded"
            : "included";
      rows.push(this.entryFromReceipt(rec, r.packageId, disposition, rec.state, false));
      for (const alias of [...rec.aliases].sort()) {
        rows.push(
          this.entryFromReceipt(rec, alias, "duplicate", "duplicate", true, r.packageId),
        );
      }
    }

    for (const sub of this.rejected) {
      const m = sub.manifest;
      rows.push({
        receiptId: "",
        submissionPackageId: sub.packageId,
        aliases: [],
        introducedRevision: sub.revision,
        disposition: "excluded",
        state: "rejected",
        siteId: m.siteId,
        subjectCode: this.subjectOfRejected(m),
        serialNumber: m.serialNumber,
        ...(m.visitId !== undefined ? { visitId: m.visitId } : {}),
        capturedFrom: m.capturedFrom,
        capturedTo: m.capturedTo,
        firmwareVersion: m.firmwareVersion,
        contentSha256: m.contentSha256,
        receivedAt: sub.at,
        basis: [`拒收：${(sub.reasons ?? []).map((c) => REJECT_TEXT[c]).join("；")}`],
        ...(sub.reasons ? { rejectCodes: [...sub.reasons] } : {}),
      });
    }

    return rows.sort(
      (a, b) =>
        a.introducedRevision - b.introducedRevision ||
        a.capturedFrom.localeCompare(b.capturedFrom) ||
        a.serialNumber.localeCompare(b.serialNumber) ||
        a.submissionPackageId.localeCompare(b.submissionPackageId),
    );
  }

  private entryFromReceipt(
    rec: ReceiptRecord,
    submissionPackageId: string,
    disposition: Disposition,
    state: PackageState | "duplicate",
    isAlias: boolean,
    canonicalPackageId?: string,
  ): ListingEntry {
    const r = rec.receipt;
    return {
      receiptId: r.receiptId,
      submissionPackageId,
      aliases: isAlias ? [] : [...rec.aliases].sort(),
      introducedRevision: rec.introducedRevision,
      ...(rec.changedAtRevision !== undefined && !isAlias
        ? { changedAtRevision: rec.changedAtRevision }
        : {}),
      disposition,
      state,
      siteId: r.siteId,
      subjectCode: r.subjectCode,
      serialNumber: r.serialNumber,
      ...(rec.visitId !== undefined ? { visitId: rec.visitId } : {}),
      capturedFrom: r.capturedFrom,
      capturedTo: r.capturedTo,
      firmwareVersion: r.firmwareVersion,
      contentSha256: r.contentSha256,
      receivedAt: r.receivedAt,
      basis: isAlias
        ? [`与提交 ${canonicalPackageId} 内容完全一致，重复提交，沿用原接收凭证 ${r.receiptId}`]
        : [...rec.basis],
      ...(rec.conflictWithSubmissionId !== undefined
        ? { conflictWithSubmissionId: rec.conflictWithSubmissionId }
        : {}),
      ...(rec.correctsSubmissionId !== undefined
        ? { correctsSubmissionId: rec.correctsSubmissionId }
        : {}),
      ...(rec.correctedBySubmissionId !== undefined
        ? { correctedBySubmissionId: rec.correctedBySubmissionId }
        : {}),
      ...(rec.correctionReason !== undefined ? { correctionReason: rec.correctionReason } : {}),
      ...(rec.adjudication !== undefined ? { adjudication: rec.adjudication } : {}),
    };
  }

  /** 拒收包没有凭证，受试者代号尽力从持有链还原（仅供清单展示）。 */
  private subjectOfRejected(m: UploadManifest): string {
    if (!Number.isNaN(Date.parse(m.capturedTo))) {
      const h = this.holdingAt(m.serialNumber, m.capturedTo);
      if (h.subject) return h.subject;
    }
    const sub = [...this.subjects.keys()].find((code) =>
      this.events.some((e) => e.subjectCode === code && e.serialNumber === m.serialNumber),
    );
    return sub ?? "UNKNOWN";
  }

  // -- 受试者视图与监管链读取 ---------------------------------------------

  /** 站点用户只看到与本站有关联的受试者代号；监查员/数据经理看全部代号。 */
  listSubjects(actor: Actor): string[] {
    const me = this.resolveActor(actor);
    if (me.role === "unblinded-user") {
      this.deny(me, "site.data.read", "subjects", "解盲账户不得浏览受试者列表");
    }
    this.audit(me, "site.data.read", "subjects", true, "受试者代号列表");
    if (me.role === "site-user") {
      const site = me.siteId as string;
      return [
        ...new Set(
          this.events.filter((e) => e.siteId === site).map((e) => e.subjectCode),
        ),
      ].sort();
    }
    return [...this.subjects.keys()].sort();
  }

  readCustody(actor: Actor, subjectCode?: string): DeviceCustodyEvent[] {
    const me = this.resolveActor(actor);
    if (me.role === "unblinded-user") {
      this.deny(me, "chain.read", subjectCode ?? "all", "解盲账户不得浏览监管链");
    }
    let events = [...this.events].sort(
      (a, b) =>
        a.subjectCode.localeCompare(b.subjectCode) ||
        a.occurredAt.localeCompare(b.occurredAt) ||
        a.eventId.localeCompare(b.eventId),
    );
    if (subjectCode) events = events.filter((e) => e.subjectCode === subjectCode);
    if (me.role === "site-user") {
      const site = me.siteId as string;
      const visible = new Set(
        this.events.filter((e) => e.siteId === site).map((e) => e.subjectCode),
      );
      events = events.filter((e) => e.siteId === site || visible.has(e.subjectCode));
    }
    this.audit(me, "chain.read", subjectCode ?? "all", true, `${events.length} 个事件`);
    return events.map((e) => ({ ...e }));
  }

  // -- 审计 ----------------------------------------------------------------

  listAudit(actor: Actor): AuditEntry[] {
    const me = this.resolveActor(actor);
    if (!["medical-monitor", "data-manager"].includes(me.role)) {
      this.deny(me, "chain.read", "audit", "只有医学监查员/数据经理可读取审计轨迹");
    }
    return this.auditLog.map((a) => ({ ...a }));
  }

  // -- 解盲（授权 + 双人确认）---------------------------------------------

  /**
   * 解盲：发起人与确认人必须是两名不同的在册授权解盲人员。
   * 随机分组从不由任何列表/导出接口返回，仅此接口在双人确认通过后一次性返回。
   */
  unblind(
    actor: Actor,
    confirmerId: string,
    request: { subjectCode: string; reason: string },
    at: string,
  ): UnblindRecord {
    const me = this.resolveActor(actor);

    if (me.role !== "unblinded-user") {
      this.deny(me, "unblind.attempt", request.subjectCode, "发起人不具备解盲授权");
    }
    if (me.userId === confirmerId) {
      this.deny(
        me,
        "unblind.attempt",
        request.subjectCode,
        "解盲必须由第二名授权人员确认，不得自我确认",
      );
    }
    const confirmer = this.users.get(confirmerId);
    if (!confirmer) {
      this.deny(me, "unblind.attempt", request.subjectCode, "确认人未注册");
    }
    if (confirmer.role !== "unblinded-user") {
      this.deny(me, "unblind.attempt", request.subjectCode, "确认人不具备解盲授权");
    }
    if (!this.subjects.has(request.subjectCode)) {
      this.deny(me, "unblind.attempt", request.subjectCode, "受试者代号不存在");
    }
    if (!request.reason.trim()) {
      this.deny(me, "unblind.attempt", request.subjectCode, "解盲必须记录医学原因");
    }
    const arm = this.randomization[request.subjectCode];
    if (arm === undefined) {
      this.deny(me, "unblind.attempt", request.subjectCode, "密封信封中没有该受试者的随机分组");
    }

    const record: UnblindRecord = {
      subjectCode: request.subjectCode,
      arm,
      reason: request.reason,
      actorId: me.userId,
      confirmerId,
      at,
    };
    this.unblindLog.push(record);
    this.audit(
      me,
      "unblind.attempt",
      request.subjectCode,
      true,
      `双人解盲成功，确认人 ${confirmerId}，原因：${request.reason}`,
    );
    return { ...record };
  }

  private stripGap(g: InternalGap): GapRecord {
    return {
      gapId: g.gapId,
      subjectCode: g.subjectCode,
      siteId: g.siteId,
      from: g.from,
      to: g.to,
      status: g.status,
      ...(g.resolution !== undefined ? { resolution: g.resolution } : {}),
      ...(g.note !== undefined ? { note: g.note } : {}),
      ...(g.documentedBy !== undefined ? { documentedBy: g.documentedBy } : {}),
      ...(g.documentedAt !== undefined ? { documentedAt: g.documentedAt } : {}),
    };
  }
}
