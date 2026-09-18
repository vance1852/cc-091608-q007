/**
 * 腕戴数据监管链平台核心。
 *
 * 设计原则：
 *  - 所有记录只追加；原包不覆盖、不删除，排除与替代均以状态 + 关联 + 原因表达。
 *  - 每个操作先做授权检查（站点用户锁定本站；UNBLIND 必须显式授权），再做业务校验。
 *  - 随机分组表除双人解盲成功的返回值外，不出现在任何列表、审计、导出中。
 */
import type {
  Adjudication,
  AuditEvent,
  CorrectionLink,
  CustodyAction,
  DatasetExport,
  DeviceCustodyEvent,
  DeviceRecord,
  FrozenDataset,
  PackageState,
  ProvenanceEntry,
  Role,
  StudyConfig,
  SubjectDeviceChain,
  TreatmentArm,
  UnblindResult,
  UploadManifest,
  UploadReceipt,
  UploadRejection,
  UploadResult,
  User,
} from "./contracts.js";
import {
  sha256Hex,
  verifyPackageSignature,
} from "./crypto.js";
import {
  Store,
  type GapRecord,
  type StoredPackage,
} from "./store.js";

export class PermissionDenied extends Error {}
export class DomainError extends Error {}

interface CustodyInput {
  eventId: string;
  studyId: string;
  siteId: string;
  subjectCode: string;
  serialNumber: string;
  action: CustodyAction;
  occurredAt: string;
  replacesSerialNumber?: string;
}

let auditSeq = 0;

export class CustodyPlatform {
  readonly store = new Store();
  private readonly now: () => string;

  constructor(now: () => string = () => new Date().toISOString()) {
    this.now = now;
  }

  // -------------------------------------------------------------------------
  // 基础登记
  // -------------------------------------------------------------------------

  registerStudy(config: StudyConfig): void {
    if (this.store.studies.has(config.studyId)) {
      throw new DomainError(`研究已存在: ${config.studyId}`);
    }
    this.store.studies.set(config.studyId, config);
  }

  registerDevice(record: DeviceRecord): void {
    if (this.store.devices.has(record.serialNumber)) {
      throw new DomainError(`设备已登记: ${record.serialNumber}`);
    }
    this.store.devices.set(record.serialNumber, record);
  }

  addUser(user: User): void {
    if (this.store.users.has(user.userId)) {
      throw new DomainError(`用户已存在: ${user.userId}`);
    }
    if (user.role === "site-user" && !user.siteId) {
      throw new DomainError("站点用户必须绑定站点");
    }
    this.store.users.set(user.userId, user);
  }

  // -------------------------------------------------------------------------
  // 授权与审计
  // -------------------------------------------------------------------------

  private actor(userId: string): User {
    const u = this.store.users.get(userId);
    if (!u) throw new PermissionDenied(`未知用户: ${userId}`);
    return u;
  }

  private audit(
    actor: User | { userId: string; role: Role; siteId?: string },
    action: string,
    target: string,
    allowed: boolean,
    detail?: string,
  ): void {
    auditSeq += 1;
    const ev: AuditEvent = {
      eventId: `aud-${auditSeq.toString(10).padStart(6, "0")}`,
      at: this.now(),
      actorId: actor.userId,
      actorRole: actor.role,
      action,
      target,
      allowed,
    };
    if (actor.siteId !== undefined) ev.siteScope = actor.siteId;
    if (detail !== undefined) ev.detail = detail;
    this.store.audit.push(ev);
  }

  private requireRole(user: User, roles: Role[]): void {
    if (!roles.includes(user.role)) {
      throw new PermissionDenied(
        `角色 ${user.role} 无权执行该操作（需要 ${roles.join("/")}）`,
      );
    }
  }

  /** 站点用户只能操作本站数据；其他角色受研究范围约束但可跨站。 */
  private assertSiteScope(user: User, siteId: string): void {
    if (user.role === "site-user" && user.siteId !== siteId) {
      throw new PermissionDenied(
        `站点用户 ${user.userId} 只能操作 ${user.siteId}，拒绝访问 ${siteId}`,
      );
    }
  }

  // -------------------------------------------------------------------------
  // 设备监管链：发放 / 回收 / 遗失 / 换机
  // -------------------------------------------------------------------------

  registerCustody(userId: string, input: CustodyInput): DeviceCustodyEvent {
    const user = this.actor(userId);
    this.requireRole(user, ["site-user", "data-manager"]);

    if (!this.store.studies.has(input.studyId)) {
      throw new DomainError(`未知研究: ${input.studyId}`);
    }
    if (this.store.custodyEvents.some((e) => e.eventId === input.eventId)) {
      throw new DomainError(`事件号重复: ${input.eventId}`);
    }
    if (!this.store.devices.has(input.serialNumber)) {
      throw new DomainError(`设备未登记: ${input.serialNumber}`);
    }

    // 换机/操作他人站点：站点用户必须是本站登记；跨站换机由接收站点登记。
    this.assertSiteScope(user, input.siteId);

    const current = this.store.subjectCurrent.get(input.subjectCode);
    const windows = this.store.deviceWindowsFor(input.serialNumber);
    const serialActive = windows.some((w) => w.to === undefined);

    switch (input.action) {
      case "issue": {
        if (current?.active) {
          throw new DomainError(
            `受试者 ${input.subjectCode} 仍持有 ${current.serial}，不能重复发放`,
          );
        }
        if (serialActive) {
          throw new DomainError(`设备 ${input.serialNumber} 仍在他人占有中`);
        }
        windows.push({ subjectCode: input.subjectCode, from: input.occurredAt });
        this.store.subjectCurrent.set(input.subjectCode, {
          serial: input.serialNumber,
          active: true,
        });
        break;
      }
      case "replace": {
        if (!input.replacesSerialNumber) {
          throw new DomainError("换机事件必须填写 replacesSerialNumber");
        }
        if (!current?.active || current.serial !== input.replacesSerialNumber) {
          throw new DomainError(
            `换机前置不成立：受试者当前持有的不是 ${input.replacesSerialNumber}`,
          );
        }
        if (serialActive) {
          throw new DomainError(`新设备 ${input.serialNumber} 已在占有中`);
        }
        if (input.serialNumber === input.replacesSerialNumber) {
          throw new DomainError("换机不能使用同一序列号");
        }
        // 关闭旧设备窗口（交接记录），开启新设备窗口。
        const oldWindows = this.store.deviceWindowsFor(input.replacesSerialNumber);
        const oldWindow = [...oldWindows].reverse().find((w) => w.to === undefined);
        if (oldWindow) {
          oldWindow.to = input.occurredAt;
          oldWindow.endedBy = "replace";
        }
        windows.push({ subjectCode: input.subjectCode, from: input.occurredAt });
        this.store.subjectCurrent.set(input.subjectCode, {
          serial: input.serialNumber,
          active: true,
        });
        // 遗失缺口在换机时给出终点，仍由医学监查员确认关闭。
        for (const gap of this.store.gaps) {
          if (
            gap.subjectCode === input.subjectCode &&
            gap.status === "open" &&
            gap.kind === "device-lost" &&
            gap.to === undefined
          ) {
            gap.to = input.occurredAt;
            gap.note = `${gap.note}；已于 ${input.occurredAt} 换机为 ${input.serialNumber}`;
          }
        }
        break;
      }
      case "return":
      case "lost": {
        if (!current?.active || current.serial !== input.serialNumber) {
          throw new DomainError(
            `${input.action} 不成立：${input.serialNumber} 非该受试者当前持有设备`,
          );
        }
        const window = [...windows].reverse().find((w) => w.to === undefined);
        if (window) {
          window.to = input.occurredAt;
          window.endedBy = input.action;
        }
        this.store.subjectCurrent.set(input.subjectCode, {
          serial: input.serialNumber,
          active: false,
        });
        if (input.action === "lost") {
          this.store.gaps.push({
            gapId: `gap-${this.store.gaps.length + 1}`,
            studyId: input.studyId,
            subjectCode: input.subjectCode,
            serialNumber: input.serialNumber,
            from: input.occurredAt,
            kind: "device-lost",
            note: `设备 ${input.serialNumber} 于 ${input.occurredAt} 遗失，数据采集中断`,
            status: "open",
            reportedAt: this.now(),
          });
        }
        break;
      }
    }

    this.store.subjectSiteSet(input.subjectCode).add(input.siteId);

    const event: DeviceCustodyEvent = {
      ...input,
      recordedAt: this.now(),
      recordedBy: user.userId,
    };
    this.store.custodyEvents.push(event);
    this.audit(user, `custody.${input.action}`, input.serialNumber, true,
      `subject=${input.subjectCode} site=${input.siteId}` +
        (input.replacesSerialNumber ? ` replaces=${input.replacesSerialNumber}` : ""));
    return event;
  }

  // -------------------------------------------------------------------------
  // 上传校验管线
  // -------------------------------------------------------------------------

  private reject(
    user: User,
    manifest: UploadManifest,
    code: UploadRejection["code"],
    message: string,
  ): UploadRejection {
    this.store.rejected.push({
      packageId: manifest.packageId,
      studyId: this.studyId,
      siteId: manifest.siteId,
      serialNumber: manifest.serialNumber,
      submittedBy: user.userId,
      code,
      at: this.now(),
    });
    this.audit(user, "upload.reject", manifest.packageId, false, code);
    return {
      accepted: false,
      rejected: true,
      code,
      message,
      submittedPackageId: manifest.packageId,
      at: this.now(),
    };
  }

  /** 平台一次装载一个研究；所有包均归属该研究。 */
  private get studyId(): string {
    const id = [...this.store.studies.keys()][0];
    if (!id) throw new DomainError("尚未装载研究配置");
    return id;
  }

  /** 区间占用跨修订版连续：冻结后重提异内容同区间仍会与历史批次冲突。 */
  private intervalKey(serial: string, from: string, to: string): string {
    return `${serial}:${from}|${to}`;
  }

  private coveringWindow(
    serial: string,
    from: string,
    to: string,
  ): { subject: string; siteOk: (siteId: string) => boolean } | undefined {
    const windows = this.store.deviceWindows.get(serial) ?? [];
    const win = windows.find(
      (w) => w.from <= from && to <= (w.to ?? "9999-12-31T23:59:59.999Z"),
    );
    if (!win) return undefined;
    return {
      subject: win.subjectCode,
      siteOk: (siteId) =>
        this.store.subjectSites.get(win.subjectCode)?.has(siteId) ?? false,
    };
  }

  /**
   * 提交数据包。校验顺序：
   * 站点范围 → 内容摘要 → 设备登记 → 设备签名 → 固件许可 → 采集区间 →
   * 占有窗口 → 校正目标 → 完全重复（返回原凭证）→ 同区间异内容（隔离）。
   */
  submitPackage(
    userId: string,
    manifest: UploadManifest,
    payloadBytes: string | Buffer,
  ): UploadResult {
    const user = this.actor(userId);
    this.requireRole(user, ["site-user", "data-manager"]);

    // 站点范围：站点用户不得为其他站点提交。
    if (user.role === "site-user" && user.siteId !== manifest.siteId) {
      this.audit(user, "upload.denied", manifest.packageId, false,
        `cross-site ${user.siteId}->${manifest.siteId}`);
      return this.reject(user, manifest, "WRONG_SITE",
        `站点用户不能为 ${manifest.siteId} 提交包（本站 ${user.siteId}）`);
    }

    // 1) 内容摘要必须与载荷实际字节一致。
    const actualDigest = sha256Hex(payloadBytes);
    if (actualDigest !== manifest.contentSha256) {
      return this.reject(user, manifest, "DIGEST_MISMATCH",
        `内容摘要不匹配：声明 ${manifest.contentSha256.slice(0, 12)}… 实际 ${actualDigest.slice(0, 12)}…`);
    }

    // 2) 设备必须已登记。
    const device = this.store.devices.get(manifest.serialNumber);
    if (!device) {
      return this.reject(user, manifest, "UNKNOWN_DEVICE",
        `未知设备序列号: ${manifest.serialNumber}`);
    }

    // 3) 设备签名（Ed25519，公钥来自设备登记记录）。
    if (!verifyPackageSignature(manifest, device.publicKeyPem)) {
      return this.reject(user, manifest, "BAD_SIGNATURE",
        "设备签名验签失败");
    }

    // 4) 固件许可白名单。
    const study = [...this.store.studies.values()][0];
    if (!study) throw new DomainError("尚未装载研究配置");
    if (!study.allowedFirmware.includes(manifest.firmwareVersion)) {
      return this.reject(user, manifest, "FIRMWARE_NOT_LICENSED",
        `固件 ${manifest.firmwareVersion} 不在研究许可名单（${study.allowedFirmware.join(", ")}）`);
    }

    // 5) 采集区间合法。
    if (
      !(manifest.capturedFrom < manifest.capturedTo) ||
      Number.isNaN(Date.parse(manifest.capturedFrom)) ||
      Number.isNaN(Date.parse(manifest.capturedTo))
    ) {
      return this.reject(user, manifest, "BAD_INTERVAL",
        "采集区间非法：capturedFrom 必须早于 capturedTo 且均为有效时间");
    }

    // 6) 采集区间必须完全落在设备由某受试者占有的窗口内。
    const cover = this.coveringWindow(
      manifest.serialNumber,
      manifest.capturedFrom,
      manifest.capturedTo,
    );
    if (!cover) {
      return this.reject(user, manifest, "OUTSIDE_CUSTODY",
        `采集区间 ${manifest.capturedFrom}/${manifest.capturedTo} 不在设备 ${manifest.serialNumber} 的占有窗口内`);
    }
    if (!cover.siteOk(manifest.siteId)) {
      return this.reject(user, manifest, "WRONG_SITE",
        `站点 ${manifest.siteId} 与受试者 ${cover.subject} 的设备交接链无关`);
    }

    // 7) 校正目标校验（不覆盖原包，只建立带原因的替代关系）。
    let correctionTarget: StoredPackage | undefined;
    if (manifest.correctsPackageId !== undefined) {
      if (!manifest.correctionReason?.trim()) {
        throw new DomainError("校正包必须提供 correctionReason");
      }
      correctionTarget = this.store.packages.get(manifest.correctsPackageId);
      if (!correctionTarget) {
        return this.reject(user, manifest, "UNKNOWN_CORRECTION_TARGET",
          `校正目标包不存在: ${manifest.correctsPackageId}`);
      }
      if (correctionTarget.manifest.contentSha256 === manifest.contentSha256) {
        throw new DomainError("校正包内容与原包完全相同，不构成校正");
      }
    }

    // 8) 完全相同的包（同设备 + 同内容摘要）：返回原接收凭证。
    //    在全部已存包中检索（含隔离包），保证重复提交在裁决前后都返回同一凭证。
    const contentKey = `${manifest.serialNumber}:${manifest.contentSha256}`;
    const identical = this.store.contentIndex.get(contentKey) ??
      [...this.store.packages.values()].find(
        (p) =>
          `${p.manifest.serialNumber}:${p.manifest.contentSha256}` === contentKey,
      );
    if (identical) {
      const sameInterval =
        identical.manifest.capturedFrom === manifest.capturedFrom &&
        identical.manifest.capturedTo === manifest.capturedTo;
      if (sameInterval) {
        this.store.duplicates.push({
          receiptId: identical.receiptId,
          canonicalPackageId: identical.packageId,
          submittedPackageId: manifest.packageId,
          submittedBy: user.userId,
          at: this.now(),
        });
        this.audit(user, "upload.duplicate", manifest.packageId, true,
          `canonical=${identical.packageId} receipt=${identical.receiptId}`);
        const receipt: UploadReceipt = {
          accepted: true,
          receiptId: identical.receiptId,
          canonicalPackageId: identical.packageId,
          submittedPackageId: manifest.packageId,
          state: identical.state,
          duplicate: true,
          subjectCode: identical.subjectCode,
          contentSha256: manifest.contentSha256,
          revision: identical.revision,
          receivedAt: identical.receivedAt,
        };
        const qr = identical.quarantineReason?.();
        if (qr !== undefined) receipt.quarantinedReason = qr;
        return receipt;
      }
      // 同内容却声明不同采集区间：数据来路自相矛盾，隔离。
      return this.quarantine(user, manifest, cover.subject,
        `与已接收包 ${identical.packageId} 内容相同但申报了不同采集区间`,
        identical.packageId);
    }

    if (this.store.packages.has(manifest.packageId)) {
      throw new DomainError(`包号 ${manifest.packageId} 已被不同内容占用，禁止覆盖`);
    }

    // 9) 同设备同区间、不同内容：冲突隔离，等待医学监查员裁决。
    //    校正包针对的正是区间占用者时除外——那是显式替代。
    const intervalKey = this.intervalKey(manifest.serialNumber, manifest.capturedFrom, manifest.capturedTo);
    const occupant = this.store.intervalIndex.get(intervalKey);
    if (occupant && (!correctionTarget || correctionTarget.packageId !== occupant.packageId)) {
      return this.quarantine(user, manifest, cover.subject,
        `与已接收包 ${occupant.packageId} 声明相同采集区间但内容摘要不同（${manifest.contentSha256.slice(0, 6)} vs ${occupant.manifest.contentSha256.slice(0, 6)}）`,
        occupant.packageId);
    }

    // 通过全部校验 → 接收。
    return this.accept(user, manifest, cover.subject, correctionTarget);
  }

  private receiptIdFor(manifest: UploadManifest): string {
    return `rcpt-${sha256Hex(`${manifest.serialNumber}:${manifest.contentSha256}`).slice(0, 16)}`;
  }

  private accept(
    user: User,
    manifest: UploadManifest,
    subjectCode: string,
    correctionTarget: StoredPackage | undefined,
  ): UploadReceipt {
    const receiptId = this.receiptIdFor(manifest);
    const stored: StoredPackage = {
      packageId: manifest.packageId,
      studyId: this.studyId,
      siteId: manifest.siteId,
      subjectCode,
      manifest,
      state: "accepted",
      receiptId,
      revision: this.store.currentRevision,
      receivedAt: this.now(),
      receivedBy: user.userId,
    };
    stored.quarantineReason = () => undefined;
    this.store.packages.set(manifest.packageId, stored);
    this.store.contentIndex.set(
      `${manifest.serialNumber}:${manifest.contentSha256}`,
      stored,
    );
    this.store.intervalIndex.set(
      this.intervalKey(manifest.serialNumber, manifest.capturedFrom, manifest.capturedTo),
      stored,
    );

    if (correctionTarget) {
      // 原包永久保留，仅转为 superseded，并追加带原因的替代关系。
      correctionTarget.state = "superseded";
      const link: CorrectionLink = {
        correctedPackageId: correctionTarget.packageId,
        correctionPackageId: manifest.packageId,
        reason: manifest.correctionReason!,
        linkedBy: user.userId,
        linkedAt: this.now(),
      };
      this.store.corrections.push(link);
      this.audit(user, "correction.link", manifest.packageId, true,
        `corrects=${correctionTarget.packageId} reason="${link.reason}"`);
    }

    this.audit(user, "upload.accept", manifest.packageId, true,
      `subject=${subjectCode} serial=${manifest.serialNumber} rev=${stored.revision}`);

    return {
      accepted: true,
      receiptId,
      canonicalPackageId: manifest.packageId,
      submittedPackageId: manifest.packageId,
      state: "accepted",
      duplicate: false,
      subjectCode,
      contentSha256: manifest.contentSha256,
      revision: stored.revision,
      receivedAt: stored.receivedAt,
    };
  }

  private quarantine(
    user: User,
    manifest: UploadManifest,
    subjectCode: string,
    reason: string,
    conflictWith: string,
  ): UploadReceipt {
    const receiptId = this.receiptIdFor(manifest);
    const stored: StoredPackage = {
      packageId: manifest.packageId,
      studyId: this.studyId,
      siteId: manifest.siteId,
      subjectCode,
      manifest,
      state: "quarantined",
      conflictWith,
      receiptId,
      revision: this.store.currentRevision,
      receivedAt: this.now(),
      receivedBy: user.userId,
    };
    let qReason = reason;
    stored.quarantineReason = () => qReason;
    this.store.packages.set(manifest.packageId, stored);
    // 隔离包不进入 content/interval 索引：它尚未被认定为任何区间的合法内容。

    this.store.gaps.push({
      gapId: `gap-${this.store.gaps.length + 1}`,
      studyId: stored.studyId,
      subjectCode,
      serialNumber: manifest.serialNumber,
      from: manifest.capturedFrom,
      to: manifest.capturedTo,
      kind: "content-conflict",
      note: reason,
      status: "open",
      reportedAt: this.now(),
    });
    this.audit(user, "upload.quarantine", manifest.packageId, false, reason);
    return {
      accepted: true,
      receiptId,
      canonicalPackageId: manifest.packageId,
      submittedPackageId: manifest.packageId,
      state: "quarantined",
      duplicate: false,
      subjectCode,
      contentSha256: manifest.contentSha256,
      revision: stored.revision,
      receivedAt: stored.receivedAt,
      quarantinedReason: reason,
    };
  }

  // -------------------------------------------------------------------------
  // 裁决与缺口处理（医学监查员；看不到随机分组）
  // -------------------------------------------------------------------------

  adjudicate(
    userId: string,
    packageId: string,
    decision: Adjudication["decision"],
    reason: string,
  ): Adjudication {
    const user = this.actor(userId);
    this.requireRole(user, ["medical-monitor"]);
    if (!reason.trim()) throw new DomainError("裁决必须写明原因");

    const pkg = this.store.packages.get(packageId);
    if (!pkg) throw new DomainError(`包不存在: ${packageId}`);
    if (pkg.state !== "quarantined") {
      throw new DomainError(`仅隔离包可裁决，当前状态 ${pkg.state}`);
    }

    const record: Adjudication = {
      packageId,
      decision,
      reason,
      decidedBy: user.userId,
      decidedAt: this.now(),
    };
    this.store.adjudications.push(record);

    if (decision === "accepted") {
      // 以本包为准：原区间占用者被替代（superseded），但记录永久保留。
      pkg.state = "accepted";
      const intervalKey = this.intervalKey(pkg.manifest.serialNumber, pkg.manifest.capturedFrom, pkg.manifest.capturedTo);
      const prior = this.store.intervalIndex.get(intervalKey);
      if (prior && prior.packageId !== packageId) {
        prior.state = "superseded";
      }
      this.store.intervalIndex.set(intervalKey, pkg);
      this.store.contentIndex.set(
        `${pkg.manifest.serialNumber}:${pkg.manifest.contentSha256}`,
        pkg,
      );
      this.audit(user, "adjudicate.accept", packageId, true,
        `reason="${reason}"${prior && prior.packageId !== packageId ? ` superseded=${prior.packageId}` : ""}`);
    } else {
      this.audit(user, "adjudicate.exclude", packageId, true, `reason="${reason}"`);
    }

    // 该冲突缺口至此有了结论。
    this.resolveConflictGaps(pkg, user, `冲突裁决（${decision}）：${reason}`);
    return record;
  }

  private resolveConflictGaps(pkg: StoredPackage, by: User, resolution: string): void {
    for (const gap of this.store.gaps) {
      if (
        gap.status === "open" &&
        gap.kind === "content-conflict" &&
        gap.subjectCode === pkg.subjectCode &&
        gap.serialNumber === pkg.manifest.serialNumber
      ) {
        gap.status = "resolved";
        gap.resolvedAt = this.now();
        gap.resolvedBy = by.userId;
        gap.resolution = resolution;
      }
    }
  }

  listGaps(userId: string): GapRecord[] {
    const user = this.actor(userId);
    if (user.role === "site-user") {
      return this.store.gaps.filter(
        (g) =>
          this.store.subjectSites.get(g.subjectCode)?.has(user.siteId!) ?? false,
      );
    }
    this.requireRole(user, ["medical-monitor", "data-manager", "auditor"]);
    return [...this.store.gaps];
  }

  resolveGap(userId: string, gapId: string, resolution: string): GapRecord {
    const user = this.actor(userId);
    this.requireRole(user, ["medical-monitor"]);
    if (!resolution.trim()) throw new DomainError("缺口处理必须写明结论");
    const gap = this.store.gaps.find((g) => g.gapId === gapId);
    if (!gap) throw new DomainError(`缺口不存在: ${gapId}`);
    if (gap.status === "resolved") throw new DomainError("缺口已关闭");
    gap.status = "resolved";
    gap.resolvedAt = this.now();
    gap.resolvedBy = user.userId;
    gap.resolution = resolution;
    this.audit(user, "gap.resolve", gapId, true, `kind=${gap.kind} note="${resolution}"`);
    return gap;
  }

  // -------------------------------------------------------------------------
  // 查询：普通站点只见本站代号
  // -------------------------------------------------------------------------

  listPackages(userId: string): Array<{
    packageId: string;
    subjectCode: string;
    siteId: string;
    serialNumber: string;
    firmwareVersion: string;
    state: PackageState;
    revision: number;
    receivedAt: string;
  }> {
    const user = this.actor(userId);
    const rows = [...this.store.packages.values()]
      .filter((p) => user.role !== "site-user" || p.siteId === user.siteId)
      .map((p) => ({
        packageId: p.packageId,
        subjectCode: p.subjectCode,
        siteId: p.siteId,
        serialNumber: p.manifest.serialNumber,
        firmwareVersion: p.manifest.firmwareVersion,
        state: p.state,
        revision: p.revision,
        receivedAt: p.receivedAt,
      }))
      .sort((a, b) =>
        a.subjectCode.localeCompare(b.subjectCode) ||
        a.receivedAt.localeCompare(b.receivedAt));
    this.audit(user, "packages.list", user.role, true,
      `count=${rows.length}${user.role === "site-user" ? ` site=${user.siteId}` : ""}`);
    return rows;
  }

  // -------------------------------------------------------------------------
  // 冻结批次与修订版
  // -------------------------------------------------------------------------

  freezeDataset(userId: string, datasetId: string): FrozenDataset {
    const user = this.actor(userId);
    this.requireRole(user, ["data-manager"]);
    if (this.store.datasets.some((d) => d.datasetId === datasetId)) {
      throw new DomainError(`批次号已存在: ${datasetId}`);
    }

    const revision = this.store.currentRevision;
    const packageDecisions: Record<string, PackageState> = {};
    const exclusionReasons: Record<string, string> = {};

    for (const pkg of this.store.packages.values()) {
      if (pkg.revision !== revision) continue;
      packageDecisions[pkg.packageId] = pkg.state;
      if (pkg.state === "quarantined") {
        const adj = [...this.store.adjudications].reverse().find(
          (a) => a.packageId === pkg.packageId,
        );
        exclusionReasons[pkg.packageId] = adj
          ? `裁决排除：${adj.reason}`
          : `冲突隔离待裁决：${pkg.quarantineReason?.() ?? ""}`;
      } else if (pkg.state === "superseded") {
        const correction = this.store.corrections.find(
          (c) => c.correctedPackageId === pkg.packageId,
        );
        const conflictWinner = [...this.store.adjudications].reverse().find(
          (a) => a.decision === "accepted" &&
            this.store.packages.get(a.packageId)?.conflictWith === pkg.packageId,
        );
        exclusionReasons[pkg.packageId] = correction
          ? `被校正包 ${correction.correctionPackageId} 替代：${correction.reason}`
          : conflictWinner
            ? `冲突裁决以 ${conflictWinner.packageId} 为准，本包排除`
            : "已被替代";
      }
    }

    const dataset: FrozenDataset = {
      datasetId,
      studyId: this.studyId,
      revision,
      frozenAt: this.now(),
      frozenBy: user.userId,
      packageDecisions,
      exclusionReasons,
      corrections: this.store.corrections
        .filter((c) => this.store.packages.get(c.correctionPackageId)?.revision === revision)
        .map((c) => ({ ...c })),
      subjectChains: this.buildChains(),
      packageCount: Object.keys(packageDecisions).length,
    };
    const predecessor = [...this.store.datasets].reverse().find((d) => true);
    if (predecessor) dataset.predecessorDatasetId = predecessor.datasetId;

    this.store.datasets.push(dataset);
    this.store.currentRevision += 1;
    this.audit(user, "dataset.freeze", datasetId, true,
      `rev=${revision} packages=${dataset.packageCount}`);
    return dataset;
  }

  // -------------------------------------------------------------------------
  // 导出清单：稳定、可复算、含纳入/排除/替代依据
  // -------------------------------------------------------------------------

  listDatasets(userId: string): FrozenDataset[] {
    const user = this.actor(userId);
    this.requireRole(user, ["data-manager", "auditor", "medical-monitor"]);
    return [...this.store.datasets];
  }

  exportDataset(userId: string, datasetId?: string): DatasetExport {
    const user = this.actor(userId);
    this.requireRole(user, ["data-manager", "auditor", "medical-monitor"]);

    let frozen: FrozenDataset | undefined;
    let revision: number;
    if (datasetId) {
      frozen = this.store.datasets.find((d) => d.datasetId === datasetId);
      if (!frozen) throw new DomainError(`批次不存在: ${datasetId}`);
      revision = frozen.revision;
    } else {
      revision = this.store.currentRevision;
    }

    const pkgs = [...this.store.packages.values()]
      .filter((p) => p.revision === revision)
      .sort((a, b) =>
        a.subjectCode.localeCompare(b.subjectCode) ||
        a.manifest.capturedFrom.localeCompare(b.manifest.capturedFrom) ||
        a.packageId.localeCompare(b.packageId));

    const corrections = frozen
      ? frozen.corrections
      : this.store.corrections.filter(
          (c) => this.store.packages.get(c.correctionPackageId)?.revision === revision,
        );

    const entries: ProvenanceEntry[] = pkgs.map((p) => {
      const device = this.store.devices.get(p.manifest.serialNumber)!;
      const adj = [...this.store.adjudications].reverse().find(
        (a) => a.packageId === p.packageId,
      );
      const correctedBy = corrections.find(
        (c) => c.correctedPackageId === p.packageId,
      );
      const winnerAdj = this.store.adjudications.find(
        (a) =>
          a.decision === "accepted" &&
          this.store.packages.get(a.packageId)?.conflictWith === p.packageId,
      );

      let state: PackageState = p.state;
      let basis: string;
      let basisDetail: string;
      if (correctedBy) {
        basis = "SUPERSEDED_BY_CORRECTION";
        basisDetail = `被校正包 ${correctedBy.correctionPackageId} 替代；原因：${correctedBy.reason}`;
      } else if (p.state === "accepted") {
        if (p.conflictWith) {
          basis = "ADJUDICATED_INCLUDED";
          basisDetail = `冲突隔离后经裁决纳入（${adj?.reason ?? ""}）；替代冲突包 ${p.conflictWith}`;
        } else if (p.manifest.correctsPackageId) {
          basis = "ACCEPTED_CORRECTION";
          basisDetail = `校正包，替代 ${p.manifest.correctsPackageId}；原因：${p.manifest.correctionReason}`;
        } else {
          basis = "ACCEPTED";
          basisDetail = "通过全部监管链校验后接收";
        }
      } else if (p.state === "quarantined") {
        if (adj?.decision === "excluded") {
          state = "quarantined";
          basis = "ADJUDICATED_EXCLUDED";
          basisDetail = `相同区间内容冲突，经裁决排除：${adj.reason}`;
        } else {
          basis = "QUARANTINED_PENDING";
          basisDetail = `相同区间内容冲突，隔离待裁决：${p.quarantineReason?.() ?? ""}`;
        }
      } else {
        // superseded
        if (winnerAdj) {
          basis = "EXCLUDED_BY_CONFLICT_DECISION";
          basisDetail = `冲突裁决以 ${winnerAdj.packageId} 为准，本包排除`;
        } else {
          basis = "SUPERSEDED_OTHER";
          basisDetail = "已被替代";
        }
      }

      return {
        packageId: p.packageId,
        subjectCode: p.subjectCode,
        siteId: p.siteId,
        serialNumber: p.manifest.serialNumber,
        deviceKeyId: device.keyId,
        firmwareVersion: p.manifest.firmwareVersion,
        capturedFrom: p.manifest.capturedFrom,
        capturedTo: p.manifest.capturedTo,
        contentSha256: p.manifest.contentSha256,
        state,
        included: state === "accepted",
        basis,
        basisDetail,
        receiptId: p.receiptId,
        revision,
      };
    });

    // 冻结批次使用快照中的交接链；活动工作区导出当前状态。
    const chains: SubjectDeviceChain[] = frozen
      ? frozen.subjectChains.map((c) => ({
          subjectCode: c.subjectCode,
          links: c.links.map((l) => ({ ...l })),
        }))
      : this.buildChains();

    const includedPackages = entries.filter((e) => e.included).map((e) => e.packageId);
    const excludedPackages = entries
      .filter((e) => !e.included)
      .map((e) => ({ packageId: e.packageId, basis: e.basis, detail: e.basisDetail }));

    const rejectedSubmissions = this.store.rejected.map((r) => ({
      packageId: r.packageId,
      siteId: r.siteId,
      serialNumber: r.serialNumber,
      submittedBy: r.submittedBy,
      code: r.code,
      at: r.at,
    }));

    const generatedAt = this.now();
    const exportObj: DatasetExport = {
      studyId: this.studyId,
      datasetId: frozen?.datasetId ?? "workspace",
      revision,
      frozen: frozen !== undefined,
      generatedAt,
      entries,
      subjectChains: chains,
      includedPackages,
      excludedPackages,
      corrections: corrections.map((c) => ({ ...c })),
      rejectedSubmissions,
      exportSha256: "",
    };
    // 摘要只对清单内容计算（不含生成时刻与摘要自身），
    // 因而同一份冻结批次在任何时刻重新导出，exportSha256 都保持一致。
    const digestView = { ...exportObj, generatedAt: undefined, exportSha256: undefined };
    exportObj.exportSha256 = sha256Hex(canonicalJson(digestView));

    this.audit(user, "dataset.export", datasetId ?? "workspace", true,
      `rev=${revision} entries=${entries.length} sha=${exportObj.exportSha256.slice(0, 12)}`);
    return exportObj;
  }

  private buildChains(): SubjectDeviceChain[] {
    const bySubject = new Map<string, SubjectDeviceChain>();
    for (const ev of this.store.custodyEvents) {
      let chain = bySubject.get(ev.subjectCode);
      if (!chain) {
        chain = { subjectCode: ev.subjectCode, links: [] };
        bySubject.set(ev.subjectCode, chain);
      }
      const link: SubjectDeviceChain["links"][number] = {
        eventId: ev.eventId,
        action: ev.action,
        siteId: ev.siteId,
        serialNumber: ev.serialNumber,
        occurredAt: ev.occurredAt,
      };
      if (ev.replacesSerialNumber !== undefined) {
        link.replacesSerialNumber = ev.replacesSerialNumber;
      }
      chain.links.push(link);
    }
    for (const chain of bySubject.values()) {
      chain.links.sort(
        (a, b) =>
          a.occurredAt.localeCompare(b.occurredAt) ||
          a.eventId.localeCompare(b.eventId),
      );
    }
    return [...bySubject.values()].sort((a, b) =>
      a.subjectCode.localeCompare(b.subjectCode));
  }

  // -------------------------------------------------------------------------
  // 双人控制解盲：授权 + 两名独立授权人确认；盲态不泄露给监查员
  // -------------------------------------------------------------------------

  requestUnblind(
    requesterId: string,
    confirmerId: string,
    subjectCode: string,
    reason: string,
  ): UnblindResult {
    const requester = this.store.users.get(requesterId);
    const confirmer = this.store.users.get(confirmerId);
    const at = this.now();

    const fail = (code: string, detail: string, actor: User | { userId: string; role: Role }): UnblindResult => {
      this.audit(actor, "unblind.denied", subjectCode, false, `${code}: ${detail}`);
      return {
        revealed: false,
        subjectCode,
        requesterId,
        confirmerId,
        reason,
        at,
        denialCode: code,
      };
    };

    if (!requester) {
      return fail("UNKNOWN_REQUESTER", "请求人不存在", { userId: requesterId, role: "data-manager" });
    }
    if (!requester.permissions?.includes("UNBLIND")) {
      return fail("REQUESTER_NOT_AUTHORIZED",
        `${requester.role} 不具备 UNBLIND 显式授权`, requester);
    }
    if (!confirmer) {
      return fail("UNKNOWN_CONFIRMER", "确认人不存在", requester);
    }
    if (confirmer.userId === requester.userId) {
      return fail("SAME_USER", "解盲必须由两名不同人员完成", requester);
    }
    if (!confirmer.permissions?.includes("UNBLIND")) {
      return fail("CONFIRMER_NOT_AUTHORIZED",
        `确认人 ${confirmer.userId}（${confirmer.role}）不具备 UNBLIND 授权`, requester);
    }
    if (!reason.trim()) {
      return fail("NO_REASON", "解盲必须填写医学原因", requester);
    }

    const study = [...this.store.studies.values()][0];
    const arm: TreatmentArm | undefined = study?.randomization[subjectCode];
    if (!arm) {
      return fail("UNKNOWN_SUBJECT", `随机表中无受试者 ${subjectCode}`, requester);
    }

    // 审计记录“谁在何时因何解盲了谁”，但绝不记录分组结果。
    this.audit(requester, "unblind", subjectCode, true,
      `confirmer=${confirmerId} reason="${reason}"`);
    return {
      revealed: true,
      subjectCode,
      requesterId,
      confirmerId,
      reason,
      at,
      arm,
    };
  }

  // -------------------------------------------------------------------------
  // 审计追踪（仅稽查员/数据经理可读）
  // -------------------------------------------------------------------------

  listAudit(userId: string): AuditEvent[] {
    const user = this.actor(userId);
    this.requireRole(user, ["auditor", "data-manager"]);
    return [...this.store.audit];
  }
}

/** 规范化 JSON：对象键递归排序，数组保持顺序，保证导出摘要可复算。 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortKeys(value));
}

function sortKeys(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sortKeys);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([a], [b]) => a.localeCompare(b))
        .map(([k, v]) => [k, sortKeys(v)]),
    );
  }
  return value;
}
