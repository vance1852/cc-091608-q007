/**
 * 用 fixtures/site-uploads.json 驱动完整监管链场景，供 demo 与测试共用。
 * 时间线：
 *   修订版 1：登记发放/换机/遗失链，上传基线包（重复、冲突、拒收、校正、换机首包）
 *             医学监查员处理换机缺口、裁决 pkg-2 维持排除；数据经理冻结
 *   修订版 2：随访包 pkg-4 与冲突重传 pkg-4b；裁决采纳 pkg-4b（pkg-4 转替代）；再次冻结
 *   解盲：两名授权人员双人确认（另有一次被拒的自我确认演示）
 */
import { existsSync, readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";
import { CustodyLedger } from "./ledger.js";
import type {
  Actor,
  DeviceRecord,
  UploadManifest,
} from "./contracts.js";

export interface FixtureFile {
  studyId: string;
  note: string;
  study: ConstructorParameters<typeof CustodyLedger>[0]["study"];
  users: Actor[];
  subjects: ConstructorParameters<typeof CustodyLedger>[0]["subjects"];
  visits: ConstructorParameters<typeof CustodyLedger>[0]["visits"];
  devices: Array<DeviceRecord & { keyPairJwk: unknown }>;
  randomization: Record<string, string>;
  events: Array<{
    action: "issue" | "return" | "lost" | "replace";
    siteId: string;
    subjectCode: string;
    serialNumber: string;
    occurredAt: string;
    replacesSerialNumber?: string;
    visitId?: string;
  }>;
  packages: Array<UploadManifest & { payload?: string }>;
}

function projectRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  while (!existsSync(resolve(dir, "package.json"))) {
    const parent = dirname(dir);
    if (parent === dir) throw new Error("找不到 package.json");
    dir = parent;
  }
  return dir;
}

export const FIXTURE_PATH = resolve(projectRoot(), "fixtures/site-uploads.json");

export function loadFixture(path: string = FIXTURE_PATH): FixtureFile {
  return JSON.parse(readFileSync(path, "utf8")) as FixtureFile;
}

export interface ScenarioResult {
  ledger: CustodyLedger;
  fixture: FixtureFile;
  actor: (userId: string) => Actor;
  rev1FrozenAt: string;
  rev2FrozenAt: string;
}

export function runScenario(path?: string): ScenarioResult {
  const fixture = loadFixture(path);
  const actor = (userId: string): Actor => {
    const u = fixture.users.find((x) => x.userId === userId);
    if (!u) throw new Error(`fixture 中没有用户 ${userId}`);
    return { userId: u.userId, role: u.role, ...(u.siteId ? { siteId: u.siteId } : {}) };
  };

  const ledger = new CustodyLedger({
    study: fixture.study,
    subjects: fixture.subjects,
    devices: fixture.devices.map(({ keyPairJwk: _key, ...d }) => d),
    visits: fixture.visits,
    users: fixture.users,
    randomization: fixture.randomization,
  });

  const dm = actor("dm-zhang");
  const monitor = actor("mon-li");
  const siteA = actor("sitea-wang");
  const siteB = actor("siteb-chen");

  // 1) 监管链登记（数据经理按站点交接记录统一登记）
  for (const e of fixture.events) {
    ledger.registerCustody(dm, e);
  }

  const byId = new Map(fixture.packages.map((p) => [p.packageId, p]));
  const submit = (id: string, who: Actor) => {
    const p = byId.get(id)!;
    const { payload, ...manifest } = p;
    return ledger.submitPackage(
      who,
      manifest,
      payload !== undefined ? Buffer.from(payload) : undefined,
    );
  };

  // 2) 修订版 1 的上传（pkg-4 / pkg-4b 留待冻结后）
  const rev1Ids = [
    "pkg-1",
    "pkg-1-retry",
    "pkg-2",
    "pkg-1-badfw",
    "pkg-1-badsig",
    "pkg-1-baddigest",
    "pkg-1-corr",
    "pkg-3",
    "pkg-5",
    "pkg-6",
  ];
  for (const id of rev1Ids) {
    const p = byId.get(id)!;
    submit(id, p.siteId === "site-b" ? siteB : siteA);
  }

  // 3) 医学监查员处理两段换机/补发缺口
  const gaps = ledger.listGaps(monitor);
  const gapA14 = gaps.find((g) => g.subjectCode === "A-014")!;
  const gapA27 = gaps.find((g) => g.subjectCode === "A-027")!;
  ledger.documentGap(
    monitor,
    gapA14.gapId,
    "documented-gap",
    "受试者 A-014 转至 site-b 随访，现场换机约 22 小时未佩戴，已记录于交接单 CHG-2026-014",
    "2026-08-14T09:00:00Z",
  );
  ledger.documentGap(
    monitor,
    gapA27.gapId,
    "documented-gap",
    "受试者 A-027 原设备遗失，补发前约 21 小时无数据，遗失报告 LOSS-2026-027 已归档",
    "2026-07-25T09:00:00Z",
  );

  // 4) pkg-2 与 pkg-1 同区间内容不同：裁决维持排除
  ledger.adjudicate(
    monitor,
    "pkg-2",
    "retain-quarantine",
    "站点重复导出的旧版本文件，内容摘要与首包不一致且无校正说明，维持排除",
    "2026-08-15T10:00:00Z",
  );

  // 5) 数据经理冻结修订版 1
  const rev1FrozenAt = "2026-08-20T18:00:00Z";
  ledger.freeze(dm, rev1FrozenAt, "ds-r19-rev1");

  // 6) 修订版 2：随访包与冲突重传
  submit("pkg-4", siteB);
  submit("pkg-4b", siteB);
  ledger.adjudicate(
    monitor,
    "pkg-4b",
    "accept-as-replacement",
    "站点核查确认 pkg-4b 为设备补传的完整 48 小时数据（pkg-4 在同步中断时截断），采纳 pkg-4b",
    "2026-09-10T10:00:00Z",
  );

  const rev2FrozenAt = "2026-09-12T18:00:00Z";
  ledger.freeze(dm, rev2FrozenAt, "ds-r19-rev2");

  // 7) 解盲：先演示一次被拒的自我确认，再完成双人确认
  const unblinder = actor("ub-lead");
  let selfConfirmRejected = false;
  try {
    ledger.unblind(unblinder, "ub-lead", {
      subjectCode: "A-014",
      reason: "SAE 医学紧急处理需要获知分组",
    }, "2026-09-13T08:00:00Z");
  } catch {
    selfConfirmRejected = true;
  }
  if (!selfConfirmRejected) throw new Error("自我确认本应被拒绝");

  ledger.unblind(unblinder, "ub-confirm", {
    subjectCode: "A-014",
    reason: "受试者发生 SAE 需紧急救治，按盲态保护 SOP 双人解盲",
  }, "2026-09-13T08:05:00Z");

  return { ledger, fixture, actor, rev1FrozenAt, rev2FrozenAt };
}
