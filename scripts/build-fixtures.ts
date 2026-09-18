/**
 * 生成 fixtures/site-uploads.json：
 * 确定性派生设备 Ed25519 测试密钥并对每份清单签名，可重复生成、结果稳定。
 * 生产环境中私钥驻留设备；夹具内含私钥仅用于在本仓库内复现验签。
 *
 * 运行：tsc 编译后 node dist/scripts/build-fixtures.js（npm run build:fixtures）
 */
import { existsSync, mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import {
  createHash,
  createPrivateKey,
  createPublicKey,
  type JsonWebKey,
} from "node:crypto";
import { sha256, signManifest } from "../src/crypto.js";
import type {
  DeviceKeyJwk,
  StudyConfig,
  SubjectRecord,
  UploadManifest,
  Visit,
  Actor,
  DeviceCustodyEvent,
} from "../src/contracts.js";

function projectRoot(): string {
  let dir = dirname(fileURLToPath(import.meta.url));
  while (!existsSync(resolve(dir, "package.json"))) {
    const parent = dirname(dir);
    if (parent === dir) throw new Error("找不到 package.json");
    dir = parent;
  }
  return dir;
}

const root = projectRoot();
const outPath = resolve(root, "fixtures/site-uploads.json");

/** 由序列号确定性派生 Ed25519 种子（仅供测试，绝不用于真实设备）。 */
function deterministicKeyPair(serial: string): { publicKey: DeviceKeyJwk; privateKeyJwk: DeviceKeyJwk } {
  const seed = createHash("sha256").update(`test-seed:${serial}`).digest();
  const privateKey = createPrivateKey({
    format: "jwk",
    key: {
      kty: "OKP",
      crv: "Ed25519",
      x: "",
      d: seed.toString("base64url"),
    } as unknown as JsonWebKey,
  });
  const privJwk = privateKey.export({ format: "jwk" }) as DeviceKeyJwk;
  const pubJwk = createPublicKey(privateKey).export({ format: "jwk" }) as DeviceKeyJwk;
  return { publicKey: { kty: "OKP", crv: "Ed25519", x: pubJwk.x }, privateKeyJwk: privJwk };
}

const study: StudyConfig = {
  studyId: "study-r19",
  title: "R19 腕戴睡眠与活动量研究",
  firmwareAllowlist: ["firmware-2.1.0", "firmware-3.0.0"],
  siteIds: ["site-a", "site-b"],
};

const subjects: SubjectRecord[] = [
  { subjectCode: "A-014", homeSiteId: "site-a" },
  { subjectCode: "A-027", homeSiteId: "site-a" },
];

const users: Actor[] = [
  { userId: "dm-zhang", role: "data-manager" },
  { userId: "mon-li", role: "medical-monitor" },
  { userId: "sitea-wang", role: "site-user", siteId: "site-a" },
  { userId: "siteb-chen", role: "site-user", siteId: "site-b" },
  { userId: "ub-lead", role: "unblinded-user" },
  { userId: "ub-confirm", role: "unblinded-user" },
];

const visits: Visit[] = [
  {
    visitId: "v-a14-enroll",
    subjectCode: "A-014",
    siteId: "site-a",
    plannedFrom: "2026-07-31T00:00:00Z",
    plannedTo: "2026-08-04T00:00:00Z",
    occurredAt: "2026-08-01T08:00:00Z",
  },
  {
    visitId: "v-a14-switch",
    subjectCode: "A-014",
    siteId: "site-b",
    plannedFrom: "2026-08-09T00:00:00Z",
    plannedTo: "2026-08-12T00:00:00Z",
    occurredAt: "2026-08-10T10:00:00Z",
  },
  {
    visitId: "v-a14-followup",
    subjectCode: "A-014",
    siteId: "site-b",
    plannedFrom: "2026-09-04T00:00:00Z",
    plannedTo: "2026-09-08T00:00:00Z",
    occurredAt: "2026-09-06T09:00:00Z",
  },
  {
    visitId: "v-a27-enroll",
    subjectCode: "A-027",
    siteId: "site-a",
    plannedFrom: "2026-07-14T00:00:00Z",
    plannedTo: "2026-07-17T00:00:00Z",
    occurredAt: "2026-07-15T09:00:00Z",
  },
  {
    visitId: "v-a27-reissue",
    subjectCode: "A-027",
    siteId: "site-a",
    plannedFrom: "2026-07-20T00:00:00Z",
    plannedTo: "2026-07-23T00:00:00Z",
    occurredAt: "2026-07-21T11:00:00Z",
  },
];

const serials = ["watch-100", "watch-101", "watch-102", "watch-205"];
const keyStore = new Map(serials.map((s) => [s, deterministicKeyPair(s)]));
const devices = serials.map((s, i) => ({
  serialNumber: s,
  label: `研究用腕戴 ${s}（固件世代 ${i < 3 ? "2.x" : "3.x"}）`,
  publicKey: keyStore.get(s)!.publicKey,
  keyPairJwk: keyStore.get(s)!.privateKeyJwk,
}));

/** 基线事件（保留原 fixture 的跨站换机），并补充遗失/补发链。 */
const events: Array<Omit<DeviceCustodyEvent, "eventId" | "studyId">> = [
  {
    action: "issue",
    siteId: "site-a",
    subjectCode: "A-014",
    serialNumber: "watch-100",
    occurredAt: "2026-08-01T08:00:00Z",
    visitId: "v-a14-enroll",
  },
  {
    action: "replace",
    siteId: "site-b",
    subjectCode: "A-014",
    serialNumber: "watch-205",
    replacesSerialNumber: "watch-100",
    occurredAt: "2026-08-10T10:00:00Z",
    visitId: "v-a14-switch",
  },
  {
    action: "issue",
    siteId: "site-a",
    subjectCode: "A-027",
    serialNumber: "watch-101",
    occurredAt: "2026-07-15T09:00:00Z",
    visitId: "v-a27-enroll",
  },
  {
    action: "lost",
    siteId: "site-a",
    subjectCode: "A-027",
    serialNumber: "watch-101",
    occurredAt: "2026-07-20T18:00:00Z",
  },
  {
    action: "replace",
    siteId: "site-a",
    subjectCode: "A-027",
    serialNumber: "watch-102",
    replacesSerialNumber: "watch-101",
    occurredAt: "2026-07-21T11:00:00Z",
    visitId: "v-a27-reissue",
  },
];

interface FixturePackageInput {
  packageId: string;
  siteId: string;
  serialNumber: string;
  visitId?: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  /** 原夹具中的说明性摘要（aaa111/bbb222）保持不变；其余由 payload 实算 */
  contentSha256: string;
  payload?: string;
  correctsPackageId?: string;
  correctionReason?: string;
  /** 置坏签名（签名失效拒收演示） */
  tamperSignature?: boolean;
  /** 保留显式声明的摘要，不按 payload 实算（摘要不符拒收演示） */
  mismatchDigest?: boolean;
}

const pkgInputs: FixturePackageInput[] = [
  // —— 基线保留：watch-100 首包、完全重复包、同区间内容冲突包 ——
  {
    packageId: "pkg-1",
    siteId: "site-a",
    serialNumber: "watch-100",
    visitId: "v-a14-enroll",
    capturedFrom: "2026-08-01T09:00:00Z",
    capturedTo: "2026-08-03T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "aaa111",
  },
  {
    packageId: "pkg-1-retry",
    siteId: "site-a",
    serialNumber: "watch-100",
    visitId: "v-a14-enroll",
    capturedFrom: "2026-08-01T09:00:00Z",
    capturedTo: "2026-08-03T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "aaa111",
  },
  {
    packageId: "pkg-2",
    siteId: "site-a",
    serialNumber: "watch-100",
    visitId: "v-a14-enroll",
    capturedFrom: "2026-08-01T09:00:00Z",
    capturedTo: "2026-08-03T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "bbb222",
  },
  // —— 三类硬性拒收 ——
  {
    packageId: "pkg-1-badfw",
    siteId: "site-a",
    serialNumber: "watch-100",
    capturedFrom: "2026-08-01T09:00:00Z",
    capturedTo: "2026-08-02T09:00:00Z",
    firmwareVersion: "firmware-9.9.9",
    contentSha256: "0f1f2e3d",
    payload: "watch-100|2026-08-02|unsupported-firmware-demo",
  },
  {
    packageId: "pkg-1-badsig",
    siteId: "site-a",
    serialNumber: "watch-100",
    capturedFrom: "2026-08-02T09:00:00Z",
    capturedTo: "2026-08-03T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "7e7e7e7e",
    tamperSignature: true,
  },
  {
    packageId: "pkg-1-baddigest",
    siteId: "site-a",
    serialNumber: "watch-100",
    capturedFrom: "2026-08-03T09:00:00Z",
    capturedTo: "2026-08-04T09:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "0000000000000000000000000000000000000000000000000000000000000000",
    payload: "watch-100|2026-08-04|actual-payload-differs-from-claimed-digest",
    mismatchDigest: true,
  },
  // —— pkg-1 的校正包：时钟漂移修正后区间略收紧，原包保留不覆盖 ——
  {
    packageId: "pkg-1-corr",
    siteId: "site-a",
    serialNumber: "watch-100",
    visitId: "v-a14-enroll",
    capturedFrom: "2026-08-01T09:05:00Z",
    capturedTo: "2026-08-03T08:55:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "ccc333",
    correctsPackageId: "pkg-1",
    correctionReason: "设备时钟漂移 5 分钟，按站点日志重新导出校正数据，原包保留以备稽查",
  },
  // —— 跨站换机后 watch-205 的首包（新固件 3.0.0）——
  {
    packageId: "pkg-3",
    siteId: "site-b",
    serialNumber: "watch-205",
    visitId: "v-a14-switch",
    capturedFrom: "2026-08-11T08:00:00Z",
    capturedTo: "2026-08-13T08:00:00Z",
    firmwareVersion: "firmware-3.0.0",
    contentSha256: "ddd444",
  },
  // —— A-027：遗失前 watch-101 的包 ——
  {
    packageId: "pkg-5",
    siteId: "site-a",
    serialNumber: "watch-101",
    visitId: "v-a27-enroll",
    capturedFrom: "2026-07-16T08:00:00Z",
    capturedTo: "2026-07-18T08:00:00Z",
    firmwareVersion: "firmware-2.1.0",
    contentSha256: "eee555",
  },
  // —— 补发 watch-102 首包 ——
  {
    packageId: "pkg-6",
    siteId: "site-a",
    serialNumber: "watch-102",
    visitId: "v-a27-reissue",
    capturedFrom: "2026-07-22T08:00:00Z",
    capturedTo: "2026-07-24T08:00:00Z",
    firmwareVersion: "firmware-3.0.0",
    contentSha256: "fff666",
  },
  // —— 冻结后才到达的随访包（进入修订版 2）——
  {
    packageId: "pkg-4",
    siteId: "site-b",
    serialNumber: "watch-205",
    visitId: "v-a14-followup",
    capturedFrom: "2026-09-05T08:00:00Z",
    capturedTo: "2026-09-07T08:00:00Z",
    firmwareVersion: "firmware-3.0.0",
    contentSha256: "999aaa",
  },
  // —— 与 pkg-4 同区间、内容不同的站点重传（修订版 2 内冲突，裁决后采纳）——
  {
    packageId: "pkg-4b",
    siteId: "site-b",
    serialNumber: "watch-205",
    visitId: "v-a14-followup",
    capturedFrom: "2026-09-05T08:00:00Z",
    capturedTo: "2026-09-07T08:00:00Z",
    firmwareVersion: "firmware-3.0.0",
    contentSha256: "999bbb",
  },
];

const packages: Array<UploadManifest & { payload?: string }> = pkgInputs.map((p) => {
  const key = keyStore.get(p.serialNumber)!;
  const claimedDigest = p.payload && !p.mismatchDigest ? sha256(p.payload) : p.contentSha256;
  const unsigned: UploadManifest = {
    packageId: p.packageId,
    siteId: p.siteId,
    serialNumber: p.serialNumber,
    capturedFrom: p.capturedFrom,
    capturedTo: p.capturedTo,
    firmwareVersion: p.firmwareVersion,
    contentSha256: claimedDigest,
    signature: "",
    ...(p.visitId !== undefined ? { visitId: p.visitId } : {}),
    ...(p.correctsPackageId !== undefined ? { correctsPackageId: p.correctsPackageId } : {}),
    ...(p.correctionReason !== undefined ? { correctionReason: p.correctionReason } : {}),
  };
  const privateKey = createPrivateKey({ format: "jwk", key: key.privateKeyJwk as JsonWebKey });
  let signature = signManifest(unsigned, privateKey);
  if (p.tamperSignature) {
    signature = "ZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZg==";
  }
  return {
    ...unsigned,
    signature,
    ...(p.payload !== undefined ? { payload: p.payload } : {}),
  };
});

const fixture = {
  studyId: study.studyId,
  generatedBy: "scripts/build-fixtures.ts",
  note: "脱敏演示夹具；设备私钥为确定性测试密钥，随机分组为密封演示信封",
  study,
  users,
  subjects,
  visits,
  devices,
  randomization: { "A-014": "arm-B", "A-027": "arm-A" },
  events,
  packages,
};

mkdirSync(dirname(outPath), { recursive: true });
writeFileSync(outPath, `${JSON.stringify(fixture, null, 2)}\n`);
console.log(`fixture written: ${outPath} (${packages.length} packages, ${events.length} custody events)`);
