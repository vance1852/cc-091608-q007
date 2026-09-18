/**
 * 加密原语：内容摘要、设备密钥与数据包签名。
 *
 * 使用 Node 内置 crypto（Ed25519 + SHA-256），无外部依赖。
 * 平台只持有设备公钥；私钥只在“设备端”（fixture 场景）出现。
 */
import {
  createHash,
  generateKeyPairSync,
  createPrivateKey,
  createPublicKey,
  sign,
  verify,
} from "node:crypto";
import type { KeyObject } from "node:crypto";
import type { UploadManifest } from "./contracts.js";

export function sha256Hex(data: string | Buffer): string {
  return createHash("sha256").update(data).digest("hex");
}

export interface DeviceKeyPair {
  keyId: string;
  publicKeyPem: string;
  privateKeyPem: string;
}

/** 随机生成 Ed25519 密钥对（真实设备出厂流程的模拟）。 */
export function generateDeviceKey(serialNumber: string): DeviceKeyPair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    keyId: `key-${serialNumber}`,
    publicKeyPem: publicKey.export({ type: "spki", format: "pem" }).toString("ascii"),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString("ascii"),
  };
}

/** PKCS#8 DER 中 Ed25519 私钥的固定前缀（AlgorithmIdentifier 1.3.101.112 + 32 字节种子）。 */
const ED25519_PKCS8_PREFIX = Buffer.from(
  "302e020100300506032b657004220420",
  "hex",
);

/**
 * 由“设备种子”确定性派生 Ed25519 私钥。
 * fixture 用它复现设备端签名（密钥不入库、不入 fixture），
 * 公钥写在设备登记记录里，平台独立验签。
 */
export function privateKeyFromSeed(seed: Buffer): KeyObject {
  if (seed.length !== 32) throw new Error("Ed25519 种子必须为 32 字节");
  return createPrivateKey({
    key: Buffer.concat([ED25519_PKCS8_PREFIX, seed]),
    format: "der",
    type: "pkcs8",
  });
}

export function publicKeyPemFromPrivate(privateKey: KeyObject): string {
  return createPublicKey(privateKey)
    .export({ type: "spki", format: "pem" })
    .toString("ascii");
}

/** 模拟设备出厂：由序列号派生稳定密钥，返回 keyId、公钥与私钥对象。 */
export function deriveDeviceIdentity(serialNumber: string): {
  keyId: string;
  publicKeyPem: string;
  privateKey: KeyObject;
} {
  const seed = createHash("sha256").update(`device-seed:${serialNumber}`).digest();
  const privateKey = privateKeyFromSeed(seed);
  return {
    keyId: `key-${serialNumber}`,
    publicKeyPem: publicKeyPemFromPrivate(privateKey),
    privateKey,
  };
}

/**
 * 设备端构造的待签名规范化报文。
 * 字段顺序固定、以换行分隔，使任何一方都能独立重建并验签。
 */
export function packageSigningPayload(m: {
  packageId: string;
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
  correctsPackageId?: string;
}): string {
  return [
    "wearable-data-package/v1",
    m.packageId,
    m.serialNumber,
    m.capturedFrom,
    m.capturedTo,
    m.firmwareVersion,
    m.contentSha256,
    m.correctsPackageId ?? "",
  ].join("\n");
}

/** 设备端签名（Ed25519 算法内部完成哈希，故算法参数为 null）。 */
export function signPackage(
  m: Parameters<typeof packageSigningPayload>[0],
  privateKey: KeyObject,
): string {
  return sign(null, Buffer.from(packageSigningPayload(m), "utf8"), privateKey).toString("hex");
}

/** 平台验签：以设备登记记录中的公钥独立核验。 */
export function verifyPackageSignature(
  m: Pick<
    UploadManifest,
    | "packageId"
    | "serialNumber"
    | "capturedFrom"
    | "capturedTo"
    | "firmwareVersion"
    | "contentSha256"
    | "signature"
    | "correctsPackageId"
  >,
  publicKeyPem: string,
): boolean {
  try {
    const sig = Buffer.from(m.signature, "hex");
    if (sig.length !== 64) return false;
    return verify(
      null,
      Buffer.from(packageSigningPayload(m), "utf8"),
      createPublicKey(publicKeyPem),
      sig,
    );
  } catch {
    return false;
  }
}
