/**
 * 加密工具：内容摘要、设备签名的规范化报文与 Ed25519 验签。
 * 夹具脚本使用同一报文规范为设备私钥签名；平台只持有公钥。
 */
import {
  createHash,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
  type JsonWebKey,
  type KeyObject,
} from "node:crypto";
import type { DeviceKeyJwk, UploadManifest } from "./contracts.js";

/** 计算任意字节内容的 SHA-256（hex）。 */
export function sha256(content: Buffer | string): string {
  return createHash("sha256").update(content).digest("hex");
}

/**
 * 生成签名报文（设备与平台必须逐字节一致）：
 * 按固定顺序排列除 signature 外的全部清单字段，字段间以换行分隔。
 */
export function signingPayload(m: UploadManifest): string {
  return [
    m.packageId,
    m.siteId,
    m.serialNumber,
    m.capturedFrom,
    m.capturedTo,
    m.firmwareVersion,
    m.contentSha256,
    m.correctsPackageId ?? "",
    m.correctionReason ?? "",
    m.visitId ?? "",
  ].join("\n");
}

/** 用设备 Ed25519 私钥签名，返回 base64（夹具/测试用）。Ed25519 为纯签名，algorithm 传 null。 */
export function signManifest(
  manifest: UploadManifest,
  privateKey: KeyObject,
): string {
  return cryptoSign(null, Buffer.from(signingPayload(manifest), "utf8"), privateKey).toString(
    "base64",
  );
}

/** 用设备公钥验证签名。任何异常（坏签名/坏密钥）一律视为验签失败。 */
export function verifyManifestSignature(
  manifest: UploadManifest,
  publicKeyJwk: DeviceKeyJwk,
): boolean {
  try {
    const publicKey = createPublicKey({ format: "jwk", key: publicKeyJwk as JsonWebKey });
    return cryptoVerify(
      null,
      Buffer.from(signingPayload(manifest), "utf8"),
      publicKey,
      Buffer.from(manifest.signature, "base64"),
    );
  } catch {
    return false;
  }
}

/**
 * 确定性接收凭证编号：内容身份 = 设备 + 采集区间 + 固件 + 内容摘要。
 * 与提交编号无关 —— 完全相同的包永远得到同一个凭证。
 */
export function contentIdentityHash(m: {
  serialNumber: string;
  capturedFrom: string;
  capturedTo: string;
  firmwareVersion: string;
  contentSha256: string;
}): string {
  const basis = [
    m.serialNumber,
    m.capturedFrom,
    m.capturedTo,
    m.firmwareVersion,
    m.contentSha256,
  ].join("|");
  return "rcpt-" + sha256(basis).slice(0, 16);
}

export function newId(prefix: string): string {
  return `${prefix}-${createHash("sha256")
    .update(`${prefix}:${process.hrtime.bigint()}:${Math.random()}`)
    .digest("hex")
    .slice(0, 12)}`;
}

/** 由业务字段确定性派生编号：同样的事件在独立重放时得到同一编号。 */
export function deterministicId(prefix: string, parts: string[]): string {
  return `${prefix}-${sha256(parts.join("|")).slice(0, 16)}`;
}
