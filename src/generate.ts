/**
 * 仅（重新）生成 fixtures/site-uploads.json。
 * 私钥由序列号确定性派生、只用于在内存中计算签名，绝不写入文件。
 */
import { writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { buildFixture } from "./scenario.js";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const out = resolve(root, "fixtures/site-uploads.json");
writeFileSync(out, `${JSON.stringify(buildFixture(), null, 2)}\n`, "utf8");
console.log(`已生成 ${out}`);
