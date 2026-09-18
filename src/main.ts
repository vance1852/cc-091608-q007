/**
 * 命令行入口：
 *  1. 由场景生成器重写 fixtures/site-uploads.json（含公钥与真实设备签名）；
 *  2. 回放全部步骤并打印监管链核查报告；
 *  3. 导出两个冻结批次的稳定清单到 reports/。
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { readFileSync } from "node:fs";
import { replay, verifyExportInvariants } from "./replay.js";
import type { SiteUploadsFixture } from "./scenario.js";

const here = dirname(fileURLToPath(import.meta.url));
const root = resolve(here, "..");

// 从磁盘读取站点上传材料（由 `npm run generate` 生成），像稽查员一样独立回放。
const fixturePath = resolve(root, "fixtures/site-uploads.json");
const fixture = JSON.parse(readFileSync(fixturePath, "utf8")) as SiteUploadsFixture;

const { platform, passed } = replay(fixture);
const { ds1, ds2 } = verifyExportInvariants(platform, fixture);

const reportsDir = resolve(root, "reports");
mkdirSync(reportsDir, { recursive: true });
for (const ds of [ds1, ds2]) {
  writeFileSync(
    resolve(reportsDir, `export-${ds.datasetId}.json`),
    `${JSON.stringify(ds, null, 2)}\n`,
    "utf8",
  );
}

const line = (s = ""): void => console.log(s);
line("================ 腕戴数据监管链：回放核查报告 ================");
line(`研究 ${fixture.study.studyId}｜许可固件 ${fixture.study.allowedFirmware.join("、")}`);
line(`场景步骤 ${fixture.steps.length} 项，逐步期望核对通过 ${passed.length} 项`);
line();

line("-- 受试者设备交接链（ds-2026-03-15 冻结时刻快照；稽查员可据此独立还原设备来路）--");
for (const chain of ds1.subjectChains) {
  line(`受试者 ${chain.subjectCode}`);
  for (const l of chain.links) {
    const replace = l.replacesSerialNumber ? `，交接替代 ${l.replacesSerialNumber}` : "";
    line(`  ${l.occurredAt}  ${l.action.padEnd(7)} ${l.serialNumber} @${l.siteId}${replace}（事件 ${l.eventId}）`);
  }
}
line();

const printDataset = (title: string, ds: typeof ds1): void => {
  line(`-- ${title}（修订版 ${ds.revision}，${ds.frozen ? "已冻结" : "工作区"}）--`);
  line(`纳入 ${ds.includedPackages.length} 包 / 排除或替代 ${ds.excludedPackages.length} 包 / 校正关系 ${ds.corrections.length} 条`);
  for (const e of ds.entries) {
    const mark = e.included ? "纳入" : "排除";
    line(`  [${mark}] ${e.packageId.padEnd(26)} ${e.subjectCode} ${e.serialNumber} ${e.firmwareVersion}`);
    line(`         ${e.capturedFrom} ~ ${e.capturedTo}`);
    line(`         依据 ${e.basis}：${e.basisDetail}`);
    line(`         摘要 ${e.contentSha256.slice(0, 16)}… 凭证 ${e.receiptId}`);
  }
  line();
};
printDataset("冻结批次 ds-2026-03-15", ds1);
printDataset("冻结批次 ds-2026-03-20", ds2);

line("-- 被拒收的提交（留痕，不进入分析数据）--");
for (const r of ds1.rejectedSubmissions) {
  line(`  ${r.packageId.padEnd(28)} ${r.code.padEnd(28)} @${r.siteId} 设备 ${r.serialNumber}`);
}
line();

line("-- 导出稳定性 --");
line(`ds-2026-03-15 清单摘要 ${ds1.exportSha256}`);
line(`ds-2026-03-20 清单摘要 ${ds2.exportSha256}`);
line("（重新生成相同冻结批次的导出，摘要必须逐次一致）");
line();

line("-- 审计记录条数与解盲 --");
line(`审计事件 ${platform.listAudit("u-auditor").length} 条（含每一次访问与全部越权拒绝）`);
line("随机分组仅在双人授权解盲成功时返回给请求人，审计与导出中均无分组字样。");
line();
line(`已读取站点材料 ${fixturePath}（由 npm run generate 生成）`);
line(`导出清单已写入 ${reportsDir}/export-ds-2026-03-15.json 与 export-ds-2026-03-20.json`);
