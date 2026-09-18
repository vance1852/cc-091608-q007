/**
 * 端到端演示：跑通夹具场景并打印监管链、各包命运、缺口处理、
 * 冻结批次稳定清单、站点受限视图与解盲记录。
 *
 * 运行：node --experimental-strip-types src/demo.ts
 */
import { runScenario } from "./scenario.js";
import type { DatasetExport, ListingEntry } from "./contracts.js";

function line(title: string): void {
  console.log(`\n${"=".repeat(72)}\n${title}\n${"=".repeat(72)}`);
}

function printEntry(e: ListingEntry): void {
  const aliasText = e.aliases.length ? `，重复提交别名: ${e.aliases.join(", ")}` : "";
  console.log(
    `  [${e.disposition.padEnd(10)}] rev${e.introducedRevision}${
      e.changedAtRevision ? `→rev${e.changedAtRevision}` : ""
    } ${e.submissionPackageId}  受试者=${e.subjectCode} 设备=${e.serialNumber}` +
      ` 站点=${e.siteId}${e.visitId ? ` 访视=${e.visitId}` : ""}`,
  );
  console.log(
    `             区间=${e.capturedFrom} ~ ${e.capturedTo} 固件=${e.firmwareVersion} sha256=${e.contentSha256}${aliasText}`,
  );
  for (const b of e.basis) console.log(`             · ${b}`);
  if (e.rejectCodes) console.log(`             · 拒收代码: ${e.rejectCodes.join(", ")}`);
  if (e.correctsSubmissionId) console.log(`             · 校正替代: ${e.correctsSubmissionId}（${e.correctionReason}）`);
  if (e.conflictWithSubmissionId) console.log(`             · 冲突对象: ${e.conflictWithSubmissionId}，裁决=${e.adjudication ?? "维持隔离"}`);
  if (e.correctedBySubmissionId) console.log(`             · 已被校正包替代: ${e.correctedBySubmissionId}`);
}

function printExport(title: string, exp: DatasetExport): void {
  line(title);
  console.log(
    `研究=${exp.studyId} 修订版=${exp.revision}${exp.datasetId ? ` 批次=${exp.datasetId}` : ""}` +
      `${exp.frozenAt ? ` 冻结于=${exp.frozenAt}` : "（开放）"} 生成于=${exp.generatedAt}`,
  );
  for (const d of ["included", "excluded", "superseded", "duplicate"] as const) {
    const rows = exp.entries.filter((e) => e.disposition === d);
    console.log(`\n-- ${d} (${rows.length}) --`);
    rows.forEach(printEntry);
  }
  console.log("\n-- 采集缺口 --");
  for (const g of exp.gaps) {
    console.log(
      `  ${g.gapId} ${g.subjectCode} ${g.from} ~ ${g.to} [${g.status}]` +
        `${g.resolution ? ` ${g.resolution} by ${g.documentedBy}: ${g.note}` : ""}`,
    );
  }
  console.log("\n-- 每次访视的来路核验 --");
  for (const v of exp.visits) {
    console.log(
      `  ${v.visitId} 受试者=${v.subjectCode} 站点=${v.siteId} 访视于 ${v.occurredAt}` +
        `（窗口 ${v.plannedFrom} ~ ${v.plannedTo}），关联提交 ${v.submissions.length} 份：`,
    );
    for (const s of v.submissions) {
      console.log(
        `      - ${s.submissionPackageId.padEnd(14)} 凭证=${s.receiptId || "（拒收，无凭证）"} 处置=${s.disposition}`,
      );
    }
  }
}

const { ledger, actor } = runScenario();

line("设备监管链（按受试者/时间）");
for (const e of ledger.readCustody(actor("dm-zhang"))) {
  console.log(
    `  ${e.occurredAt}  ${e.subjectCode}  ${e.action.padEnd(7)} ${e.serialNumber}` +
      `${e.replacesSerialNumber ? ` (替换 ${e.replacesSerialNumber})` : ""} @${e.siteId}${e.visitId ? ` 访视=${e.visitId}` : ""} [${e.eventId}]`,
  );
}

printExport("冻结批次清单：修订版 1（锁库快照，不可变）", ledger.exportListing(actor("dm-zhang"), 1));
printExport("冻结批次清单：修订版 2（含随访冲突裁决）", ledger.exportListing(actor("dm-zhang"), 2));

line("普通站点 site-a 用户视图（只可见本站代号/数据，绝无随机分组）");
const siteView = ledger.exportListing(actor("sitea-wang"), 2);
console.log(`可见受试者代号: ${ledger.listSubjects(actor("sitea-wang")).join(", ")}`);
console.log(`可见条目 ${siteView.entries.length} 条（site-b 的 pkg-3/pkg-4* 不可见）：`);
siteView.entries.forEach((e) =>
  console.log(`  [${e.disposition.padEnd(10)}] ${e.submissionPackageId} 受试者=${e.subjectCode}`),
);

line("医学监查员视图：可处理缺口/裁决，但同样看不到随机分组");
console.log(`监查员可见受试者代号: ${ledger.listSubjects(actor("mon-li")).join(", ")}`);
console.log(`导出对象中没有任何 arm/randomization 字段（类型层面亦不存在）。`);

line("解盲记录（仅记录经双人确认的成功解盲与拒绝轨迹）");
for (const u of ledger.unblindRecords) {
  console.log(
    `  ${u.at} ${u.subjectCode} -> ${u.arm}；发起人=${u.actorId} 确认人=${u.confirmerId}；原因=${u.reason}`,
  );
}
const audit = ledger.listAudit(actor("dm-zhang"));
const denied = audit.filter((a) => !a.granted);
console.log(`\n被拒绝的敏感操作共 ${denied.length} 条（含站点越权与解盲自我确认）：`);
for (const a of denied) console.log(`  ${a.at} ${a.actorId}/${a.action} 目标=${a.target} — ${a.detail}`);

line("稽查轨迹统计（只增，共 " + audit.length + " 条）");
const counts = new Map<string, number>();
for (const a of audit) counts.set(a.action, (counts.get(a.action) ?? 0) + 1);
for (const [k, v] of [...counts.entries()].sort()) console.log(`  ${k}: ${v}`);
