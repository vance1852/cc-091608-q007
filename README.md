# 腕戴数据监管链平台（wearable-trial-custody）

面向临床试验锁库场景的 Node.js + TypeScript 平台，解决三类现实问题：

1. **设备来路可还原**——两个研究中心使用不同固件、受试者跨站换机后序列号缺少交接记录；
2. **数据来路可证明**——站点重复提交、同区间内容冲突、事后校正，现有汇总无法说明分析数据来自哪台设备；
3. **盲态与职责分离**——普通站点只见本站代号，医学监查员可处理数据缺口但看不到随机分组，解盲必须授权且双人确认。

所有结论都可由独立稽查员仅凭导出清单、设备公钥与审计记录**独立复算**（摘要、Ed25519 验签、交接链）。

## 运行

```bash
npm install
npm run generate   # 由确定性场景生成 fixtures/site-uploads.json（含设备公钥与真实签名，不含任何私钥）
npm start          # 回放站点材料并在 reports/ 下产出两个冻结批次的稳定导出清单
npm test           # 类型检查 + 生成 fixture + 20 项断言
npm run check      # 仅 tsc --noEmit
```

需要 Node.js 22，无运行时第三方依赖（仅用内置 `node:crypto` 与 `node:test`）。

## 领域模型（src/contracts.ts）

| 概念 | 说明 |
| --- | --- |
| `StudyConfig` | 研究号、许可固件白名单、密封的随机分组表（`randomization` 与业务数据隔离） |
| `User` / `Role` / `Permission` | 站点用户、医学监查员、数据经理、稽查员；`UNBLIND` 为显式授权，不随角色授予 |
| `DeviceRecord` | 序列号 ↔ Ed25519 公钥（`keyId`），平台只存公钥 |
| `DeviceCustodyEvent` | `issue` / `return` / `lost` / `replace`，换机必须填 `replacesSerialNumber` |
| `UploadManifest` | 包号、站点、序列号、采集区间、固件、SHA-256 内容摘要、设备签名、可选校正目标与原因 |
| `Adjudication` / `CorrectionLink` | 冲突裁决（纳入/排除+原因）、校正替代关系（原包保留+原因） |
| `FrozenDataset` | 冻结批次快照：修订版号、每包状态、排除依据、校正链、前驱批次 |
| `DatasetExport` | 稳定清单：逐包纳入/排除/替代依据 + 受试者设备交接链 + 拒收留痕 + 清单摘要 |

## 上传校验管线（src/platform.ts `submitPackage`）

按序执行，任一不过即拒收并留痕（`PackageRejectionCode`）：

1. **站点范围**——站点用户不得为别站提交（`WRONG_SITE`）；
2. **内容摘要**——载荷字节 SHA-256 必须等于声明值（`DIGEST_MISMATCH`）；
3. **设备登记**——序列号必须已登记（`UNKNOWN_DEVICE`）；
4. **设备签名**——以设备登记公钥验 Ed25519 签名（`BAD_SIGNATURE`）；
5. **固件许可**——固件必须在研究白名单内（`FIRMWARE_NOT_LICENSED`）；
6. **采集区间**——起止合法（`BAD_INTERVAL`）；
7. **占有窗口**——区间必须完全落在设备由该受试者占有的窗口内，且站点在交接链上（`OUTSIDE_CUSTODY`/`WRONG_SITE`）；
8. **校正目标**——校正包必须指向存在的原包并附原因（`UNKNOWN_CORRECTION_TARGET`）。

随后是内容仲裁：

- **完全相同**（同设备 + 同摘要 + 同区间）→ 返回**原接收凭证**，不新增数据行；重传时设备须对新包号重新签名（签名覆盖包号，凭证号由 `设备:摘要` 决定，故保持不变）；
- **同设备同区间、内容不同** → `quarantined` 隔离，生成缺口工单，等待医学监查员裁决；裁决可纳入（原占用者转 `superseded`）或排除，全部附原因、不删除任何包；
- **校正** → 原包永久保留并转 `superseded`，追加带原因的 `CorrectionLink`，校正包作为新包正常接收。

## 冻结与修订版

数据经理冻结批次时对当前修订版（从 1 起）做快照；冻结后新上传自动进入下一修订版。导出按包号所属修订版过滤，因此**历史批次内容与 `exportSha256` 永不改变**（摘要只对清单内容做规范化 JSON 哈希，不含生成时刻）。

每个条目的 `basis` 稳定说明其去向：`ACCEPTED`、`ACCEPTED_CORRECTION`、`SUPERSEDED_BY_CORRECTION`、`ADJUDICATED_INCLUDED`、`ADJUDICATED_EXCLUDED`、`QUARANTINED_PENDING`、`EXCLUDED_BY_CONFLICT_DECISION`。

## 角色与盲态

- **站点用户**：绑定唯一站点；`listPackages` 只返回本站包，越站登记/上传直接拒绝，拒绝动作也写审计；
- **医学监查员**：可查看并裁决隔离包、处理设备遗失/冲突缺口，但任何接口都不返回随机表，也不具备 `UNBLIND`；
- **数据经理**：冻结批次、查看全部数据与审计，默认同样不能解盲；
- **稽查员**：只读，可导出全部批次与审计流，不能写任何数据；
- **解盲**（`requestUnblind`）：请求人与确认人必须是两名不同的、各自显式具备 `UNBLIND` 授权的人员，并填写医学原因；成功时分组结果只存在于本次返回值。审计记录“谁、何时、为何、对谁解盲、由谁确认”，**绝不记录分组结果**，导出清单同样不含 `control/intervention` 字样。

## 示例故事（fixtures/site-uploads.json）

由 `src/scenario.ts` 确定性生成（设备密钥由序列号派生，仅在内存中签名）：

- **A-014**：site-a 发放 `watch-100`（fw-2.4.1）→ 首包、站点重复提交（返回同一凭证）、同区间异内容包隔离、四类篡改/非法拒包 → site-b 登记跨站换机为 `watch-205`（交接记录 `replacesSerialNumber=watch-100`，fw-3.1.0）；换机前的数据包以 `OUTSIDE_CUSTODY` 拒收，无关站点 site-c 冒充提交以 `WRONG_SITE` 拒收；换机后首包随后被**带原因的校正包**替代（时间戳漂移对齐）；
- **B-027**：`watch-310` 随访包与重复提交 → 设备遗失（自动开缺口）→ 补发 `watch-311` 续采；
- 医学监查员裁决冲突包**排除**并附依据、关闭遗失缺口；
- 第一次冻结 `ds-2026-03-15`（修订版 1）；锁库后到达的随访包进入修订版 2，再冻结 `ds-2026-03-20`；
- 第二次冻结之后研究结束回收 `watch-311`（`return`）——该流转进入活动工作区，但两个已冻结批次的交接链快照与摘要均不改变；
- 四个解盲用例：无授权、同人兼任、确认人无授权（均拒绝）、双人授权成功。

`reports/export-ds-2026-03-15.json` 中可独立核对：4 包纳入、2 包排除/替代（各附依据）、1 条校正链、8 条拒收留痕，以及 A-014 完整换机链与 B-027 的遗失/补发链。

## 代码结构

```
src/
  contracts.ts   领域类型（研究/用户/设备/事件/上传/裁决/冻结/导出/审计/解盲）
  crypto.ts      SHA-256、确定性设备密钥派生、规范化报文、Ed25519 签名与验签
  store.ts       只追加的内存存储（监管窗口、内容/区间索引、缺口、拒收、审计）
  platform.ts    授权 RBAC、监管链登记、上传校验管线、裁决、冻结、稳定导出、双人解盲
  scenario.ts    固定临床故事 + 设备端签名模拟（fixture 生成器）
  generate.ts    写出 fixtures/site-uploads.json
  replay.ts      按步骤回放并逐步核对期望 + 跨切面导出不变量
  main.ts        读取磁盘 fixture 回放，打印核查报告并写出 reports/
  custody.test.ts 20 项 node:test 断言
```
