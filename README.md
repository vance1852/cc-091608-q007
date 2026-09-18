# 腕戴数据监管链（wearable-trial-custody）

锁库前证明“每份分析数据来自哪台设备、经谁交接、为何纳入/排除”的 Node.js + TypeScript 平台。
受试者全程以**研究代号**表示；随机分组（盲态）密封保存，任何常规接口都不返回，
只有经授权的**双人解盲**流程可以一次性读取并留痕。

## 解决的问题

- 两站点设备固件不同 → 上传时校验**固件许可白名单**；
- 受试者换机、序列号无交接记录 → 设备发放/回收/遗失/**换机**构成只增监管链，换机必须形成连续持有链；
- 文件被站点重复提交 → 内容身份（设备+采集区间+固件+SHA-256）相同的包返回**同一接收凭证**；
- 同一声明区间、内容不同 → **隔离**等待医学监查员裁决；
- 校正文件 → 不覆盖原包，只追加“以原因关联”的**替代关系**；
- 锁库 → 数据经理**冻结修订版**，此后新上传进入下一修订版，冻结快照不可变。

## 模块

| 文件 | 职责 |
| --- | --- |
| `src/contracts.ts` | 研究、受试者代号、设备密钥、访视、发放事件、上传清单、凭证、裁决、缺口、冻结批次、导出与审计契约 |
| `src/crypto.ts` | SHA-256 内容摘要、规范化签名报文、Ed25519 设备签名/验签、确定性凭证与事件编号 |
| `src/ledger.ts` | 监管链状态机：上传四类命运、裁决、校正替代、缺口、冻结修订版、RBAC、双人解盲、审计轨迹 |
| `src/scenario.ts` | 用夹具驱动完整时间线（修订版 1 冻结 → 修订版 2 冲突裁决 → 双人解盲） |
| `src/demo.ts` | 端到端演示，打印换机链、每包依据、访视核验、站点受限视图与解盲/审计记录 |
| `scripts/build-fixtures.ts` | 为每台设备确定性派生 Ed25519 测试密钥并对清单签名，生成 `fixtures/site-uploads.json` |
| `test/ledger.test.ts` | 28 个 node:test 契约测试 |

## 上传的四类命运

1. **接收 accepted**：设备在册、签名有效、采集区间内设备在受试者持有链中、固件已许可、访视一致；
2. **重复 duplicate**：内容身份与既有凭证完全一致 → 返回**原接收凭证**，仅登记提交别名；
3. **隔离 quarantined**：同设备、完全相同采集区间但摘要不同 → 排除等待裁决（`retain-quarantine` 或 `accept-as-replacement`）；
4. **拒收 rejected**：硬性校验失败，返回机器可读代码（`unknown-device` / `device-not-in-custody` /
   `site-mismatch` / `signature-invalid` / `content-digest-mismatch` / `firmware-not-licensed` /
   `bad-interval` / `unknown-visit` / 校正相关代码等）。

## 角色（RBAC）

- `site-user`：只能登记/上传/查看**本站**数据与本站相关受试者代号，看不到随机分组；
- `medical-monitor`：可处理采集缺口、裁决冲突包，但导出中**不存在**随机分组字段；
- `data-manager`：登记监管链、冻结批次、导出；
- `unblinded-user`：只能参与解盲，不得浏览任何监管数据。解盲需两名不同的授权人员（发起人 + 确认人）。

## 导出

`exportListing(actor, revision?)` 稳定列出每个提交的 **纳入 / 排除 / 替代 / 重复** 处置与
只增不改的依据（basis），并附：

- `visits`：每次访视 → 关联提交、接收凭证与处置（“每次访问都可验证”）；
- `custody`：完整设备换机链；
- `gaps`：换机/补发缺口区间及医学监查员的书面处理；
- 给定 `revision` 返回冻结时刻不可变快照；不传则导出当前开放修订版。

事件号、缺口号、接收凭证均由业务字段**确定性派生**，独立重放逐字节一致（除 `generatedAt`）。

## 常用命令

```bash
npm install
npm run check          # tsc --noEmit 类型检查
npm run build:fixtures # 重新生成带真实 Ed25519 签名的夹具（结果稳定）
npm test               # 编译并运行 28 个契约测试
npm run demo           # 端到端演示
```
