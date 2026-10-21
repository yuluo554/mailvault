# examples —— 已归档的样例产物

本目录放**用真 CLI 跑真 fixture 得到的样例账本**，两个用途：

1. `tools/check_forbidden_terms.py` 的**扫描面**（M0 期这里为空，那条门只能报 `SKIP`；
   有了真产物才从 `SKIP` 转成真判定）。
2. Release 附件里的"示例产物"——让读者不装环境也能看到一份真实账本长什么样。

**全部由 `tools/gen_examples.py` 生成**（跑的是 `mailvault.cli.main`，不是手搓 JSON）；
`--check` 可逐字节复核幂等性与退出码：

```bash
py -3.12 tools/gen_examples.py            # 重新生成
py -3.12 tools/gen_examples.py --check    # 只比对，不写盘
```

## 用例一览

| 目录 | 命令 | 展示什么 | 退出码 |
|---|---|---|---|
| `reconcile-r2-gateway-body/` | `audit` | 报文的 `Authentication-Results` 与本工具重算**矛盾**（网关改正文）→ `reconcile.cross_check` 汇总为 `undecidable` + 每条矛盾 ≥2 条可能解释与各自要查什么 | `2` |
| `dmarc-b41/` | `audit` | 干净通过：RFC 9989 B.4.1 的 DMARC DNS Tree Walk 复现例 | `0` |
| `whatif-spf-tighten/` | `whatif` | 反事实差分：SPF `?all` → `-all` 让退出码 0 翻成 1；产物带 `whatif.diff.ops` | `1` |
| `diff-p-reject/` | `diff` | 两份账本的结构差分（附基线与候选两份真产物）；`p=none` → `p=reject` | `0` |

每份产物都带 `--strict-evidence`：归档样例必须是**禁词合规**的形态，也是该开关的示形。

## 与 `fixtures/` 的分工

- `fixtures/` 是**输入 + 期望值**（`snap.json` / `message.eml` / `query.json` / `expected.json`），
  供测试断言用。
- `examples/` 是**输出快照**（`verdict.json` / `verdict.md` / `diff.json` / `diff.md`），
  供人读与门扫用。

`examples/` 里的域一律是保留域（`.example.com` / `.example.net` / `.example.org`）、IP 一律是
文档 IP 段（`192.0.2.0/24`、`198.51.100.0/24`、`203.0.113.0/24`），且账本内**不含绝对路径**
（K9，由渲染层断言）。

## 为什么中间态不在这里

`diff-p-reject/` 的生成会给 `audit` / `whatif` 各写一份中间产物——那两份的 Markdown 写进
临时目录、不入仓；只有作为差分**两侧真产物**的 `baseline.json` / `candidate.json` 落在这里，
让差分可被读者独立复算。