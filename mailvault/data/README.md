mailvault/data/ —— 随包冻结的数据件

| 文件 | 内容 | 许可 |
|---|---|---|
| `public_suffix_list.dat` | PSL 冻结件（M1 入仓） | MPL 2.0 |
| `psl.meta.json` | 版本 / 日期 / 来源 URL / sha256（M1 入仓） | 本仓库 |

纪律：

- 运行时**只读**冻结件，禁止联网更新。
- 输出必须带 `psl_version` + `psl_date`（题面 §2.5 灰区 3）。
- 冻结件被登记 sha256 → `.gitattributes` 标 `-text`（已标）。
