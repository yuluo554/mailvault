mailvault/data/ —— 随包冻结的数据件

| 文件 | 内容 | 许可 | 状态 |
|---|---|---|---|
| `public_suffix_list.dat` | PSL 冻结件（上游原样字节，338010 字节） | MPL 2.0 | ✅ M1 |
| `psl.meta.json` | 版本 / 日期 / 来源 URL / sha256 / 检索时刻 | 本仓库 | ✅ M1 |

当前冻结版本（`psl.meta.json`）：

| 项 | 值 |
|---|---|
| `version` | `2026-10-20_08-40-56_UTC`（取自文件头 `// VERSION:`） |
| `date` | `2026-10-20` |
| `source_url` | `https://publicsuffix.org/list/public_suffix_list.dat` |
| `sha256` | `8228e4bd…b1b70755`（完整值见 meta） |

纪律：

- 运行时**只读**冻结件，禁止联网更新（`mailvault/psl.py` 不 import 任何网络模块，K3 守）。
- 输出必须带 `psl_version` + `psl_date`（题面 §2.5 灰区 3）。快照 schema 把这两个字段列为**必需**，
  缺了 → `InputError`（exit 3），不会静默降级。
- 冻结件被登记 sha256 → `.gitattributes` 标 `-text`（已标）。
- **每次加载都复核 sha256**（`psl.load_psl()`）：冻结件被误改或被 git 归一化换行时当场报错，
  而不是悄悄给出不同的 Organizational Domain。

更新冻结件的步骤（M6 或确需换版时）：

1. 从 `https://publicsuffix.org/list/public_suffix_list.dat` 取原文；
2. 用**未归一化的字节**落盘（不要过任何换行转换工具）；
3. 重算 `sha256` 写进 `psl.meta.json`，`version` / `date` 取自文件头 `// VERSION:`；
4. 跑 `py -3.12 tools/check_no_network.py` 与 `py -3.12 -m pytest tests/test_psl.py`。
