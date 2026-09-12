# natpierce-ghidra-cloud

私有仓：把本地搞不定的反编译搬到 GitHub Actions 上跑。

本地已解决的（`F:\worker\tools\ghidra-proj`）：`natpierce.dll` 313 个业务函数全量反编译。
本仓负责的：

1. `natpierce.exe` / `network.dll` 的首次深度分析（本地 REA 被版本 pin + x86 卡死，从没跑通过）。
2. `natpierce.dll` 剩下 ~7700 个函数（Go runtime/标准库/第三方）的全量 sweep。
3. REA 在 **Ghidra 12.1.2 精确版本** 下的重跑（本地只有 12.1.3，REA 拒认）。

## 用法

Actions → `ghidra-cloud-decompile` → Run workflow：

| input | 说明 |
|---|---|
| `ghidra_version` | 默认 `12.1.2`（脚本按前缀自动解析 release asset） |
| `target` | `all` / `dll` / `exe` / `network` |
| `scope` | `app`（业务包 313 同款过滤） / `full`（除 `FUN_` 未命名外的全部） |
| `batch_size` | 每批函数数，默认 60 |

产物在 Artifacts：`cloud-<target>-<scope>/`（`funcs.csv`、`decomp-cloud-N.txt`、`headless-*.log`、`RUN_SUMMARY.md`），保留 30 天。

## 目录

```
scripts/            # Ghidra headless 脚本（DecompileBatch/PrintMem/DumpFuncs/XrefsTo/DumpAsm）
tools/              # resolve_ghidra.py（解析 release asset）/ split_batches.py（筛函数+分批）
targets/            # 待分析二进制（私有仓，仅供互操作研究）
.github/workflows/  # ghidra-cloud.yml
```

注意：`targets/` 内为第三方闭源二进制，仅供本地互操作分析，勿外传、勿公开本仓。
