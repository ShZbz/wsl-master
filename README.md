# wsl-master

WSL2 磁盘空间分析与清理工具：交互式树图可视化磁盘占用、四类垃圾文件安全清理、VHDX 自动收缩。提供 Web UI 与 CLI 两种使用方式，扫描引擎可选 Rust 加速。

## 功能特性

- **交互式树图磁盘分析**：`squarify` 经典短边排布算法，嵌套/扁平双模式，缩放与面包屑导航，超大目录级别合并——小文件 (<0.1%) 聚合为独立 `Other` 块，比例诚实、无重叠无黑块；`<6px` 小矩形实心填充无描边，深色主题下不再发黑
- **四类垃圾清理**：包管理器缓存 / 系统日志 / 临时文件 / 应用缓存，YAML 规则驱动（路径前缀 + 通配模式 + 排除规则），两级安全等级（Safe/Caution），默认 dry-run 预览、确认后执行，删除走回收区可恢复
- **VHDX 收缩助手**：自动探测 WSL 发行版的 `ext4.vhdx` 位置（含 Windows Docker Desktop 场景），一键生成 PowerShell 收缩脚本，免去手动找盘符
- **扫描缓存**：SQLite (WAL) 缓存扫描结果，增量扫描只更新变化目录；复合索引 + 分批批量写入，全盘 30 万文件级扫描秒级查询
- **高性能扫描**：Python 并发扫描器（默认）或可选 Rust 引擎（`scanner/`，walkdir + rusqlite，超时安全、流式写入）——29.9 万文件全盘扫描热缓存 ~32s
- **Web UI**：单文件零依赖前端（内嵌 JS/CSS），`ThreadingHTTPServer` + HTTP/1.1 keep-alive；树图平移缩放在独立 Worker 中渲染不卡界面
- **安全的 HTTP 层**：文件名全量转义 + `data-path` 事件委托（杜绝 HTML 注入），输入框不劫持键盘导航，非法请求与路径穿越校验

## 安装

要求：Python 3.10+，Linux (WSL2 优先)。

```bash
# 源码直接运行(无需安装)
git clone https://github.com/ShZbz/wsl-master.git
cd wsl-master
pip install pyyaml

# 或安装为命令
pip install .
# 依赖 Rust 引擎(可选,显著提升大目录扫描速度)
cd scanner && cargo build --release && cp target/release/wsl-scanner ../bin/
```

## 快速开始

```bash
# 启动 Web UI(默认端口 8878,浏览器打开 http://localhost:8878)
wsl-master web --port 8878

# 命令行
wsl-master scan ~          # 扫描主目录
wsl-master scan --quick    # 只扫缓存/日志类目录
wsl-master list --db <db>  # 列出 Top 占用
wsl-master clean           # dry-run 预览可清理项
wsl-master vhdx            # 生成 VHDX 收缩脚本
```

> `--db` / `--rules` 也可通过环境变量 `WSL_MASTER_DB`、`WSL_MASTER_RULES` 指定；默认库位于 `/tmp/wsl-master/cache/scan_cache.db`（重启清空）。

## 清理规则

规则文件 `config/default_rules.yaml`，按顺序匹配、首条命中生效。每条规则含：

| 字段 | 说明 |
|---|---|
| `path` | 匹配路径，支持前缀精确与 `*`/`?`/`[]` 通配 |
| `category` | 分类（包管理器缓存/系统日志/临时文件/应用缓存） |
| `safety` | `Safe`（推荐清理）/ `Caution`（谨慎） |
| `max_depth` | 目录递归深度上限 |
| `exclude_patterns` | 排除模式（`**/selfcheck/**` 等），命中即跳过 |

未匹配任何规则的文件视为 `Safe` 且不进入清理列表。

## 可选配置

| 环境变量 | 默认值 | 说明 |
|---|---|---|
| `WSL_MASTER_DB` | `/tmp/wsl-master/cache/scan_cache.db` | 扫描结果 SQLite 路径 |
| `WSL_MASTER_RULES` | `/opt/wsl-master/config/default_rules.yaml` | 清理规则文件路径（源码运行请显式指定或安装到系统路径） |

## 已知注意事项

- WSL 9p 文件系统上 `rglob`/`glob` 极慢，扫描器使用 `iterdir` 逐层遍历
- `wsl.exe` 输出为 UTF-16 LE，已做专门解码
- PyInstaller 打包（`wsl-master.spec`）用于生成独立可执行文件，Textual TUI 模式已移除，Web UI 为唯一可视化界面

## 设计文档与变更记录

- [设计文档](docs/wsl-master-v3-design.md)：树图算法、数据模型与 HTTP API 设计说明
- [CHANGELOG](CHANGELOG.md)：版本演进记录

## License

MIT © 2026 ShZbz