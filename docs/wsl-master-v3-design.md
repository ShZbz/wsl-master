# WSL Storage Master v3 — 架构设计文档

**版本:** 3.0  
**日期:** 2026-05-09
**最后更新:** 2026-05-09  
**状态:** 已实现 (P1/P2/P3 全部完成)

---

## 1. 目标

实现一款与 WizTree 功能对标的磁盘空间分析 + 文件清理工具，运行于 WSL2 环境：

- **磁盘分析**：递归扫描目录大小分布，以交互式矩形树图 (Canvas Treemap) 展示，支持点击下钻
- **文件清理**：按四类垃圾（系统日志/包缓存/临时文件/应用缓存）分类，支持安全删除
- **VHDX 收缩**：自动探测 WSL .vhdx 位置并生成 PowerShell 收缩脚本

核心约束：
- **扫描永不卡死** — 无论遇到何种特殊文件（FIFO、挂死的 FUSE、损坏 inode）
- **WizTree 级 treemap 体验** — 两级粒度、渐进式细节、流畅缩放

---

## 2. 技术选型

| 组件 | 技术 | 理由 |
|------|------|------|
| 扫描引擎 | Rust (walkdir + rusqlite + regex + serde_yml) | 原生超时控制、通配符正则分类、编译为独立二进制 |
| 后端服务 | Python 3.12 + http.server (stdlib) | 无额外依赖，打包体积小 |
| 数据库 | SQLite (WAL 模式) | 扫描结果持久化，Rust/Python 共享读写 |
| 前端 | 单页 HTML (666行) + Canvas 2D + vanilla JS | 零外部依赖，浏览器即界面 |
| Treemap | Squarified 算法 + 递归嵌套 + HSL 分类着色 | 自适应深度，文件与目录同级渲染 |
| 安全 | X-Auth-Token + 路径穿越防御 + 清理后端校验 | API 鉴权 + 路径白名单 |
| 全局命令 | `wsl-master` 命令行工具 | `python3 -m wsl_master` 或打包后直接调用 |

**去除 Textual TUI** — 终端界面改为 Web 单页应用，消除 PyInstaller 打包 Textual 的模块问题。

---

## 3. 总体架构

```
 ┌─────────────────────────────────────────────────────┐
 │                    浏览器 (localhost)                │
 │  ┌───────────────────────────────────────────────┐  │
 │  │         index.html (单页)                      │  │
 │  │  [📊 扫描分析] [🗑️ 文件清理] [💾 VHDX]       │  │
 │  │  ┌─控制栏──┐ ┌─进度条──┐ ┌─目录列表──┐       │  │
 │  │  │ 扫描按钮 │ │  52%   │ │ DataTable │       │  │
 │  │  └─────────┘ └─────────┘ └───────────┘       │  │
 │  │  ┌──────────────────────────────────────┐     │  │
│  │  │        Canvas Treemap 矩形树图        │     │  │
│  │  │   (Squarified + 递归嵌套 + 点击下钻)   │     │  │
 │  │  └──────────────────────────────────────┘     │  │
 │  └───────────────────────────────────────────────┘  │
 └──────────────────┬──────────────────────────────────┘
                    │ HTTP (JSON)
 ┌──────────────────┴──────────────────────────────────┐
 │                Python 后端进程                       │
 │  ┌───────────┐  ┌───────────┐  ┌───────────┐       │
 │  │  /api/*   │  │  clean/   │  │  vhdx/    │       │
 │  │  HTTP API │  │ executor  │  │  helper   │       │
 │  └─────┬─────┘  └─────┬─────┘  └─────┬─────┘       │
 │        │              │              │              │
 │        └──────────────┼──────────────┘              │
 │               ┌───────┴───────┐                    │
 │               │ cache/store.py│ SQLite 读           │
 │               └───────┬───────┘                    │
 └───────────────────────┼────────────────────────────┘
                         │
 ┌───────────────────────┼────────────────────────────┐
 │                 Rust 扫描器 (wsl-scanner)           │
 │  ┌────────────────────┴──────────────────────┐     │
 │  │  walkdir + 线程级metadata超时 + sync_channel │     │
 │  │  目录节点 + 文件详情 → 批量写入 SQLite      │     │
 │  │  classifier: 前缀 + 正则通配符双路径匹配     │     │
 │  │  超时保护：单文件metadata独立线程5s超时     │     │
 │  │  --max-depth 深度限制支持                   │     │
 │  └───────────────────────────────────────────┘     │
 └────────────────────────────────────────────────────┘
```

---

## 4. 项目目录结构

```
/opt/wsl-master/
├── wsl_master/                       # Python 包
│   ├── __init__.py
│   ├── __main__.py                   # CLI 入口 (scan/list/clean/vhdx/web)
│   ├── config.py                     # 全局配置 (端口/路径/默认值)
│   │
│   ├── rules/                        # 规则引擎
│   │   ├── __init__.py
│   │   └── engine.py                 # YAML 加载 + 路径分类匹配
│   │
│   ├── cache/                        # SQLite 缓存层
│   │   ├── __init__.py
│   │   └── store.py                  # 查询接口 (仅读)
│   │
│   ├── scan/                         # 扫描协调
│   │   ├── __init__.py
│   │   └── controller.py             # 调起 Rust 二进制 + 解析进度
│   │
│   ├── clean/                        # 文件清理
│   │   ├── __init__.py
│   │   └── executor.py               # 删除/回收区执行 (含quarantine逻辑)
│   │
│   ├── vhdx/                         # VHDX 辅助
│   │   ├── __init__.py
│   │   └── helper.py                 # 探测 + PowerShell 脚本生成
│   │
│   ├── web/                          # Web 服务
│   │   ├── __init__.py
│   │   ├── server.py                 # HTTP 服务器 (含所有 API 端点)
│   │   └── static/                   # 前端静态文件
│       │   └── index.html            # 单页应用 (含 CSS/JS, 666行)
│
├── scanner/                          # Rust 扫描器
│   ├── Cargo.toml
│   └── src/
│       ├── main.rs                   # CLI 入口 (clap) + 扫描/聚合双线程 (sync_channel背压)
│       ├── walker.rs                 # 目录遍历 + metadata线程超时 + 进度输出(500ms频率)
│       ├── db.rs                     # SQLite 建表/批量写入/扫描管理
│       └── classifier.rs             # YAML规则加载 + 前缀/正则双路径匹配 (glob_to_regex)
│
├── config/
│   └── default_rules.yaml            # 清理规则 (不变)
│
├── dist/
│   ├── wsl-master                    # PyInstaller Python 入口
│   └── wsl-scanner                   # Rust release 二进制
│
├── wsl-master.spec                   # PyInstaller spec
├── tests/                             # 测试
│   ├── test_store.py                  # DB查询测试 (7 tests)
│   ├── test_integration.py            # HTTP端点测试 (7 tests)
│   ├── test_security.py               # 路径穿越/API校验测试 (10 tests)
│   ├── test_cli.py                    # CLI参数解析测试 (3 tests)
│   ├── test_rules.py                  # 规则引擎测试 (20 tests)
│   ├── test_cleaner.py                # 清理器测试 (17 tests)
│   └── test_vhdx.py                   # VHDX探测/脚本测试 (15 tests)
├── wsl-master.spec                    # PyInstaller spec
└── docs/
    └── wsl-master-v3-design.md       # 本文档
```

---

## 5. CLI 接口

```bash
# Web 模式 (默认)
wsl-master                              # 启动 Web 服务 + 打开浏览器
wsl-master --port 9876                  # 自定义端口 (默认 8878)

# 或使用 python3 -m
python3 -m wsl_master                   # 同上
python3 -m wsl_master --port 9876

# 纯命令行模式
wsl-master scan                         # 调 Rust 全量扫描 → SQLite
wsl-master scan --quick                 # 快速扫描
wsl-master list                         # 从 SQLite 列出 Top 文件
wsl-master clean                        # dry-run 清理
wsl-master clean --no-dry-run           # 实际清理
wsl-master vhdx                         # 生成 VHDX 收缩脚本
```

**全局命令**: `/usr/local/bin/wsl-master` 已软链到 `/opt/wsl-master/bin/wsl-master`，终端任意路径可直接使用。

**端口配置优先级:**
1. `--port` CLI 参数
2. 环境变量 `WSL_MASTER_PORT`
3. 默认: `8878`

**Rust 扫描器独立调用:**
```bash
wsl-scanner scan --paths /var/cache,/tmp --db /tmp/wsl-master/cache/scan_cache.db
wsl-scanner scan --quick                     # 使用 rules.yaml 中的快速路径
wsl-scanner scan --max-depth 3               # 限制扫描深度
```

---

## 6. SQLite Schema

```sql
-- 扫描摘要
CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT UNIQUE NOT NULL,
    total_size INTEGER DEFAULT 0,
    total_files INTEGER DEFAULT 0,
    total_dirs INTEGER DEFAULT 0,
    skipped INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
);

-- 目录聚合节点
CREATE TABLE IF NOT EXISTS nodes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    path TEXT NOT NULL,
    name TEXT NOT NULL,
    parent_path TEXT DEFAULT '',
    depth INTEGER DEFAULT 0,
    is_dir INTEGER DEFAULT 0,
    size_self INTEGER DEFAULT 0,
    size_total INTEGER DEFAULT 0,
    file_count INTEGER DEFAULT 0,
    dir_count INTEGER DEFAULT 0,
    category TEXT DEFAULT '',
    safety TEXT DEFAULT 'Safe',
    mtime REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_path ON nodes(scan_id, path);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_parent ON nodes(scan_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_depth_size ON nodes(scan_id, depth, size_total DESC);
CREATE INDEX IF NOT EXISTS idx_nodes_scan_size ON nodes(scan_id, size_total DESC);

-- 文件详情
CREATE TABLE IF NOT EXISTS files (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    path TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    parent_path TEXT NOT NULL,
    category TEXT DEFAULT '',
    safety TEXT DEFAULT 'Safe',
    mtime REAL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_files_scan_parent ON files(scan_id, parent_path);
CREATE INDEX IF NOT EXISTS idx_files_scan_size ON files(scan_id, size DESC);
CREATE INDEX IF NOT EXISTS idx_files_scan_category ON files(scan_id, category);

-- 分类统计
CREATE TABLE IF NOT EXISTS categories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    name TEXT NOT NULL,
    size INTEGER DEFAULT 0,
    file_count INTEGER DEFAULT 0,
    dir_count INTEGER DEFAULT 0
);
```

---

## 7. API 端点设计

**鉴权:** 服务启动时生成随机 token (`secrets.token_urlsafe(16)`)，注入到 index.html 的 `<meta name="auth-token">`。除 `/api/health` 和 `/` 外所有 API 要求 `X-Auth-Token` 头匹配。token 也可通过 query string `?token=...` 传递。

### 7.1 扫描相关

| 方法 | 路径 | 说明 |
|------|------|------|
| POST | `/api/scan/start` | 启动扫描 `{"mode":"quick|full|custom","paths":["/var"]}` |
| GET  | `/api/scan/status` | 扫描进度 `{"running":true,"scan_id":"scan_...","progress":52,"current":"/var/log/...","total":123456789}` (前端每 500ms 轮询) |
| POST | `/api/scan/stop` | 停止扫描 |
| GET  | `/api/scan/list` | 列出历史扫描记录 |

### 7.2 树图数据

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/tree` | 获取当前层级节点 `?parent=/&top_n=100&depth=0` (扁平) 或 `depth=5` (嵌套)。depth 范围 0-5，默认 2 |
| GET  | `/api/tree/files` | 获取某目录下文件列表 `?parent=/var/log` |
| GET  | `/api/rules/reload` | 热重载规则引擎 |

### 7.3 清理相关

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/clean/preview` | 全量清理计划 `?scan_id=`：`{scan_id, totals, categories[], files[], blocked_examples[], truncated, rules_changed_since_scan}`。**统计口径是全量**（不受展示上限影响），每个文件都带安全闸门判定 `{deletable, code, reason}` |
| POST | `/api/clean/execute` | 执行清理。范围式：`{"scan_id","categories":{"系统日志":"safe\|all\|none"},"include":[],"exclude":[],"allow_caution":false,"quarantine":true}`；显式式（兼容）：`{"paths":[...]}`。两条路径都逐条过 CleanPolicy |

清理的安全性由服务端把关，前端只是"表达选择"：

```
files 表 (扫描结果)
   │  category != ''            ← 候选集（无 LIMIT 截断）
   ▼
CleanPolicy.evaluate()           ← 删除前的唯一权威判定
   ├ 白名单 / wsl-master 自身数据  → 拦截
   ├ 规则复核（按"当前"规则重算分类）→ 已非垃圾则拦截
   ├ Caution 且未显式确认          → 拦截
   ├ 文件不存在 / 已变成目录        → 拦截（绝不 rmtree）
   ├ 被进程打开或 mmap             → 拦截
   ├ 位于虚拟环境 / Git 仓库内      → 拦截
   ├ 无写权限（含 root 拥有的日志）  → 拦截
   └ 临时目录中 10 分钟内仍在写入    → 拦截
   ▼
/var/log/wsl-master/… 日志 + 隔离区（按原始路径镜像 + manifest.jsonl）
```



### 7.4 VHDX

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/api/vhdx/detect` | 探测 WSL 实例 |
| POST | `/api/vhdx/shrink` | 生成收缩脚本并可选执行 |

### 7.5 静态资源

| 方法 | 路径 | 说明 |
|------|------|------|
| GET  | `/` | index.html |
| GET  | `/static/*` | JS/CSS 等静态文件 |

---

## 8. 前端设计 (单页 HTML)

### 8.1 布局

```
┌─ WSL Storage Master ─────────────────────────────────┐
│  [📊 扫描分析] [🗑️ 文件清理] [💾 VHDX收缩]          │
│                                                       │
│  ┌─ 扫描分析 Tab (默认) ──────────────────────────┐  │
│  │ ┌─工具栏─────────────────────────────────────┐ │  │
│  │ │ [🔍 快速扫描] [📂 全盘 /] [⏸] [⏹]        │ │  │
│  │ │ 路径: [/var/cache        ] [扫描此路径]    │ │  │
│  │ └───────────────────────────────────────────┘ │  │
│  │ ┌─进度──────────────────────────────────────┐ │  │
│  │ │ ████████████░░░░░░ 52%  已扫描 12,345 文件│ │  │
│  │ │ 当前: /var/log/syslog                     │ │  │
│  │ └───────────────────────────────────────────┘ │  │
│  │ ┌──────────────┬───────────────────────────┐ │  │
│  │ │  目录列表     │     Canvas Treemap        │ │  │
│  │ │  (左 40%)    │     (右 60%)              │ │  │
│  │ │              │                           │ │  │
│  │ │  点击行→     │  点击矩形→下钻            │ │  │
│  │ │  展开/收起    │  Breadcrumb导航           │ │  │
│  │ │  排序切换     │  扁平/嵌套开关            │ │  │
│  │ │              │                           │ │  │
│  │ └──────────────┴───────────────────────────┘ │  │
│  │ ┌─状态栏───────────────────────────────────┐ │  │
│  │ │ 总计: 12.3 GB | 文件: 458 | 当前: /       │ │  │
│  │ │                             [扁平 ●] 开关 │ │  │
│  │ └───────────────────────────────────────────┘ │  │
│  └──────────────────────────────────────────────┘  │
└────────────────────────────────────────────────────┘
```

### 8.2 Treemap 交互

- **双模式切换**: 状态栏右侧 `扁平/嵌套` 滑动开关。扁平模式 (depth=0) 仅显示当前层级，点击目录通过 API 刷新；嵌套模式 (depth=5) 预取最多 5 层深度数据，前端自适应渲染层次关系
- **squarify 布局 (v3.2.2)**: 每行沿剩余矩形**短边**排布（横向行/纵向列自适应），高瘦容器不再出现极端长条
- **小文件聚合 (v3.2.2)**: 占容器总大小 <0.1% (`MIN_RATIO=0.001`) 的文件在**布局前**合并为单个 `... (N)` 灰色节点参与 squarify——矩形无重叠、面积与数据一致、缩放稳定；单个孤立小文件同样合并
- **自适应嵌套**: 文件夹矩形足够大 (≥120×80px) 时内部加内边距递归展开子节点；否则子节点直接铺满该区域。子节点布局失败时渲染为彩色叶子（消除黑块）
- **小矩形渲染 (v3.2.2)**: <6px 文件块实心填充、无描边（避免近黑描边吞掉小块）；≥6px 用 0.88 透明度填充 + 浅色描边 `#334155`；最低绘制门槛 1px
- **点击下钻**: 扁平模式下点目录 → 使用缓存的 children 直接展开（无需 API）。嵌套模式下点目录 → 始终调用 `/api/tree` 重新获取深度数据，确保嵌套层次完整
- **文件同目录渲染**: `get_tree()` 同时查询 `nodes` + `files` 表，文件与子目录在 treemap 中同级排列
- **不对称边框**: 文件夹上边沿 10px（显示目录名如 `tmp/`），左右下各 4px 窄边。小文件夹跳过边框直接铺满子项
- **颜色**: HSL 分类着色 + 路径 hash 色相偏移(±12°)，同目录同类文件自然区分。未分类文件默认青绿色。最低亮度 38%，深度惩罚 3%/层
- **安全渲染 (v3.2.2)**: 目录/文件列表用 `data-path` 属性 + 事件委托，名称与路径 HTML 转义（文件名可含 `<>&"` 等字符）；键盘导航在输入框聚焦时不触发
- **Breadcrumb**: 顶部 `/> home > user > ... > lib > node_modules > openclaw`，长路径截断为首 2 段 + `...` + 尾 3 段，每段可点击跳回（使用完整 parts 数组重建路径，确保截断段仍正确导航）。面包屑 `pointer-events:none` 透传鼠标事件到 canvas，避免阻挡 tooltip
- **目录列表联动**: 左侧目录列表顶部显示当前完整路径 + `←` 回退按钮。行左侧 `▶/▼` 箭头可展开内联子目录（异步加载），点击行本身导航树图。支持 `大小`/`名称` 排序切换
- **悬停 tooltip**: 显示名称、大小、分类、安全等级、完整路径
- **hover 区分**: 文件夹 hover 白色亮边框 (`#fff`)，文件 hover 浅灰亮边框 (`#94a3b8`)，视觉区分文件/文件夹
- **小块处理**: 宽度<36px或高度<18px时隐藏文字标签，保留色块
- **键盘导航**: `←/Backspace` 回上级，`→` 进入 hover 目录，`↑/↓` 在同级目录间循环跳转，`R` 回到根。嵌套模式下方向键导航同点击逻辑（通过 API 确保数据完整）
- **视口裁剪**: 跳过完全在可见区域外的矩形，减轻 Canvas 重绘压力
- **防抖 resize**: 窗口大小变化 150ms 防抖，避免频繁重绘
- **HTTP (v3.2.2)**: `ThreadingHTTPServer` + HTTP/1.1 keep-alive，所有响应带 Content-Length

### 8.3 文件清理 Tab

- **四个数字卡（v3.2.5）**:
  - *选中垃圾总大小* = 当前勾选会被释放的空间（取消勾选即时联动）
  - *可删除文件总大小* = 扫描出的、删除后无影响且通过安全闸门的全部垃圾（项目效果上限）
  - *扫描发现垃圾总量* = 命中清理规则的全部文件（含 ⚠️ 与已拦截）
  - *⚠️ 需确认 / 🔒 已拦截* = 需显式确认才可删的（模型、浏览器缓存…）与闸门拦下的（占用中、虚拟环境、无权限…）
- **分类动态化**: 分类按钮由服务端返回的分类生成，不再是写死的 4 个（新分类不会"看不见也删不掉"）
- **三态循环**: 每个分类 ☑仅Safe(默认) → ☑全选 → ☐未选；单个文件可单独勾选/取消
- **默认勾选**: 扫描结束后自动加载并全选"删除后无影响"的 Safe 文件（loadCleanPreview 在扫描完成时触发）
- **拦截可视化**: 被闸门拦下的文件仍在列表中（🔒 + 原因），不会静默消失
- **不安全文件保护**: 选中含 ⚠️ 时先弹明细确认（置 allow_caution）→ 再弹总数确认 → 双重确认后才执行
- **列表截断说明**: 每个分类最多展示 300 个（按大小），但**删除范围是全量勾选集**，界面明确标注
- **深链**: 支持 #scan / #clean / #vhdx 直接进入对应标签页

---

## 9. Rust 扫描器详情

### 9.1 超时保护 (防卡死)

每个文件的 `metadata()` 调用被包裹在独立线程中，通过 `mpsc::channel` + `recv_timeout` 实现真正的可中断超时。挂死的 FUSE/损坏 inode 无法阻塞扫描线程:

```
metadata_with_timeout(path, timeout):
  spawn thread:
    result = fs::metadata(path)
    tx.send(result)
  return rx.recv_timeout(timeout).ok().flatten()
  // 超时 → 返回 None → 跳过该 entry, 计入 skipped
```

WalkDir 迭代受 `Instant::elapsed()` 检测保护，长时间无响应的目录被跳过。
```

### 9.2 扫描与聚合模型

```
扫描线程 (单线程串行扫描各根路径):
  WalkDir 遍历 → 每 entry 通过 sync_channel(10_000) 发送到聚合线程
  ├─ metadata_with_timeout: 独立线程 + recv_timeout 防卡死
  ├─ 进度输出: 每 500ms (time-based, 非计数)
  └─ skipped 计数器 (权限错误/超时)
  
聚合线程 (main.rs):
  ├─ 接收 entry, 运行 classifier.classify()
  ├─ 文件: 每 1000 条批量 INSERT 到 SQLite files 表 (流式写入)
  ├─ node_map: 运行时累计 files 统计到父目录
  └─ 扫描结束: bottom-up size 传播 (depth DESC) → 每 500 条批量 INSERT nodes

sync_channel 背压:
  tx_entry: sync_channel(10_000) → 缓冲区满时阻塞扫描线程
  tx_progress: sync_channel(100)  → 进度消息
```
```

### 9.2.1 快速扫描范围（v3.2.5）

快速扫描的根目录不再是写死的目录列表，而是从规则文件派生：

- Python 侧：`rules/engine.py::quick_scan_roots()` 取每条规则的"静态前缀"（第一个通配符之前的部分，如 /var/log/*.log → /var/log），去重嵌套后过滤不存在的目录，再由 ScanController 以多个 --paths 传给扫描器；
- Rust 侧：`wsl-scanner scan --quick` 保留同一份列表，供直接调用二进制时使用。

因此"规则能识别什么"与"快速扫描扫到哪里"只有一个真值来源，新增规则即自动纳入扫描范围。
本机实测：列入 ~/.npm/_cacache、~/.cargo/registry/cache 后，快速扫描多发现 10 GB / 1.1 万个文件。

### 9.3 数据写入策略

**全量扫描 (当前实现):**
扫描阶段一次性遍历所有路径，同时写入 nodes (目录聚合) 和 files (文件详情)。
文件通过批量 INSERT (1000条/批次) 实时写入 SQLite，避免内存堆积。
目录节点扫描结束后经过 bottom-up size 传播后批量写入。

**L2 按需扫描 (计划中 — P3 #24):**
首次扫描仅写入 nodes 表 (目录级聚合)。通过 `/api/tree/files?parent=/var/log` 
按需对特定目录启动轻量扫描，结果写入 files 表后返回并缓存。

### 9.4 进度输出格式 (JSON Lines, stdout)

```json
{"type":"progress","scanned":15234,"total_bytes":9876543210,"current":"/var/log/syslog","dirs":456}
{"type":"progress","scanned":15734,"total_bytes":9998765432,"current":"/var/log/auth.log","dirs":460}
{"type":"timeout","path":"/mnt/dead_mount","reason":"readdir timeout after 10s"}
{"type":"error","path":"/root/.ssh/id_rsa","reason":"Permission denied"}
{"type":"done","scan_id":"scan_20260508_120000","total_files":50000,"total_dirs":1200,"total_size":12345678901,"skipped":23,"timeouts":5}
```

---

## 10. 打包方案

```
PyInstaller 打包:
  Python 模块 → 单文件 wsl-master (~15MB 含 stdlib)
  
Rust release 打包:
  cargo build --release → 单文件 wsl-scanner (~3MB 静态链接)

最终 dist/:
  ├── wsl-master         # Python 入口 (PyInstaller)
  ├── wsl-scanner        # Rust 扫描引擎
  └── config/            # default_rules.yaml (PyInstaller 自动包含)
```

Python 入口启动时检测 `wsl-scanner` 是否在默认路径，若不存在则使用 Python os.walk 降级扫描（保留兼容性）。

---

## 11. 数据流总结

```
用户操作 → 前端 (index.html)
              │
              ▼ POST /api/scan/start
          Python web/server.py
              │
              ▼ subprocess.Popen
          Rust wsl-scanner scan --paths /...
              │
              ├─ 流式 stdout JSON lines (进度)
              │     → Python 解析 → 前端轮询 /api/scan/status → 更新进度条
              │
              └─ 写入 SQLite nodes/files/categories 表
                    │
                    ▼
              扫描完成 → 前端显示 DataTable
                    │
              GET /api/tree?parent=/&top_n=100
                    │
              Python cache/store.py 查 SQLite
                    │
                    ▼ JSON
              前端 Canvas Treemap 渲染
                    │
              用户点击矩形 → GET /api/tree?parent=/var/cache
                    │
              ...
```

---

## 12. 与旧版对比

| 维度 | 旧版 (v2) | 新版 (v3) |
|------|-----------|-----------|
| 前端 | Textual TUI + 独立浏览器窗口 | **单一 Web 页面 (666行 HTML)** |
| 扫描引擎 | Python subprocess(find) | **Rust 二进制 (超时保护)** |
| 卡死风险 | 阻塞式 Popen.stdout 无超时 | **线程级metadata超时 5s + 扫描停滞30s检测** |
| 并发 | 单线程 | **扫描+聚合双线程 sync_channel 背压** |
| 数据粒度 | 全量内存 node_map | **批量流式写入 + 目录聚合** |
| Treemap | 独立 HTML + 独立 Web Server | **自适应嵌套 (3%面积阈值), HSL着色, 文件同树渲染, 扁平/嵌套开关** |
| 目录列表 | 无 | **完整路径显示, ←回退, ▶内联展开, 大小/名称排序** |
| 面包屑 | 无 | **长路径截断 (首2···尾3), 完整路径重建** |
| hover | 无区分 | **文件夹亮白/文件暗灰 视觉区分** |
| 打包 | PyInstaller (Textual 模块问题) | **PyInstaller + Rust 二进制** |
| 安全 | 无 | **X-Auth-Token 鉴权 + 路径穿越防御 + 清理后端校验** |
| 文件清理 | TUI 内操作 | **Web 内操作, 三态选择, 不安全文件双重确认** |
| 全局命令 | 需手动 python3 -m | **wsl-master 全局可用** |

---

## 13. 实施阶段

| 阶段 | 内容 | 输出 | 状态 |
|------|------|------|------|
| 1 | Rust 扫描核心 (walker + db + classifier) | `wsl-scanner` 二进制, 可独立运行 | ✅ |
| 2 | Python cache/store.py (SQLite 读 + 嵌套树查询) | 查询接口 + `get_tree()` | ✅ |
| 3 | Python web/ (HTTP 服务 + API 路由) | 完整后端 + `/api/tree?depth=` | ✅ |
| 4 | 前端 index.html (自适应嵌套Treemap + HSL着色 + 扁平/嵌套开关 + 目录展开收起/排序 + 键盘导航 + 清理三态) | 完整前端 (666行) | ✅ |
| 5 | clean/ + vhdx/ 适配新架构 | 清理 + VHDX 功能 | ✅ |
| 6 | PyInstaller 打包 | 可分发的 dist/ | 待完成 |
| 7 | 测试 + 文档 | 完整交付 | 85 测试全部通过 |

---

## 14. 风险与缓解

| 风险 | 缓解 |
|------|------|
| Rust 编译环境未安装 | 降级模式：Python walkdir + timeout 扫描 (性能略低但可用) |
| SQLite 并发写冲突 | WAL 模式 + Rust 端单写者 |
| 浏览器访问不到 WSL 服务 | 绑定 127.0.0.1，打印 URL，自动尝试 cmd.exe start |
| 端口被占用 | 随机端口检测 + --port 可配 |
| 大量文件导致前端 OOM | top_n + merge_threshold 限制 + L2 按需加载 |

---

## 15. 变更记录

### v3.2.5 (2026-09-11)

清理逻辑重构轮：目标是"**不要漏删、也不要错删**"，并把"扫描 → 清理"两端对齐。

**漏删（修 3 处）**
- /api/clean/preview 旧实现是 ORDER BY size DESC LIMIT 500：本机实测 10 万个垃圾文件里只有 500 个能被看到和删除。现在统计**全量**、只截断展示；执行按"分类范围 + 排除项"在全量候选集上重算，与预览同一套判定。
- 清理页分类写死 4 个：不在列表里的分类既不显示也删不掉。现在分类由服务端返回，有几个显示几个。
- 快速扫描目录在 Python / Rust 里各写死一份（且缺 ~/.npm/_cacache、~/.cargo/registry/cache），新增规则时扫描范围不跟随 → "规则认识、扫描扫不到"。现在由 rules/engine.py::quick_scan_roots() 从规则文件派生，Rust --quick 列表同步；本机实测因此多发现 **10 GB / 1.1 万文件** 的 npm 缓存。

**错删（新增 clean/policy.py 删除安全闸门，删除前逐条复核）**
- 白名单此前只写在 YAML 里、无人执行 → 现在 Rust/Python 两侧都生效，删除端再次拦截
- wsl-master 自身数据（数据库 / 隔离区 / 日志 / 规则 / 二进制）永不删除
- 规则复核：按**当前**规则重算分类，规则改过后旧扫描结果不能授权删除
- 进程占用（/proc/*/fd + /proc/*/maps 快照）→ 拦截（删了也不释放空间，还会影响运行中的程序）
- 虚拟环境 / Git 仓库标记（pyvenv.cfg、.git）→ 拦截。本机实测拦下 ~/.cache/phxsc-venv、~/.cache/dsh-sdk-venv 共 3.3 万文件，以及 uv 缓存里一个 65 MB 的 uv 托管虚拟环境
- 文件类型复核：扫描时是文件、删除时已变目录 → 拒绝（旧 _delete_path 会 shutil.rmtree 整棵子树）
- 权限复核：无写权限（如 root 拥有的 /var/log/*.gz）不再计入"可删除"
- 临时目录 10 分钟内仍在写入的文件不默认勾选
- Caution 需 allow_caution 显式置位（前端二次确认后才发），服务端不再"客户端说删就删"

**隔离区（发现并修复一个静默数据丢失缺陷）**
- 旧实现把文件搬到 quarantine/<basename> 扁平目录，同名文件互相覆盖（shutil.move 遇已存在目标静默 rename），"可还原"名不副实
- 现在按 quarantine/<run_id>/<原始绝对路径> 镜像存放，并在 run 目录实时追加 manifest.jsonl；同名多份时 restore_from_quarantine() **拒绝猜测**并报错

**规则调整（保守扩张，用户确认的方案 A）**
- 升级为 Safe：~/.cache/uv、~/.cache/pypoetry、~/.cache/yarn、~/.npm/_logs、~/.cache/node-gyp、~/.cache/node、~/.cache/typescript、~/.cache/pyinstaller、~/.cache/fontconfig、~/.cache/mesa_shader_cache、/var/log/*.[0-9]
- 保持 Caution（删除有代价）：huggingface 模型、ms-playwright/puppeteer/electron 二进制、Chrome/Chromium 用户目录、/var/log/journal
- 兜底规则改为通配符规则（/var/log/**、~/.cache/**）：前缀规则优先于通配符规则，否则兜底会抢在 /var/log/*.log 之前把轮转日志误判成 Caution
- Python 前缀规则改为按长度降序（与 Rust 一致），消除两套引擎对嵌套前缀规则的判定分歧

**性能**
- 白名单/保护目录判定改前缀 trie、权限判定改 mode 位比较（省 10 万次 access）、父目录可写性按目录缓存：全量 9.5 万文件的审计从 ~7s 降到 ~3s；计划缓存 15s（删除/换扫描即失效）

**测试**: 116 → 151（新增 tests/test_clean_policy.py 35 项：闸门各分支、全量统计、范围式执行、快速扫描派生、隔离区同名不覆盖/歧义拒绝）

### v3.2.4 (2026-09-01)

CI 修复轮：`test_fallback_skips_excluded_roots` 在 GitHub Actions 上失败（本地全绿）。

- **根因 1（测试卫生）**: 该测试把 `os.path.exists` 全局替换为恒真，连带骗过了 `RulesEngine.from_default()` 的规则文件存在性守卫，导致线程内 `FileNotFoundError` → done 事件永不触发 → 30s 超时。修复：fake 只对 `/mnt/x` 说谎，其余委托真实 `os.path.exists`。
- **根因 2（生产隐患，本轮一并拔除）**: `rules/engine.py::from_default()` 硬编码 `/opt/wsl-master/config/default_rules.yaml` 开发机路径；另一候选 `wsl_master/../config`（包内）指向不存在的 `wsl_master/config/`——即除本开发机外任何环境 fallback 均静默加载空规则。修复：候选改为源码仓根相对（`../../config/`）+ `os.getcwd()` 相对；两候选在开发机与源码仓内均指向同一真实文件，已验证。
- 版本 3.2.3 → 3.2.4。测试无新增（回归由 CI 本轮验证）。

### v3.2.3 (2026-09-01)

详见 `docs/superpowers/specs/2026-09-01-v3.2.3-bugfix-perf.md`。要点：

- **备用扫描器修复**: fallback 结果此前因未 commit 整体回滚丢失；同秒重扫 IntegrityError；排除根(/mnt 等)不再误走 9p；支持 `stop()` 中止
- **非 root 启动**: 日志/清理目录按 `/var/log/wsl-master → ~/.local/state/wsl-master → /tmp` 回退，不再 import 期 PermissionError 崩溃（支持 `WSL_MASTER_LOG_DIR`/`WSL_MASTER_QUARANTINE` 环境变量）
- **规则引擎统一**: Python/Rust 统一为组件级 glob（`*` 不跨 `/`），`**` 跨分隔符——`**/selfcheck/**` 类排除模式在 Rust 端此前从未生效
- **扫描根路径**: `--paths` 不再逗号拼接（含逗号路径不损坏）；重复/嵌套根去重防双计数；显式扫描排除前缀有明确提示
- **WebUI**: 假超时根治（目录密集段/写库段不再误报且不再永久停轮询）；停止后如实显示"已停止"；进度回调异常隔离
- **性能**: walker 每条目省一次 PathBuf 拷贝+String 分配；错误进度 500ms 限速；聚合器索引自底向上传播替代全量行拷贝；fallback 单 stat 判定
- **Rust 扫描器 0.1.2**; 测试 92 → 108
