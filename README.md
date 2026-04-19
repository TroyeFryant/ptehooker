# ptehook

**零字节修改、零 .so 注入、零 VMA 痕迹的 Android ARM64 内核态 hook 框架。**

ptehook 通过 ARM64 PTE `UXN` bit 陷阱 + VMA-less ghost 内存实现函数级 hook，在 `/proc/pid/maps`、`ArtMethod` 结构体、代码段字节等各维度均无可见修改。面向强反作弊环境设计。

---

## 功能特性

- **7.2 UXN Trap** — 在 PTE 层翻转 UXN bit 触发 Instruction Abort，内核 fault handler 重定向 PC 到 ghost shellcode，ArtMethod 和代码段字节完全不动
- **VMA-less Ghost 内存** — shellcode 页通过 `apply_to_page_range` 直接安装 PTE，不经 VMA 系统，`/proc/maps` 完全看不见
- **DBI 重编译引擎** — 整页代码搬到 ghost 页并修复 PC-relative 指令（B/BL/ADR/ADRP/LDR literal），非目标方法通过 Pass 3 fallthrough 正常执行
- **设备端自治 hook（ptehookd）** — 守护进程自动监控目标 app 启动，无需 PC 连接即可自动装 hook，支持进程重启和设备重启后自动恢复
- **Profile 编译器（ptehook-compile）** — PC 侧一次性预计算 DEX 解析 + shellcode 模板，产出 JSON profile 供设备端 daemon 使用
- **APatch 模块** — 开箱即用的 APatch 模块结构，开机自动加载 KPM + 启动 daemon

## 技术架构

```
┌────────────────────────────────────────────────────────────┐
│  PC 侧（一次性）                                            │
│                                                            │
│  ptehook-compile.py  → profile.json                        │
│  (DEX 解析 + shellcode 模板生成)                            │
└──────────────────────────┬─────────────────────────────────┘
                           │ push to device
                           ↓
┌────────────────────────────────────────────────────────────┐
│  Android 设备侧（永久运行）                                  │
│                                                            │
│  service.sh → kpatch load KPM → ptehookd &                 │
│                                                            │
│  ptehookd 监控循环:                                         │
│    检测进程启动 → pte_scan 扫 ArtMethod → ptehook_ctl 装 hook │
│    监控进程存活 → 进程死亡 → 等待重启 → 重新安装               │
│                                                            │
│  KPM (内核 EL1):                                            │
│    UXN trap → fault handler → PC redirect → ghost shellcode │
└────────────────────────────────────────────────────────────┘
```

## 项目结构

```
ptehook/
├── test_kmod/                          # KPM 内核模块
│   ├── ptehook_planc_v2.c              # 主文件: ctl 命令 / fault handler
│   ├── ghost_mm.{c,h}                  # VMA-less ghost 页分配
│   ├── dbi_kern.{c,h}                  # ARM64 DBI 重编译引擎
│   └── Makefile.planc                  # 构建 → ptehook_planc_v2.kpm
│
├── pte_hookctl/                        # Python host + 设备侧工具
│   ├── ptehook/                        # 高层 Python API
│   │   ├── __init__.py
│   │   ├── session.py                  # Session 类
│   │   └── actions.py                  # ReturnConst / LogArgs / CallBackup
│   ├── ptehook_compile.py              # ★ Profile 编译器 (PC 侧)
│   ├── ptehookd.c                      # ★ 设备端自治 hook 守护进程
│   ├── shellcode_patch.h               # ★ 运行时 shellcode patch (C)
│   ├── Makefile.ptehookd               # ★ daemon 构建脚本
│   ├── device_scanner.c                # ArtMethod 扫描器 (pte_scan)
│   ├── kpm_client.py                   # KPM ctl 命令封装
│   ├── shellcode.py                    # ARM64 shellcode 生成器
│   ├── dex_parser.py                   # DEX 文件解析
│   ├── art_offsets.py                  # ART 偏移表
│   ├── sym_resolver.py                 # .so 符号解析
│   └── examples/                       # 使用示例
│
├── apatch_module/                      # ★ APatch 模块
│   ├── module.prop
│   ├── service.sh                      # 开机启动脚本
│   └── customize.sh                    # 安装脚本
│
├── docs/
│   ├── ARCHITECTURE_AND_USAGE.md       # 技术架构文档
│   ├── DESIGN_ONDEVICE_AUTO_HOOK.md    # 自治 hook 设计方案
│   └── ARTICLE_ONDEVICE_AUTO_HOOK.md   # 公众号文章版本
│
└── readme_pro.md                       # 本文件
```

（★ 标记为自治 hook 新增文件）

## 前置要求

- Android ARM64 设备，已 root
- **APatch** v0.12.2+（提供 KernelPatch 运行环境）
- 设备 Kernel 4.9 - 6.x
- **PC 侧**：Python 3.8+、Android NDK r21+
- 支持 Android API 30-35（Android 11 - 15）

## 快速开始

### 方式一：交互式 hook（传统模式，需要 PC 连接）

```python
import ptehook

sess = ptehook.attach("com.target.app")
sess.java_hook(
    "Lcom/target/License;", "isVIP", "()Z",
    replace=1,
    wait_jit=True,
)
sess.run()
sess.close()
```

### 方式二：设备端自治 hook（无需 PC 持续连接）

#### 第一步：构建设备侧二进制

```bash
cd pte_hookctl
make -f Makefile.ptehookd NDK_DIR=/path/to/ndk
# 产出: ptehookd, pte_scan
```

#### 第二步：构建 KPM

```bash
cd test_kmod
make -f Makefile.planc
# 产出: ptehook_planc_v2.kpm
```

#### 第三步：编译 hook profile

```bash
export ADB_SERIAL=<your_device>

python3 pte_hookctl/ptehook_compile.py \
    --package com.target.app \
    --hook "java:Lcom/target/License;.isVIP:()Z:return_const=1:wait_jit" \
    --hook "java:Lcom/target/Auth;.checkRoot:(I)Z:return_const=0:wait_jit" \
    -o /tmp/com.target.app.json
```

#### 第四步：部署到设备

```bash
# 推送二进制和配置
adb push pte_hookctl/ptehookd /data/adb/ptehook/
adb push pte_hookctl/pte_scan /data/adb/ptehook/
adb push ptehook_ctl /data/adb/ptehook/         # 预编译的 ctl binary
adb push test_kmod/ptehook_planc_v2.kpm /data/adb/ptehook/
adb push /tmp/com.target.app.json /data/adb/ptehook/profiles/

# 设置权限
adb shell "su -c 'chmod 755 /data/adb/ptehook/ptehookd \
    /data/adb/ptehook/pte_scan /data/adb/ptehook/ptehook_ctl'"

# 配置 superkey
adb shell "su -c 'echo YOUR_APATCH_SUPERKEY > /data/adb/ptehook/superkey \
    && chmod 600 /data/adb/ptehook/superkey'"
```

#### 第五步：加载 KPM + 启动 daemon

```bash
SK=$(adb shell "su -c 'cat /data/adb/ptehook/superkey'")
adb shell "su -c '/data/adb/kpatch $SK kpm load /data/adb/ptehook/ptehook_planc_v2.kpm'"
adb shell "su -c '/data/adb/ptehook/ptehookd \
    --superkey-file=/data/adb/ptehook/superkey \
    --profiles-dir=/data/adb/ptehook/profiles \
    --bin-dir=/data/adb/ptehook'"
```

此后 **ptehookd 会自动监控目标 app**：启动时自动装 hook，被杀后自动重装。

#### 可选：安装为 APatch 模块（开机自动启动）

```bash
cd pte_hookctl
make -f Makefile.ptehookd module
# 产出: /tmp/ptehook-module.zip

# 通过 APatch 管理器安装该 zip，重启即生效
```

## Hook Spec 格式

编译 profile 时通过 `--hook` 参数指定 hook 规则：

```
java:<class_descriptor>.<method_name>:<signature>:<action>=<value>[:<deploy_mode>]
```

| 字段 | 说明 | 示例 |
|---|---|---|
| `class_descriptor` | DEX 类描述符 | `Lcom/target/License;` |
| `method_name` | 方法名 | `isVIP` |
| `signature` | 方法签名 | `()Z` |
| `action` | `return_const` / `noop` / `log_args` | `return_const=1` |
| `deploy_mode` | `default` / `wait_jit` / `unsafe_bridge` | `wait_jit` |

示例：

```bash
# 让 isVIP() 返回 true (1)，等 JIT 编译后安装
--hook "java:Lcom/target/License;.isVIP:()Z:return_const=1:wait_jit"

# 让 checkRoot() 返回 false (0)
--hook "java:Lcom/target/Security;.checkRoot:()Z:return_const=0:wait_jit"

# 空方法（返回 0）
--hook "java:Lcom/target/Report;.send:(Ljava/lang/String;)V:noop"
```

## ptehookd 命令行

```
ptehookd [OPTIONS]

  --superkey-file=PATH    superkey 路径 (默认 /data/adb/ptehook/superkey)
  --profiles-dir=PATH     profile 目录 (默认 /data/adb/ptehook/profiles)
  --bin-dir=PATH          二进制目录 (默认 /data/adb/ptehook)
  --log=PATH              日志路径 (默认 /data/adb/ptehook/ptehookd.log)
  --poll-interval=MS      轮询间隔 (默认 500)
  --art-ready-delay=MS    ART 初始化等待 (默认 2000)
  --foreground            前台运行
  --status                查看 daemon 状态
  --reload                热重载 profile (发送 SIGHUP)
  --stop                  停止 daemon (发送 SIGTERM)
```

设备上管理 daemon：

```bash
# 查看运行状态
su -c '/data/adb/ptehook/ptehookd --status'

# 添加新 profile 后热重载
su -c 'cp /sdcard/Download/new_profile.json /data/adb/ptehook/profiles/'
su -c '/data/adb/ptehook/ptehookd --reload'

# 查看日志
su -c 'tail -f /data/adb/ptehook/ptehookd.log'

# 停止 daemon
su -c '/data/adb/ptehook/ptehookd --stop'
```

## 设备端文件布局

```
/data/adb/ptehook/
├── superkey                       # APatch superkey (chmod 600)
├── ptehookd                       # 守护进程
├── ptehook_ctl                    # KPM supercall bridge
├── pte_scan                       # ArtMethod 扫描器
├── ptehook_planc_v2.kpm           # 内核模块
├── ptehookd.log                   # daemon 日志
└── profiles/
    ├── com.target.app.json        # hook 配置
    └── com.another.app.json
```

## 反检测能力

| 检测手段 | ptehook 表现 |
|---|---|
| 扫 `/proc/pid/maps` | 完全不可见 |
| 扫 TracerPid / ptrace | 完全不可见 |
| `dl_iterate_phdr` 遍历 .so | 不可见 |
| CRC/MD5 校验代码页 | 字节未修改 |
| 扫 ArtMethod.entry_point | 字段未修改 (7.2 trap 模式) |
| 扫 ArtMethod.access_flags | 未修改 (7.2 trap 模式) |
| `/proc/self/pagemap` PFN 对比 | 只改 UXN bit，PFN 不变 |
| 检测 ADB / USB 调试 | daemon 模式下可关闭 ADB |
| Kernel-level PTE scan | UXN bit 可读 (已知限制) |

## 已知限制

- **PTE 扫描不可隐身**：如果目标反作弊在内核态扫描 PTE UXN bit，本框架无法隐藏
- **DBI 引擎已知崩溃**：`artInvokeInterfaceTrampoline` 类复杂辅助函数页重编译有 bug，建议使用 `wait_jit=True` 规避
- **Java onLeave 不支持**：7.2 trap 模式下 Java 方法的 `CallBackup`（onLeave）暂未实现
- **仅 attach 模式**：当前不支持 spawn-time 注入（zygote fork hook 规划中）
- **APK 版本更新**：APK 更新后 method_idx 可能变化，需重新编译 profile

## 诊断

```python
# 查看 UXN slot 状态
import kpm_client as K
for r in K.uxn_list():
    print(f"slot={r['slot']} pid={r['pid']} target=0x{r['target']:x} hits={r['hits']}")

# hits=0 说明方法没被调用或走了 Nterp 绕过 entry_point
# 建议使用 wait_jit=True

# 查看 KPM 全局状态
print(K.ctl_raw("stat"))
```

设备端日志诊断：

```bash
su -c 'cat /data/adb/ptehook/ptehookd.log'

# 典型正常输出:
# [2026-04-19 12:00:05] ptehookd starting (pid=1234)
# [2026-04-19 12:00:05] loaded profile: com.target.app.json (com.target.app, 2 hooks)
# [2026-04-19 12:00:05] entering monitor loop (1 profiles, poll=500ms)
# [2026-04-19 12:00:10] [com.target.app] process detected pid=5678
# [2026-04-19 12:00:10] [com.target.app] libart ready, waiting 2000ms for ART init
# [2026-04-19 12:00:12] installing 2 hooks for com.target.app (pid=5678)
# [2026-04-19 12:00:13]   [isVIP_0] OK artmethod=0x... ep=0x... ghost=0x... backup=0x...
# [2026-04-19 12:00:13] 2/2 hooks installed for com.target.app
# [2026-04-19 12:00:13] [com.target.app] hooks active
```

## 许可证

见 [LICENSE](LICENSE)。
