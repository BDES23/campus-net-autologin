# 校园网开机自动登录（Windows 11 · Portal 认证）

一个用于**个人账号**的校园网 Portal 自动登录工具：开机后自动检测网络，未登录就自动登录，
已登录则跳过；登录失败会重试并记录脱敏日志；密码保存在 **Windows 凭据管理器**，不落盘、不入代码。

> **使用声明**
> 本项目仅用于作者本人账号的自动化登录，目的是省去每次开机手动点登录的麻烦。
> 使用前请确认学校网络管理规定允许脚本化登录；**不要**用于批量、代他人或任何绕过计费/认证的场景。
> 账号密码由使用者自行保管，本项目不收集、不上传任何凭据。

> **本文档的脱敏说明**
> 为保护隐私，下文出现的 Portal 地址统一写作 `portal.example.edu`，账号写作 `13800138000`，
> 本机 IP 写作 `10.20.30.40`，主机名写作 `youruser` —— **这些都不是真实值**。
> 但协议本身（`/api` 前缀、提交字段、CSRF 机制、`code` 语义、`err_count_captcha`）
> 全部是逆向真实 Portal 得到的**真实结论**，没有为了脱敏而改动任何一个接口细节。

---

## 目录

- [1. 它是怎么工作的（协议来源说明）](#1-它是怎么工作的协议来源说明)
- [2. 项目结构](#2-项目结构)
- [3. 安装](#3-安装)
- [4. 配置](#4-配置)
- [5. 运行与测试](#5-运行与测试)
- [6. 开机自启](#6-开机自启)
- [7. 关闭自启 / 完全卸载](#7-关闭自启--完全卸载)
- [8. 验收步骤](#8-验收步骤)
- [9. 排障](#9-排障)
- [10. 安全说明](#10-安全说明)
- [11. 验证状态](#11-验证状态)

---

## 1. 它是怎么工作的（协议来源说明）

**重要：本项目里的每一个接口路径和字段名都来自实测，不是推测。**

校园网 Portal 的登录协议是通过分析本机 Edge 浏览器**磁盘缓存中残留的真实 Portal 前端 JavaScript**
还原出来的（原始文件见 `recon/cache_dump/`）。提取到的关键事实：

| 项目 | 实测值 | 证据 |
|---|---|---|
| Portal 主机 | `http://portal.example.edu` | Edge 历史 + 缓存 + 直连回包 |
| **API 前缀** | **`host_url = '/api'`** | 登录页的 `static/js/config.js` 原文 |
| 入口跳转链 | `/api/r/{nasId}?wlanuserip={ip}` → `/tpl/default/login.html?ip=..&nasId=..&wlanuserip=..` → `/tpl/default/login_account.html` | 直连实测 302 |
| 在线状态接口 | `GET /api/account/status?wlanuserip=<ip>`，`code==0` 表示已在线 | 直连实测 `{"code":0,"msg":"在线"}` |
| 登录前检查 | `POST /api/account/check` | 直连实测 `{"code":0,"isChangePwd":"0"}` |
| **登录接口** | **`POST /api/account/login`** | 直连实测 `{"code":0,"msg":"认证成功"}` |
| 注销接口 | `GET /api/account/logout?wlanuserip=<ip>` | 前端 JS |
| **CSRF** | **`GET /api/csrf-token` 取 `csrf_token`，之后每个请求带 `X-CSRF-Token` 头** | `static/js/csrf.js` 原文 + 直连实测 |
| CSRF 失败表现 | 令牌**缺失** → `400 Bad Request`；令牌**过期/错误** → `403` | 生产日志实测（两者都会自动刷新令牌重试） |
| 其他接口 | `GET /api/config`（有 `err_count_captcha: 3`）、`GET /api/csrf-token` | 直连实测 |
| 提交格式 | `application/x-www-form-urlencoded`（jQuery `$.post` 默认） | 前端 JS |
| **密码是否加密** | **不加密，明文提交**（源码：`postData.password = $('#password').val()`） | 前端 JS |
| 提交字段 | `username, password, switchip, nasId, userIpv4, userMac, captcha, captchaId, isp, timeLimit` | 前端 JS |
| 空值处理 | **值为空串的字段会被前端删除后再提交** | 前端 JS |
| 响应语义 | `code=0` 成功；`code=1` 失败（读 `msg`）；`code=2` 需要验证码（读 `captcha.picPath` / `captcha.captchaId`） | 前端 JS 注释 + 直连实测 |
| 验证码策略 | 密码连续错 **3** 次后开始要求验证码（`err_count_captcha: 3`） | `/api/config` 实测 |

> ⚠️ **路径必须带 `/api` 前缀**。这是本项目唯一一次踩坑：早期版本按 `/account/login` 请求，
> 被 nginx 直接 404。根因是 `host_url` 定义在 `static/js/config.js` 里（该文件当时不在浏览器缓存中），
> 后来把它抓下来才看到 `var host_url = '/api'`。老版 `config.ini` 会被自动迁移，无需手工改。

因为密码是**明文**提交、没有 JS 加密，所以**不需要 Playwright/Selenium**，用 `requests` 即可，
启动快、资源占用低，非常适合开机自启场景。

### 运行时流程

```
开机 / 登录 → 任务计划程序延迟 30s → run_login.py
    │
    ├─ 1. SSID 白名单校验（可选）——不在校园网 SSID 上直接跳过
    ├─ 2. 多探测点判断是否已登录
    │      http://www.gstatic.com/generate_204       期望 204
    │      http://connect.rom.miui.com/generate_204  期望 204
    │      http://www.msftconnecttest.com/connecttest.txt 期望 200 + "Microsoft Connect Test"
    │      （全部用 http，绝不用 https——未认证时 https 会被阻断）
    │      任一探测点符合预期即判定"已登录" → 跳过，不重复登录
    │
    ├─ 3. 跟随真实 302 链，自动发现 Portal 入口，解析出 wlanuserip / nasId / switchip / mac
    │      ⚠ nasId 是接入设备编号，会随楼栋/AP 变化，因此**从重定向动态获取，绝不写死**
    │
    ├─ 4. GET {host_url}/csrf-token 取 CSRF 令牌，挂到后续请求的 X-CSRF-Token 头
    │      （**带重试**：实测校园网关约一半连接会超时；POST 若返回 403 会自动刷新令牌重试）
    ├─ 5. GET /api/account/status 再确认一次（避免重复登录）
    ├─ 6. POST /api/account/check（非致命，用于识别"强制改密"）
    ├─ 7. POST /api/account/login，密码明文、form-urlencoded、空字段剔除
    ├─ 8. 校验连通性；失败则指数退避重试（默认 3 次）
    └─ 9. 全程写日志，密码自动脱敏为 ***
```

---

## 2. 项目结构

```
campus-net-autologin/
├─ README.md                     本文件
├─ requirements.txt              依赖清单
├─ config.example.ini            配置示例（占位符）
├─ config.ini                    你的实际配置（setup 生成；**已被 .gitignore 排除**）
├─ .gitignore                    确保账号与日志永不进仓库
├─ campusnet.cmd                 便捷启动器（自动挑可用 Python，绕开商店占位符）
├─ run_login.py                  开机自启入口（任务计划程序调用）
├─ run_guard.py                  巡检守护入口（每 5 分钟检查一次）
├─ setup_autostart.ps1           安装开机自启（当前用户级，无需管理员）
├─ remove_autostart.ps1          卸载开机自启
├─ campusnet/                    核心包
│  ├─ __init__.py                协议来源说明
│  ├─ config.py                  INI 配置读写（含旧配置自动迁移）
│  ├─ secretstore.py             凭据管理（Windows 凭据管理器 / keyring）
│  ├─ logkit.py                  日志 + 强制脱敏
│  ├─ netcheck.py                网络检测、Portal 入口自动发现、本机 IP/MAC/SSID
│  ├─ portal.py                  Portal 协议客户端（接口、字段、CSRF）
│  ├─ runner.py                  登录编排、智能重试、巡检
│  ├─ cli.py                     命令行
│  └─ __main__.py                python -m campusnet 入口
├─ tools/
│  ├─ probe_portal.py            只读侦察探针（判断是否被劫持、抓 302 链、解析表单）
│  ├─ capture_live.py            真实交互验证（用故意错误的密码探测接口，不需要真实密码）
│  └─ browser_forensics.py       浏览器取证：门户不可达时，从缓存/历史里还原登录接口
├─ docs/
│  └─ evidence/
│     ├─ config.js               关键证据①：`var host_url = '/api'`
│     └─ csrf.js                 关键证据②：CSRF 令牌如何取、如何带
├─ tests/                        测试套件（仅用标准库 unittest，不需要 pytest）
│  ├─ mock_portal.py             本地模拟 Portal，严格复刻实测协议（含 CSRF 校验）
│  └─ test_campusnet.py          30 个单元 + 集成测试
├─ logs/
│  └─ campusnet.log              滚动日志（UTF-8，密码已脱敏；**已被 .gitignore 排除**）
└─ recon/                        侦察产物与只读分析脚本
   ├─ cache_dump/                从浏览器缓存提取的**真实 Portal 前端源码**（协议证据）
   ├─ query_history.py           只读查询浏览器历史（还原 Portal 访问时间线）
   ├─ scan_cache.py / scan_cache2.py  只读扫描浏览器缓存
   └─ check_endpoints.py         端点连通性探测
```

---

## 3. 安装

### 3.1 安装 Python

本机原本**没有** Python（`python.exe` 只是 0 字节的微软商店占位符），需先安装：

```powershell
winget install --id Python.Python.3.12 --exact --accept-package-agreements --accept-source-agreements
```

> ⚠️ 装完后 `python` 命令可能仍指向商店占位符（`WindowsApps\python.exe`），
> 因为 `WindowsApps` 在 PATH 里排得更前。两种处理方式：
> - **推荐**：在项目里建虚拟环境（见 3.3），自启脚本会优先用它，完全绕开 PATH 问题；
> - 或到「设置 → 应用 → 高级应用设置 → 应用执行别名」里关掉 `python.exe` / `python3.exe`。

### 3.2 安装依赖

```powershell
cd <项目目录>
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m pip install -r requirements.txt
```

依赖只有两个：

| 包 | 用途 |
|---|---|
| `requests` | 发 HTTP 请求 |
| `keyring` | 把密码写进 Windows 凭据管理器（后端 `WinVaultKeyring`） |

### 3.3 创建虚拟环境（可选）

**不建也能用**——`requests` 和 `keyring` 已经装在上面的用户级 Python 里了，
`campusnet.cmd` 与 `setup_autostart.ps1` 都能自动找到它。想隔离环境再建：

```powershell
& "$env:LOCALAPPDATA\Programs\Python\Python312\python.exe" -m venv --system-site-packages .venv
```

> 因为本机访问 PyPI 很不稳定（实测 `pip install` 在工作区内建 venv 时能卡住 5 分钟以上），
> 建议加 `--system-site-packages`：这样 venv 直接继承已装好的 `requests` / `keyring`，
> **完全不需要联网**。若仍要独立安装依赖，把 `--system-site-packages` 去掉即可。
> 本机实测：装在 `%LOCALAPPDATA%` 的基础 Python，`pip install` 约 30 秒完成。

建好之后，`campusnet.cmd` 与 `setup_autostart.ps1` 会**自动优先使用 `.venv\Scripts\python.exe`**。

---

## 4. 配置

### 4.1 交互式初始化（推荐）

```powershell
python -m campusnet setup
```

会依次询问：学号 → Portal 主机 → SSID 白名单，然后**用隐藏输入**录入两遍密码，
密码直接写进 Windows 凭据管理器（`服务名 = campus-net-autologin`）。

**密码永远不会写进 `config.ini`，也不会出现在日志里。**

### 4.2 手动编辑 `config.ini`

```ini
[portal]
base_url =                          ; Portal 主机；**留空即可**，默认靠 302 重定向自动发现
login_path = /api/account/login     ; 登录接口（实测值，**/api 前缀不能少**）
check_path = /api/account/check     ; 登录前检查
status_path = /api/account/status   ; 在线状态
logout_path = /api/account/logout   ; 注销
csrf_path = /api/csrf-token         ; CSRF 令牌接口；若你的 Portal 没有就留空
csrf_header = X-CSRF-Token          ; 令牌放在哪个请求头（实测值）
probe_url = http://www.gstatic.com/generate_204   ; 探测地址，必须用 http
entry_template =                    ; 可选兜底入口，形如 http://10.0.0.1/api/r/1?wlanuserip={ip}
extra_headers =                     ; 需要额外请求头时在此加，形如 A: b; C: d

[account]
username =                          ; 学号（setup 会填）
isp = local                         ; 运营商，校园网一般 local
time_limit =                        ; 上网时长，留空即不下发该字段

[network]
interface = WLAN
ssid_whitelist =                    ; 限定 SSID，逗号分隔；留空=不限制
verify_after_login = true           ; 登录后校验一次连通性

[policy]
retries = 3                         ; 单次运行的重试次数
retry_backoff = 2.0                 ; 退避基数（秒）：第 n 次等待 backoff × 2^(n-1)
request_timeout = 8                 ; 单请求超时（秒）
guard_interval = 300                ; 巡检间隔（秒），最小 30
on_captcha = stop                   ; 遇到验证码：stop=记日志退出

[logging]
dir = logs
level = INFO
max_bytes = 1048576
backup_count = 5
```

改完**不需要重新安装自启任务**，下次运行即生效。

---

## 5. 运行与测试

所有命令都在项目根目录执行。**推荐用 `campusnet.cmd` 包装脚本**——它会自动挑一个
可用的 Python 解释器并加上 `-X utf8`，可以完全绕开"`python` 指向微软商店占位符"的坑：

```powershell
cd <项目目录>
.\campusnet.cmd status      # 看状态
.\campusnet.cmd setup       # 初始化（录入学号 + 密码）
.\campusnet.cmd check       # 执行一次登录
```

下面表格里的 `python -m campusnet xxx` 是等价写法；如果你机器上的 `python` 会打开微软商店，
就统一换成 `.\campusnet.cmd xxx`（或把 `python` 换成
`"$env:LOCALAPPDATA\Programs\Python\Python312\python.exe"`）。

| 命令 | 作用 |
|---|---|
| `python -m campusnet setup` | 交互式初始化（写配置 + 存密码） |
| `python -m campusnet check` | **执行一次**：检测网络，未登录就登录（自启调用的就是这个逻辑） |
| `python -m campusnet check --force` | 即使已在线也强制走一遍登录流程（验证接口用） |
| `python -m campusnet guard` | 常驻巡检：每 5 分钟检查一次，掉线自动重登 |
| `python -m campusnet status` | 查看当前状态（配置、凭据、IP/MAC/SSID、探测结果），不做登录动作 |
| `python -m campusnet doctor` | 环境自检与排障信息（依赖、链路、Portal 入口） |
| `python -m campusnet logout` | 主动注销，用于测试（**会断网，浏览器重新认证即可恢复**） |
| `python -m campusnet set-password` | 只更新凭据管理器里的密码 |
| `python -m campusnet delete-password` | 删除凭据管理器里的密码 |

> 中文输出乱码时加 `-X utf8`，例如 `python -X utf8 -m campusnet status`。

### 5.1 侦察工具（只读，不改系统）

```powershell
python tools\probe_portal.py           # 判断是否被 Portal 劫持、打印完整 302 链、解析登录表单
python tools\probe_portal.py --watch   # 每 3 秒轮询，等 Portal 出现（配合下面 5.3 使用）
```

> **Portal 已经能上网、抓不到包怎么办？** 用浏览器取证。
> 门户主机通常只在未认证时可达，但门户页面和它的 JS **会留在浏览器磁盘缓存里**：
>
> ```powershell
> python tools\browser_forensics.py --list                        # 看有哪些浏览器配置目录
> python tools\browser_forensics.py --history --keyword wlanuserip # 从历史还原门户入口（带时间线）
> python tools\browser_forensics.py --cache --keyword host_url     # 从缓存里捞出登录页与其 JS
> ```
>
> 本项目的 `host_url = '/api'` 就是这么找到的——当时门户已经完全不可达。

### 5.2 真实交互验证（**不需要真实密码**）

```powershell
python tools\capture_live.py
```

它会在**未登录状态**下：

1. 打印完整 302 重定向链，保存入口页 HTML；
2. 检查页面引用了哪些脚本（重点看有没有 `csrf.js`）、有没有加密/验证码关键字；
3. 调 `GET /account/status` 看 Portal 是否认为已在线；
4. **用一个一眼假的占位密码**去调 `POST /account/check` 和 `POST /account/login`。
   因为是错密码，**不可能登录成功**，但能确认：接口路径存在、字段名被接受、返回是 JSON。
   如果拿到 `code=1`（业务层失败）而不是 404/403，就说明本项目实现与学校 Portal 完全一致。

### 5.3 怎么制造"未登录"状态

Portal 只在**未认证**时可达，已登录时抓不到登录请求。要复现未登录状态：

1. **换随机 MAC（最有效，不需要管理员）**
   设置 → 网络和 Internet → WLAN → 点当前网络 → 打开「随机硬件地址」→ 断开重连。
   本机实测拓扑中，电脑直接持有校园网 DHCP 租约（IP `10.20.30.40`，网关 `10.20.30.1`），
   说明认证是按本机 MAC/IP 计的，而不是路由器代拨 —— 换 MAC 即可强制回到未认证态。
2. **换 IP**：断开 Wi-Fi 再连，或 `ipconfig /release` + `ipconfig /renew`（可能需要管理员）。
   Portal 的入口参数就叫 `wlanuserip`，认证很可能与 IP 绑定。
3. **主动注销**：`python -m campusnet logout`（前提是 Portal 当时可达）。
4. **等会话过期**。

拿到未认证状态后，配合 `python tools\probe_portal.py --watch` 能自动捕捉到 Portal 出现的瞬间。

### 5.4 自动化测试（不需要校园网，不需要真实密码）

```powershell
python -X utf8 -m unittest discover -s tests -v
```

25 个测试，全部使用标准库 `unittest`，**不需要 pytest**。核心思路是
`tests\mock_portal.py` 在 `127.0.0.1` 上起一个**严格复刻实测协议**的模拟 Portal
（同样的 302 链、同样的 `/account/login` 字段、同样的 `code` 语义），
然后把 `probe_url` 指向它，跑完整的 `runner.run_once`。

| 测试 | 验证内容 |
|---|---|
| `TestHappyPath` | 未登录 → 跟随 302 链发现入口 → 提交 → 校验成功；提交的字段、明文密码、`form-urlencoded`、空字段剔除全部逐项核对 |
| `TestAlreadyOnline` | 已登录时**绝不**调用 `/account/login`；`--force` 时才真的提交 |
| `TestFailurePaths` | 密码错误 → 明确失败，且不会误报成功 |
| `TestSmartRetry` | 含"密码/账号"字样的错误**立即停止**重试；其他错误重试到配置上限 |
| `TestCaptcha` | 服务端要求验证码 → 返回专门的退出码 |
| `TestMissingConfig` | 缺账号 / 缺密码 → 返回配置错误码并给出修复提示 |
| `TestRedaction` | **服务端把密码回显到错误信息里时，日志里必须变成 `***`** |
| `TestPayload` / `TestResponseMapping` / `TestEntryParsing` / `TestConfig` | 字段构造、`code` 语义、入口参数解析、配置读写 |

---

## 6. 开机自启

### 6.1 安装

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_autostart.ps1
```

会注册**两个当前用户级任务**（**不需要管理员权限，不会弹 UAC**）：

| 任务名 | 触发 | 动作 |
|---|---|---|
| `CampusNetAutoLogin` | 用户登录时，**延迟 30 秒** | 运行 `run_login.py`，检测并登录一次 |
| `CampusNetGuard` | 用户登录时，延迟 90 秒 | 运行 `run_guard.py`，常驻巡检，每 5 分钟检查一次 |

只想要开机登录、不要巡检：

```powershell
powershell -ExecutionPolicy Bypass -File .\setup_autostart.ps1 -NoGuard
```

参数：

| 参数 | 说明 |
|---|---|
| `-ProjectDir <路径>` | 项目根目录，默认脚本所在目录 |
| `-PythonExe <路径>` | 指定 python.exe，默认优先 `.venv`，否则自动探测 |
| `-NoGuard` | 不安装巡检任务 |

安装脚本会做**前置检查**：缺依赖、或凭据管理器里没有密码，都会直接拒绝安装并提示。

任务的关键设置：`RunLevel=Limited`（不需要管理员）、`StartWhenAvailable`（错过触发时间会补跑）、
`AllowStartIfOnBatteries`（笔记本用电池也运行）、`RestartCount=3`（失败自动重启）。

### 6.2 验证自启

```powershell
# 查看任务
Get-ScheduledTask -TaskName CampusNet* | Format-Table TaskName, State

# 看上次运行结果（LastTaskResult=0 表示成功）
Get-ScheduledTask -TaskName CampusNet* | Get-ScheduledTaskInfo

# 不等重启，手动立刻跑一次登录任务
Start-ScheduledTask -TaskName CampusNetAutoLogin

# 实时看日志
Get-Content .\logs\campusnet.log -Tail 50 -Wait
```

重启电脑后，登录进桌面约 30 秒，检查 `logs\campusnet.log` 的末尾即可确认是否自动登录成功。

---

## 7. 关闭自启 / 完全卸载

### 7.1 只停自启，保留配置和密码

```powershell
powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1
```

它会删除两个计划任务、结束正在运行的巡检进程，**保留**凭据与日志。

### 7.2 连密码一起清掉

```powershell
powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1 -RemoveSecrets
```

### 7.3 连日志一起清掉

```powershell
powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1 -RemoveSecrets -RemoveLogs
```

### 7.4 手动方式（备选）

```powershell
# 删除任务
Unregister-ScheduledTask -TaskName CampusNetAutoLogin -Confirm:$false
Unregister-ScheduledTask -TaskName CampusNetGuard     -Confirm:$false

# 结束巡检进程
Get-CimInstance Win32_Process -Filter "Name like 'python%'" |
  Where-Object { $_.CommandLine -match 'run_guard\.py' } |
  ForEach-Object { Stop-Process -Id $_.ProcessId -Force }

# 删除密码：控制面板 → 凭据管理器 → Windows 凭据 → 找到 campus-net-autologin
# 或命令行：
python -m campusnet delete-password
```

卸载自启后如果还想彻底删除项目，直接删掉 `<项目目录>` 整个目录即可
（项目没有往注册表、系统目录写任何东西）。

---

## 8. 验收步骤

按顺序做完这 9 步，就能确认整套东西真的可用。

### 第 0 步 · 环境
```powershell
python -X utf8 -m unittest discover -s tests -v      # 先跑自检：25 个测试
python -X utf8 -m campusnet doctor                   # 再看本机实际环境
```
- [ ] **25 个测试全部通过**（不需要校园网，不需要真实密码）
- [ ] 显示 Python 版本、`requests`、`keyring` 后端为 `WinVaultKeyring`
- [ ] 「链路判定」显示 `已登录`
- [ ] 「Portal 入口」能列出一个带 `wlanuserip=` 的 URL

### 第 1 步 · 配置与凭据
```powershell
python -X utf8 -m campusnet setup
python -X utf8 -m campusnet status
```
- [ ] `status` 里「账号」是你的学号
- [ ] 「密码已存 : 是」
- [ ] **`config.ini` 里搜不到密码**（可用 `Select-String -Path config.ini -Pattern "<你的密码>"` 确认无匹配）

### 第 2 步 · 已登录时正确跳过
在**已联网**状态下：
```powershell
python -X utf8 -m campusnet check
```
- [ ] 输出「已在线」，退出码 `0`
- [ ] 日志里没有出现任何 POST `/account/login`

### 第 3 步 · 制造未登录状态
按 [5.3](#53-怎么制造未登录状态) 打开「随机硬件地址」并重连 Wi-Fi。
```powershell
python tools\probe_portal.py
```
- [ ] 判定为 `未登录 —— 链路被 Portal 劫持`
- [ ] 打印出 302 跳转链，且能看到 `/api/r/<nasId>`、`/index_<nasId>.html` 等路径

### 第 4 步 · 确认真实协议（关键）
```powershell
python tools\capture_live.py
```
- [ ] 第 2 节打印出真实的 302 链
- [ ] 第 4 节列出入口页引用的脚本，并明确指出有没有 `csrf.js`
- [ ] 第 6 节 `POST /account/check` 与 `POST /account/login` **都返回了业务层失败（`code=1`）而不是 404/403**
       → 这证明接口路径与字段名与本项目实现一致
- [ ] 若返回 404 → 改 `config.ini` 的 `*_path`；若返回 403 → 说明有 CSRF 校验，见 [第 11 节](#11-已知未验证点)

### 第 5 步 · 真实自动登录
仍在未登录状态：
```powershell
python -X utf8 -m campusnet check
```
- [ ] 输出「登录成功并已校验连通」，退出码 `0`
- [ ] 打开浏览器能正常上网
- [ ] `logs\campusnet.log` 末尾有完整过程记录
- [ ] **日志里搜不到你的密码**（`Select-String -Path .\logs\campusnet.log -Pattern "<你的密码>"` 无结果）

### 第 6 步 · 失败重试
把 `config.ini` 里 `account.username` 临时改成一个错误学号，然后制造未登录状态：
```powershell
python -X utf8 -m campusnet check
```
- [ ] 日志里能看到重试过程，最终失败并给出明确原因
- [ ] 退出码非 `0`
- [ ] **改回正确学号**

### 第 7 步 · 安装自启
```powershell
powershell -ExecutionPolicy Bypass -File .\setup_autostart.ps1
Get-ScheduledTask -TaskName CampusNet* | Format-Table TaskName, State
```
- [ ] 两个任务都是 `Ready` 状态，全程没有弹 UAC
- [ ] `Start-ScheduledTask -TaskName CampusNetAutoLogin` 后，日志里出现新的一轮记录

### 第 8 步 · 重启验证（最终验收）
先制造未登录状态，然后**重启电脑**，登录进桌面后等 30～60 秒：
- [ ] 不用手动点任何东西，网络自动恢复
- [ ] `logs\campusnet.log` 里有本次开机时间的登录成功记录

### 第 9 步 · 卸载验证
```powershell
powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1
Get-ScheduledTask -TaskName CampusNet* -ErrorAction SilentlyContinue
```
- [ ] 两个任务都已消失（无输出即正确）
- [ ] `Get-CimInstance Win32_Process -Filter "Name like 'python%'"` 里不再有 `run_guard.py`

---

## 9. 排障

| 现象 | 原因 / 解决 |
|---|---|
| `python` 打开微软商店 | PATH 里 `WindowsApps` 优先。用完整路径，或建 `.venv`（见 3.1 / 3.3） |
| 中文输出乱码 | 加 `-X utf8`，例如 `python -X utf8 -m campusnet status` |
| `keyring 不可用` | `pip install keyring`；仍不行就改用环境变量 `CAMPUSNET_PASSWORD`（不安全，仅临时） |
| 判定"未登录"但其实能上网 | 内置探测点被学校屏蔽。把 `config.ini` 的 `probe_url` 改成一个轻量 http 地址即可——**只要它不等于内置的三个地址，就以它独占判定**（规则：2xx 且无跳转且正文不像 Portal 页面）；若该地址不可达会自动退回内置探测点 |
| 找不到 Portal 入口 | 手工把 `entry_template` 改成实际的 `http://<portal_ip>/api/r/<nasId>?wlanuserip={ip}` |
| **接口全返回 404** | 路径漏了 `/api` 前缀（实测 `host_url = '/api'`）。确认 `config.ini` 里是 `/api/account/login`；老配置会被自动迁移，若仍不对就删掉 `config.ini` 重新 `setup` |
| **POST 返回 403** | CSRF 令牌没取到或过期。代码已内置重试与自动刷新；若仍 403，用 `tools\capture_live.py` 看 `/api/csrf-token` 是否可达 |
| `nasId` 变了 | 正常情况下会自动发现，无需处理；若用了兜底模板，请更新模板里的数字 |
| 请求超时 / 时通时断 | 校园网关本身不稳定（本机实测同一主机 6 次请求 3 次超时）。脚本已内置重试与退避 |
| 返回 `code=2` / `captcha_needed` | 服务端要求验证码，无人值守无法完成。日志会明确记录；先手动登录一次消除风控 |
| 返回 403 | 多半是 CSRF 校验，见 [第 11 节](#11-已知未验证点) |
| `Win32_Process` 查询权限不足 | 用管理员 PowerShell，或直接用 `remove_autostart.ps1` |
| 装了 Tailscale / Radmin 等虚拟网卡 | 它们可能抢默认路由或干扰探测。抓包与排障时建议先退出 |

---

## 10. 安全说明

- **密码只存在 Windows 凭据管理器**（`服务名 campus-net-autologin`），
  `config.ini`、代码、日志里都没有密码。
- **日志强制脱敏**：`logkit` 注册了敏感值过滤器，密码一旦出现在任何日志消息里都会被替换成 `***`；
  另有正则兜底拦截 `password=xxx` 这类片段。
- **网络请求的响应体在写日志前先脱敏**，避免服务端回显密码。
- **绝不会**把密码发到任何第三方；本项目不含任何遥测、上报代码。
- 如果 keyring 不可用，程序会**明确报错并拒绝运行**，而不是偷偷降级成明文存储。
- 想换密码：`python -m campusnet set-password`。
- 想彻底删除密码：`python -m campusnet delete-password`。

---

## 11. 验证状态

### 已在真实校园网上端到端跑通（2026-10-17 生产日志）

```
01:42:14 [WARNING] runner: 第 1/3 次出现异常：400 Client Error: Bad Request for /api/account/login
01:42:14 [INFO   ] runner: 等待 2.0 秒后重试…
01:42:30 [INFO   ] runner: 第 2/3 次尝试登录（账号 13800138000）…
01:42:30 [INFO   ] runner: 认证成功（用户 13800138000）
01:43:54 [INFO   ] autostart: 开机自动登录任务启动
01:43:55 [INFO   ] runner: 网络已处于已登录状态，跳过（不重复登录）
01:43:55 [INFO   ] autostart: 结束：已在线（退出码 0）
```

**已确证的事项**：接口路径与 `/api` 前缀、提交字段与明文密码、CSRF 令牌机制、
`code` 语义、`isChangePwd` 是字符串、登录成功、已登录时正确跳过、开机任务真实触发。

那次 `400 Bad Request` 是 CSRF 令牌连续 3 次超时导致的。**现已修复**：
令牌**缺失**（400）与令牌**过期/错误**（403）都会自动刷新令牌并重试，
可在**单轮尝试内自愈**，不再浪费 runner 的重试次数。

### 仍未验证的部分

| # | 未验证项 | 原因 | 对策 |
|---|---|---|---|
| 1 | `/api/account/check` 是否必需 | 前端会先调它，但服务端是否强制未知 | 代码按前端行为调用，且**失败不阻断登录**，不会成为单点故障 |
| 2 | 验证码实际触发后的表现 | 已知 `err_count_captcha: 3`（密码连错 3 次要验证码），但未实际触发 | 代码识别 `code=2` 并明确记录；若常态要求验证码，需改用 Playwright + OCR |
| 3 | 会话超时时间 | 未长时间观察 | 已用每 5 分钟巡检兜底，掉线即重登 |

---

## 附：开发环境与实测发现

### 开发环境

| 项 | 值 |
|---|---|
| 系统 | Windows 11 家庭版 `10.0.26100` |
| 权限 | **普通用户，非管理员**（因此自启采用用户级任务，完全不需要提权） |
| Python | 3.12（`winget` 安装到用户目录 `%LOCALAPPDATA%\Programs\Python\Python312`） |
| 浏览器 | Microsoft Edge（用于抓包与浏览器缓存取证） |
| 虚拟网卡 | Tailscale / Radmin VPN / 网易UU / VeryKuai（排障时建议先退出，它们会干扰默认路由与网络探测） |

### 逆向过程中确认的事实（值已脱敏，结论未改动）

| 项 | 值 |
|---|---|
| API 前缀 | `host_url = '/api'` —— 直接来自登录页引用的 `static/js/config.js` |
| 鉴权方式 | 无 cookie 会话，靠 CSRF 令牌 + 同源 `Referer`/`Origin` |
| CSRF | `GET /api/csrf-token` → `{"csrf_token": "..."}`，随 `X-CSRF-Token` 头发送 |
| 密码 | **明文**提交（`postData.password = $('#password').val()`），无任何 JS 加密 |
| `nasId` | 随接入设备变化，因此从 302 跳转**动态解析，绝不写死** |
| 验证码 | 密码连续错 3 次后开始要求（`err_count_captcha: 3`） |
| 链路质量 | 到 Portal 主机约**一半连接会超时**（连续 6 次请求中 3 次超时、3 次被 nginx 秒回）→ 重试是必需的，不是可选优化 |

### 方法论（可复用到你自己的学校）

1. 用多个轻量探测点（`generate_204` 等）判断当前是否被 Portal 劫持；
2. 从 `302 Location` 还原入口链，取出 `wlanuserip` / `nasId` / `switchip` / `mac`；
3. Portal 只有在**未认证**时才可达；已登录时若拿不到包，就改从
   **浏览器磁盘缓存**里提取登录页与它引用的 `config.js` / `csrf.js`
   （本项目就是这样才找到 `host_url = '/api'` 的）；
4. 用 `tools/capture_live.py` 以**故意错误的密码**探测接口，
   借返回码区分"路径不对（404）"和"字段/令牌不对（400/403）"；
5. 用本地模拟 Portal（`tests/mock_portal.py`）搭一套端到端回归，
   把链路抖动、令牌失效等异常都变成可重复的测试用例。
