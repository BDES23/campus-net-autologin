<#
.SYNOPSIS
    安装「校园网开机自动登录」自启任务（当前用户级，无需管理员）。

.DESCRIPTION
    创建两个任务计划程序任务：
      1. CampusNetAutoLogin  —— 用户登录时触发，延迟 30 秒，网络可用后运行一次
      2. CampusNetGuard      —— 用户登录时触发，延迟 90 秒，常驻巡检（每 5 分钟）

    为什么不用管理员权限：
      任务以当前用户身份、在用户登录时运行，属于用户级任务，不需要提权，
      也不会触发 UAC。系统级（开机即运行）任务才需要管理员，本方案不使用。

.PARAMETER ProjectDir
    项目根目录，默认取本脚本所在目录。

.PARAMETER PythonExe
    指定 python.exe，默认自动探测（优先用项目内 .venv）。

.PARAMETER NoGuard
    只装开机登录任务，不装巡检任务。

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\setup_autostart.ps1
#>
[CmdletBinding()]
param(
    [string]$ProjectDir = "",
    [string]$PythonExe  = "",
    [switch]$NoGuard
)

# 注意：不要把 $PSScriptRoot 直接作为 param 的默认值——在 -File 调用方式下，
# 参数绑定阶段它可能还是空串，会让 Join-Path/Test-Path 报 "Path 为空"。
if (-not $ProjectDir) {
    if ($PSScriptRoot) { $ProjectDir = $PSScriptRoot }
    else { $ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
}
$ProjectDir = (Resolve-Path -LiteralPath $ProjectDir).Path

$ErrorActionPreference = 'Stop'

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok  ($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Err ($msg) { Write-Host "[!!] $msg" -ForegroundColor Red }

# ---------------------------------------------------------------- 定位 python
if (-not $PythonExe) {
    $venv = Join-Path $ProjectDir ".venv\Scripts\python.exe"
    if (Test-Path $venv) {
        $PythonExe = $venv
    } else {
        $cands = @()
        $cands += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Recurse -Filter python.exe -ErrorAction SilentlyContinue |
                  Where-Object { $_.FullName -notmatch 'venv|WindowsApps' } | Select-Object -ExpandProperty FullName
        $cands += Get-ChildItem "C:\Program Files\Python*" -Recurse -Filter python.exe -ErrorAction SilentlyContinue |
                  Select-Object -ExpandProperty FullName
        $PythonExe = $cands | Sort-Object -Descending | Select-Object -First 1
    }
}
if (-not $PythonExe -or -not (Test-Path $PythonExe)) {
    Write-Err "找不到 python.exe，请用 -PythonExe 指定完整路径。"
    exit 1
}
Write-Ok "Python: $PythonExe"

# ---------------------------------------------------------------- 前置检查
$loginScript = Join-Path $ProjectDir "run_login.py"
$guardScript = Join-Path $ProjectDir "run_guard.py"
if (-not (Test-Path $loginScript)) { Write-Err "找不到 $loginScript"; exit 1 }
if (-not $NoGuard -and -not (Test-Path $guardScript)) { Write-Err "找不到 $guardScript"; exit 1 }

Write-Step "检查依赖…"
& $PythonExe -c "import requests, keyring" 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Err "缺少依赖，请先执行：`"$PythonExe`" -m pip install -r `"$ProjectDir\requirements.txt`""
    exit 1
}
Write-Ok "requests / keyring 就绪"

# 确认已配置账号与密码，避免装好了却登不上
Push-Location $ProjectDir
try {
    $statusOut = & $PythonExe -X utf8 -m campusnet status 2>&1 | Out-String
} finally {
    Pop-Location
}
if ($statusOut -match '密码已存\s*:\s*否') {
    Write-Err "凭据管理器里还没有密码。请先执行：`"$PythonExe`" -m campusnet setup"
    exit 1
}

# ---------------------------------------------------------------- 注册任务
Write-Step "注册开机自启任务（当前用户，无需管理员）…"

$taskLogin = 'CampusNetAutoLogin'
$taskGuard = 'CampusNetGuard'
foreach ($t in @($taskLogin, $taskGuard)) {
    if (Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue) {
        Write-Host "    已存在同名任务，先移除：$t"
        Unregister-ScheduledTask -TaskName $t -Confirm:$false
    }
}

# --- 任务 1：登录后延迟 30 秒，执行一次登录
$actionLogin = New-ScheduledTaskAction `
    -Execute $PythonExe `
    -Argument "-X utf8 `"$loginScript`"" `
    -WorkingDirectory $ProjectDir

$triggerLogin = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
$triggerLogin.Delay = 'PT30S'          # ISO8601 时长：30 秒

$settings = New-ScheduledTaskSettingsSet `
    -AllowStartIfOnBatteries `
    -DontStopIfGoingOnBatteries `
    -StartWhenAvailable `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
    -MultipleInstances IgnoreNew `
    -RestartCount 3 `
    -RestartInterval (New-TimeSpan -Minutes 2)

$principal = New-ScheduledTaskPrincipal `
    -UserId "$env:USERDOMAIN\$env:USERNAME" `
    -LogonType Interactive `
    -RunLevel Limited                  # Limited = 不需要管理员

Register-ScheduledTask `
    -TaskName $taskLogin `
    -Action $actionLogin `
    -Trigger $triggerLogin `
    -Settings $settings `
    -Principal $principal `
    -Description "校园网开机自动登录：用户登录后延迟 30 秒检测网络，未登录则调用 Portal 登录接口。" | Out-Null
Write-Ok "已注册任务：$taskLogin（登录后延迟 30 秒触发）"

# --- 任务 2：登录后延迟 90 秒，常驻巡检
if (-not $NoGuard) {
    $actionGuard = New-ScheduledTaskAction `
        -Execute $PythonExe `
        -Argument "-X utf8 `"$guardScript`"" `
        -WorkingDirectory $ProjectDir

    $triggerGuard = New-ScheduledTaskTrigger -AtLogOn -User $env:USERNAME
    $triggerGuard.Delay = 'PT90S'

    $settingsGuard = New-ScheduledTaskSettingsSet `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries `
        -StartWhenAvailable `
        -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1)
    # 常驻任务不限制运行时长（默认 3 天会被杀掉）
    $settingsGuard.ExecutionTimeLimit = 'PT0S'

    Register-ScheduledTask `
        -TaskName $taskGuard `
        -Action $actionGuard `
        -Trigger $triggerGuard `
        -Settings $settingsGuard `
        -Principal $principal `
        -Description "校园网巡检守护：每 5 分钟检查一次，掉线自动重新登录。" | Out-Null
    Write-Ok "已注册任务：$taskGuard（登录后延迟 90 秒启动巡检）"
}

Write-Host ""
Write-Ok "安装完成。"
Write-Host "  立即测试登录   : `"$PythonExe`" -X utf8 -m campusnet check" -ForegroundColor Gray
Write-Host "  手动跑一次任务 : Start-ScheduledTask -TaskName $taskLogin"      -ForegroundColor Gray
Write-Host "  查看任务状态   : Get-ScheduledTask -TaskName CampusNet* | Get-ScheduledTaskInfo" -ForegroundColor Gray
Write-Host "  查看日志       : Get-Content `"$ProjectDir\logs\campusnet.log`" -Tail 50 -Wait" -ForegroundColor Gray
Write-Host "  卸载自启       : powershell -ExecutionPolicy Bypass -File `"$ProjectDir\remove_autostart.ps1`"" -ForegroundColor Gray
