<#
.SYNOPSIS
    卸载「校园网开机自动登录」自启任务，并停止正在运行的巡检进程。

.DESCRIPTION
    1. 停止并删除 CampusNetAutoLogin / CampusNetGuard 两个任务
    2. 结束由本项目 run_guard.py 启动的 python 进程
    3. -RemoveSecrets：一并删除凭据管理器里的密码
    4. -RemoveLogs   ：一并删除日志

.EXAMPLE
    powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1
    powershell -ExecutionPolicy Bypass -File .\remove_autostart.ps1 -RemoveSecrets
#>
[CmdletBinding()]
param(
    [string]$ProjectDir = "",
    [switch]$RemoveSecrets,
    [switch]$RemoveLogs
)

# 注意：不要把 $PSScriptRoot 直接作为 param 的默认值——在 -File 调用方式下，
# 参数绑定阶段它可能还是空串，会让 Join-Path/Test-Path 报 "Path 为空"。
if (-not $ProjectDir) {
    if ($PSScriptRoot) { $ProjectDir = $PSScriptRoot }
    else { $ProjectDir = Split-Path -Parent $MyInvocation.MyCommand.Definition }
}
$ProjectDir = (Resolve-Path -LiteralPath $ProjectDir).Path

$ErrorActionPreference = 'Continue'

function Write-Step($msg) { Write-Host "[*] $msg" -ForegroundColor Cyan }
function Write-Ok  ($msg) { Write-Host "[OK] $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!] $msg" -ForegroundColor Yellow }

$tasks = @('CampusNetAutoLogin', 'CampusNetGuard')

# ---------------------------------------------------------------- 定位 python
function Find-Python {
    param([string]$Root)
    $venv = Join-Path $Root ".venv\Scripts\python.exe"
    if (Test-Path $venv) { return $venv }
    $c = @()
    $c += Get-ChildItem "$env:LOCALAPPDATA\Programs\Python" -Recurse -Filter python.exe -ErrorAction SilentlyContinue |
          Where-Object { $_.FullName -notmatch 'venv|WindowsApps' } | Select-Object -ExpandProperty FullName
    $c += Get-ChildItem "C:\Program Files\Python*" -Recurse -Filter python.exe -ErrorAction SilentlyContinue |
          Select-Object -ExpandProperty FullName
    return ($c | Sort-Object -Descending | Select-Object -First 1)
}

# ---------------------------------------------------------------- 1. 删除任务
Write-Step "删除任务计划程序中的自启任务..."
foreach ($t in $tasks) {
    $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
    if ($task) {
        Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $t -Confirm:$false
        Write-Ok "已删除：$t"
    } else {
        Write-Warn "不存在（跳过）：$t"
    }
}

# ---------------------------------------------------------------- 2. 结束巡检进程
Write-Step "结束正在运行的巡检进程..."
$killed = 0
Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue | ForEach-Object {
    $cmd = $_.CommandLine
    if ($cmd -and ($cmd -match 'run_guard\.py' -or $cmd -match 'campusnet\s+guard')) {
        try {
            Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop
            $killed++
            Write-Ok "已结束 PID $($_.ProcessId)"
        } catch {
            Write-Warn "无法结束 PID $($_.ProcessId)：$($_.Exception.Message)"
        }
    }
}
if ($killed -eq 0) { Write-Warn "没有发现运行中的巡检进程" }

# ---------------------------------------------------------------- 3. 凭据
if ($RemoveSecrets) {
    Write-Step "删除凭据管理器中的密码..."
    $py = Find-Python -Root $ProjectDir
    if ($py) {
        Push-Location $ProjectDir
        try {
            & $py -X utf8 -m campusnet delete-password --yes
        } catch {
            Write-Warn "调用 CLI 删除凭据失败：$($_.Exception.Message)"
        } finally {
            Pop-Location
        }
    } else {
        Write-Warn "找不到 python，无法自动删除。"
        Write-Host "     手动删除：控制面板 -> 凭据管理器 -> Windows 凭据 -> 找到 campus-net-autologin" -ForegroundColor Gray
    }
} else {
    Write-Warn "凭据管理器里的密码已保留（如需删除请加 -RemoveSecrets）"
}

# ---------------------------------------------------------------- 4. 日志
if ($RemoveLogs) {
    $logDir = Join-Path $ProjectDir "logs"
    if (Test-Path $logDir) {
        Remove-Item $logDir -Recurse -Force
        Write-Ok "已删除日志目录：$logDir"
    }
} else {
    Write-Warn "日志已保留：$ProjectDir\logs"
}

Write-Host ""
Write-Ok "卸载完成。项目文件仍在 $ProjectDir，可手动删除。"
