@echo off
rem ============================================================
rem  campusnet.cmd - launcher for the campus-network auto-login tool.
rem
rem  Why this wrapper exists:
rem    On this machine the bare "python" command still resolves to the
rem    0-byte Microsoft Store alias in WindowsApps, which opens the Store
rem    instead of running Python. This wrapper picks a real interpreter.
rem
rem  Usage (cmd.exe or PowerShell, from this folder):
rem      campusnet.cmd status
rem      campusnet.cmd check
rem      campusnet.cmd setup
rem      campusnet.cmd doctor
rem
rem  Kept ASCII-only on purpose so it renders under any console code page.
rem ============================================================
setlocal
set "ROOT=%~dp0"
pushd "%ROOT%"

set "PY="
call :try "%ROOT%.venv\Scripts\python.exe"
call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
call :try "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
call :try "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
call :try "%ProgramFiles%\Python312\python.exe"
call :try "%ProgramFiles%\Python313\python.exe"
call :try "%ProgramFiles%\Python311\python.exe"

if not defined PY (
    echo [ERROR] Python 3.11+ was not found.
    echo         Install it with:
    echo             winget install --id Python.Python.3.12 --exact
    popd
    exit /b 3
)

"%PY%" -X utf8 -m campusnet %*
set "RC=%ERRORLEVEL%"
popd
exit /b %RC%

:try
if not defined PY if exist "%~1" set "PY=%~1"
goto :eof
