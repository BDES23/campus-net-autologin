@echo off
rem ============================================================
rem  One-click build: package the whole project into CampusNet.exe
rem
rem  Two rules this script follows, both learned the hard way:
rem    1. ASCII only. cmd.exe parses .bat with the OEM code page, so
rem       UTF-8 Chinese here silently corrupts the following lines.
rem    2. No delayed expansion (!VAR!). Plain %VAR% outside blocks is
rem       enough, and it keeps the parser from mangling things.
rem ============================================================
setlocal
cd /d "%~dp0"

echo ============================================================
echo   CampusNet.exe  -  one-click build
echo ============================================================
echo.

rem ---------------------------------------------------------- find python
set "PY="
call :try "%LOCALAPPDATA%\Programs\Python\Python312\python.exe"
call :try "%LOCALAPPDATA%\Programs\Python\Python313\python.exe"
call :try "%LOCALAPPDATA%\Programs\Python\Python311\python.exe"
call :try "%ProgramFiles%\Python312\python.exe"
call :try "%ProgramFiles%\Python313\python.exe"
call :try "%ProgramFiles%\Python311\python.exe"
if not defined PY goto :nopython

echo [1/4] Python: %PY%
"%PY%" -c "import sys;print('      version '+sys.version.split()[0])"

rem ---------------------------------------------------------- dependencies
echo.
echo [2/4] Checking dependencies...
"%PY%" -c "import requests, keyring" >nul 2>&1
if errorlevel 1 "%PY%" -m pip install --disable-pip-version-check -q requests keyring
"%PY%" -c "import PyInstaller" >nul 2>&1
if errorlevel 1 "%PY%" -m pip install --disable-pip-version-check -q pyinstaller
echo       OK

rem ---------------------------------------------------------- build
echo.
echo [3/4] Building (first run takes 1-3 minutes)...
"%PY%" -m PyInstaller --noconfirm --clean build.spec
if errorlevel 1 goto :fail
if not exist "dist\CampusNet.exe" goto :fail

rem ---------------------------------------------------------- assemble
echo.
echo [4/4] Assembling release folder...
set "OUT=dist\CampusNet"
if not exist "%OUT%" mkdir "%OUT%"
copy /y "dist\CampusNet.exe" "%OUT%\CampusNet.exe" >nul
if not exist "%OUT%\config.ini" copy /y "config.example.ini" "%OUT%\config.ini" >nul
if exist "LICENSE" copy /y "LICENSE" "%OUT%\LICENSE.txt" >nul
rem copy any loose .txt (e.g. the Chinese readme) without naming it in this file
for %%f in (*.txt) do copy /y "%%f" "%OUT%\" >nul

echo.
echo ============================================================
echo   DONE
echo ============================================================
echo   Single file          : dist\CampusNet.exe
echo   Ready-to-send folder : %OUT%
for %%f in ("%OUT%\CampusNet.exe") do echo   CampusNet.exe size  : %%~zf bytes
echo.
echo   Send the whole folder above to your classmates.
echo   They double-click CampusNet.exe, fill in account / password,
echo   click the save button, then click the autostart button.
echo.
goto :end

:nopython
echo.
echo [ERROR] Python 3.11+ not found.
echo         Install it with:
echo             winget install --id Python.Python.3.12 --exact
exit /b 1

:try
if not defined PY if exist "%~1" set "PY=%~1"
goto :eof

:fail
echo.
echo [FAILED] See the messages above.
exit /b 1

:end
exit /b 0
