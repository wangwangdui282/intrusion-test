@echo off
setlocal EnableDelayedExpansion
chcp 65001 >nul
cd /d "%~dp0"

set "PORT=8080"
set "PY=%~dp0runtime\python\python.exe"
if not exist "%PY%" set "PY=python"

REM ---- Agnes test API key ----
REM 出于安全考虑，此处不再内置任何密钥；需要跑 AI 用例时请先设置环境变量：
REM     set AGNES_TEST_API_KEY=<你的测试key>
if not defined AGNES_TEST_API_KEY (
    echo      AGNES_TEST_API_KEY not set, AI cases will be skipped.
)

echo ============================================================
echo  Intrusion Test - one click API test runner
echo  Project: %~dp0
echo  Python : %PY%
echo ============================================================

REM ---- 1. check if service already listening ----
set "ALREADY=0"
netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul
if !errorlevel!==0 set "ALREADY=1"

if "!ALREADY!"=="1" (
    echo [1/4] Service already running on port %PORT%, reuse it.
) else (
    echo [1/4] Starting service: %PY% app\run.py
    start "intrusion-server" /min "%PY%" "app\run.py"
)

REM ---- 2. wait until port is ready (max 30s) ----
echo [2/4] Waiting for http://127.0.0.1:%PORT% ...
set "READY=0"
for /l %%i in (1,1,30) do (
    if "!READY!"=="0" (
        netstat -ano | findstr ":%PORT%" | findstr "LISTENING" >nul
        if !errorlevel!==0 (
            set "READY=1"
        ) else (
            timeout /t 1 >nul
        )
    )
)

if "!READY!"=="0" (
    echo.
    echo [FAIL] Service did not start within 30s.
    echo        Check: runtime\python\python.exe exists and dependencies installed.
    exit /b 1
)
echo      Service is up.

REM ---- 3. run pytest with the SAME python as the service ----
echo [3/4] Running test suite...
echo.
"%PY%" -m pytest test_api.py -v
set "RC=!errorlevel!"
echo.

REM ---- 4. stop the service if we started it ----
if "!ALREADY!"=="0" (
    echo [4/4] Stopping service...
    for /f "tokens=5" %%P in ('netstat -ano ^| findstr ":%PORT%" ^| findstr "LISTENING"') do (
        taskkill /F /PID %%P >nul 2>&1
    )
) else (
    echo [4/4] Service was already running, leave it alone.
)

echo.
if "!RC!"=="0" (
    echo RESULT: ALL TESTS PASSED
) else (
    echo RESULT: TESTS FAILED  (exit code !RC!)
)

REM ---- keep the window open so user can read / screenshot ----
echo.
echo ============================================================
echo  Test run finished. Keep this window open.
echo  Press any key to close it.
echo ============================================================
pause >nul
exit /b !RC!
