@echo off
REM Shadow9 Manager - Main Control Script (Windows)
REM Manage users, start server, and test connections

setlocal EnableDelayedExpansion

cd /d "%~dp0"

REM Load environment variables from .env
if exist ".env" (
    for /f "tokens=1,2 delims==" %%a in ('type .env ^| findstr /v "^#"') do (
        set "%%a=%%b"
    )
)

REM Check if virtual environment exists
if not exist "venv" (
    echo ERROR: Virtual environment not found.
    echo Please run setup.bat first.
    exit /b 1
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Handle test command
if "%1"=="test" (
    echo ================================================================
    echo               Shadow9 Connection Test
    echo ================================================================
    echo.
    
    set HOST=127.0.0.1
    set PORT=1080
    
    REM Parse arguments
    set ARGS=%*
    shift
    
    :parse_args
    if "%1"=="" goto :run_test
    if "%1"=="--host" (
        set HOST=%2
        shift
        shift
        goto :parse_args
    )
    if "%1"=="--port" (
        set PORT=%2
        shift
        shift
        goto :parse_args
    )
    if "%1"=="--user" (
        set TEST_USER=%2
        shift
        shift
        goto :parse_args
    )
    if "%1"=="--pass" (
        set TEST_PASS=%2
        shift
        shift
        goto :parse_args
    )
    shift
    goto :parse_args
    
    :run_test
    REM Prompt for credentials if not provided
    if not defined TEST_USER (
        set /p TEST_USER="Username: "
    )
    if not defined TEST_PASS (
        set /p TEST_PASS="Password: "
    )
    
    echo.
    echo Testing connection to %HOST%:%PORT%...
    echo.
    
    python -c "import asyncio; import sys; sys.path.insert(0, 'src'); from shadow9.socks5_client import Socks5Client, ProxyConfig, Socks5ConnectionError, Socks5AuthError; proxy = ProxyConfig(host='%HOST%', port=%PORT%, username='%TEST_USER%', password='%TEST_PASS%', timeout=10.0); client = Socks5Client(proxy); asyncio.run(client.connect('httpbin.org', 80)); print('  Connection successful!'); asyncio.run(client.close())" 2>nul
    
    if errorlevel 1 (
        echo   Connection test FAILED
        echo.
        echo   Make sure:
        echo   1. The server is running: shadow9.bat serve
        echo   2. Username and password are correct
    ) else (
        echo.
        echo ================================================================
        echo                     TEST PASSED
        echo ================================================================
    )
    
    exit /b
)

REM Show banner for certain commands
if "%1"=="" (
    echo ================================================================
    echo                    Shadow9 Manager
    echo          Secure SOCKS5 Proxy with Tor Support
    echo ================================================================
    echo.
)

REM Pass all arguments to the Python CLI
python -m shadow9 %*
