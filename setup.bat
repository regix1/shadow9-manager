@echo off
REM Shadow9 Manager - Initial Setup Script (Windows)
REM This script sets up the environment

setlocal EnableDelayedExpansion

echo.
echo ================================================================
echo                   Shadow9 Manager Setup
echo          Secure SOCKS5 Proxy with Tor Support
echo ================================================================
echo.

cd /d "%~dp0"

REM Check Python version
echo [1/4] Checking Python version...
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is required but not found.
    echo Please install Python 3.10+ from https://www.python.org/downloads/
    pause
    exit /b 1
)

for /f "tokens=2 delims= " %%v in ('python --version 2^>^&1') do set PYTHON_VER=%%v
echo       Python %PYTHON_VER% found

REM Create virtual environment
echo.
echo [2/4] Setting up virtual environment...
if not exist "venv" (
    python -m venv venv
    echo       Virtual environment created
) else (
    echo       Virtual environment already exists
)

REM Activate virtual environment
call venv\Scripts\activate.bat

REM Install dependencies
echo.
echo [3/4] Installing dependencies...
pip install --upgrade pip -q
pip install -e . -q
echo       Dependencies installed

REM Create config directory
if not exist "config" mkdir config

REM Generate master key
echo.
echo [4/4] Generating encryption key...

REM Check if .env already exists
if exist ".env" (
    echo       Using existing master key from .env
) else (
    REM Generate a random key using Python
    for /f "delims=" %%k in ('python -c "import secrets; print(secrets.token_urlsafe(32))"') do set MASTER_KEY=%%k

    REM Save to .env file
    echo # Shadow9 Master Key - Keep this secret! > .env
    echo # This key encrypts your credentials file >> .env
    echo SHADOW9_MASTER_KEY=!MASTER_KEY! >> .env

    echo       Master key generated and saved to .env
)

echo.
echo ================================================================
echo                     Setup Complete!
echo ================================================================
echo.
echo   Next steps:
echo.
echo   1. Create a user:
echo      shadow9.bat user generate
echo.
echo   2. Start the server:
echo      shadow9.bat serve
echo.
echo   3. Connect your app (SOCKS5 proxy):
echo      Host: 0.0.0.0    Port: 1080
echo.
echo   For more options: shadow9.bat --help
echo.
echo ================================================================

pause
