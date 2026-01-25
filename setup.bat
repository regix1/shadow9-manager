@echo off
REM Shadow9 Manager - Initial Setup Script (Windows)
REM This script sets up the environment and creates the first user

setlocal EnableDelayedExpansion

echo.
echo ================================================================
echo                   Shadow9 Manager Setup
echo          Secure SOCKS5 Proxy with Tor Support
echo ================================================================
echo.

cd /d "%~dp0"

REM Check Python version
echo [1/5] Checking Python version...
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
echo [2/5] Setting up virtual environment...
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
echo [3/5] Installing dependencies...
pip install --upgrade pip -q
pip install -e . -q
echo       Dependencies installed

REM Create config directory
if not exist "config" mkdir config

REM Generate master key
echo.
echo [4/5] Generating encryption key...

REM Generate a random key using Python
for /f "delims=" %%k in ('python -c "import secrets; print(secrets.token_urlsafe(32))"') do set MASTER_KEY=%%k

REM Save to .env file
echo # Shadow9 Master Key - Keep this secret! > .env
echo # This key encrypts your credentials file >> .env
echo SHADOW9_MASTER_KEY=%MASTER_KEY% >> .env

echo       Master key generated and saved to .env
echo       IMPORTANT: Keep this key safe!

REM Set the environment variable for this session
set SHADOW9_MASTER_KEY=%MASTER_KEY%

REM Create first user
echo.
echo [5/5] Creating your first user...
echo.

python -c "import os; import sys; sys.path.insert(0, 'src'); from pathlib import Path; from shadow9.auth import AuthManager; auth = AuthManager(credentials_file=Path('config/credentials.enc'), master_key=os.environ.get('SHADOW9_MASTER_KEY')); username, password = auth.generate_credentials(); auth.add_user(username, password, use_tor=True); print(f'\n================================================================'); print(f'                    Your Credentials'); print(f'================================================================'); print(f'  Username: {username}'); print(f'  Password: {password}'); print(f'================================================================'); print(f'  WARNING: SAVE THESE NOW! They will not be shown again.'); print(f'================================================================\n')"

echo.
echo ================================================================
echo                     Setup Complete!
echo ================================================================
echo.
echo   Next steps:
echo.
echo   1. Start the server:
echo      shadow9.bat serve
echo.
echo   2. Configure your app to use SOCKS5 proxy:
echo      Host: 127.0.0.1
echo      Port: 1080
echo      Auth: Use the credentials above
echo.
echo   For more options:
echo      shadow9.bat --help
echo.
echo ================================================================

pause
