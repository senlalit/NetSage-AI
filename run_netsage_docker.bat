@echo off
setlocal
cd /d "%~dp0"

where docker >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Docker is not installed or not on PATH.
    exit /b 1
)

docker compose up --build
