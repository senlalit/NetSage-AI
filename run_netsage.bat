@echo off
setlocal
cd /d "%~dp0"

if not exist ".venv\Scripts\python.exe" (
    echo [ERROR] .venv was not found.
    echo Create it with: py -m venv .venv
    exit /b 1
)

echo Starting NetSage AI on http://localhost:8501
".venv\Scripts\python.exe" -m streamlit run app.py --server.headless true --server.port 8501
