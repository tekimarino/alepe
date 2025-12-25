@echo off
setlocal
cd /d %~dp0

REM Port par défaut pour Alépé (évite le conflit avec 5000)
REM Tu peux lancer avec:  run_windows.bat 5002
set PORT=%1
if "%PORT%"=="" set PORT=5001

if not exist .venv (
  python -m venv .venv
)

call .venv\Scripts\activate
pip install -r requirements.txt
python run.py
