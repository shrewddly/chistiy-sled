@echo off
chcp 65001 >nul
cd /d "%~dp0"
set "PY=C:\Users\Arlen\AppData\Local\Programs\Python\Python312\python.exe"
if not exist "%PY%" set "PY=python"
"%PY%" check_password.py
pause
