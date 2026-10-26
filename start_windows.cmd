@echo off
cd /d "%~dp0"
py -3.12 server.py
if errorlevel 1 (
  echo.
  echo Confirm Python 3.12 is installed. If port 8830 is busy, run: set RULE_WORKBENCH_PORT=8831
  pause
)
