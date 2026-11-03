@echo off
REM Launches the starkscan GUI.
REM
REM -STA is required: Windows Forms needs a single-threaded apartment.
REM -ExecutionPolicy Bypass applies to this one process only; it does not
REM change any machine or user policy setting.
powershell.exe -NoProfile -NoLogo -STA -ExecutionPolicy Bypass -File "%~dp0starkscan-gui.ps1" %*
if errorlevel 1 pause
