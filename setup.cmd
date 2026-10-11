@echo off
rem Double-click to install Strata. Finds Python 3.10+ and runs setup.py next to this file.
setlocal
cd /d "%~dp0"
where py >nul 2>nul && (py -3 setup.py %* & goto :end)
where python >nul 2>nul && (python setup.py %* & goto :end)
echo Python 3.10 or newer is required: https://www.python.org/downloads/
echo Tick "Add python.exe to PATH" in the installer, then run this again.
pause
:end
