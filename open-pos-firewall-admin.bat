@echo off
set "SCRIPT=%~dp0start-lan-server.ps1"
powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath powershell.exe -Verb RunAs -ArgumentList '-NoProfile -ExecutionPolicy Bypass -NoExit -File ""%SCRIPT%"" -OpenFirewall -AllowPublicNetwork'"
