Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)

pyinstaller --onefile --name EdgeAgentStandalone agent_runner.py
pyinstaller --onefile --name EdgeDashboardRelay dashboard_server.py

Write-Host "Build complete:"
Write-Host "  edge-suite/dist/EdgeAgentStandalone.exe"
Write-Host "  edge-suite/dist/EdgeDashboardRelay.exe"
