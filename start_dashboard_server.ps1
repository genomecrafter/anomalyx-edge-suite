param(
    [int]$Port = 8600
)

Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
python dashboard_server.py --port $Port
