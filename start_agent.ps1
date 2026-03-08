param(
    [string]$AgentId = "win-vm-001",
    [string]$RelayUrl = "http://localhost:8600"
)

Set-Location (Split-Path -Parent $MyInvocation.MyCommand.Path)
python agent_runner.py --agent-id $AgentId --relay-url $RelayUrl
