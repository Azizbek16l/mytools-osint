#requires -Version 5.1
<#
.SYNOPSIS
  Register a Windows Scheduled Task that runs the Bluetm Agent locally once
  per day. Run this on the machine where `claude login` was completed so the
  Claude Code OAuth token is available for agent/tasks/claude_improvements.py.

  Defaults assume the standard rootpc layout used by Mars IT:
    D:\Code\mytools\.venv\Scripts\python.exe -m agent.main

.PARAMETER Hour
  Hour of day to run (24h, local time). Default 03.

.EXAMPLE
  pwsh .\scripts\install_local_agent.ps1
  pwsh .\scripts\install_local_agent.ps1 -Hour 5

.NOTES
  Requires Administrator only if -SystemUser is used. Default runs as the
  current user, which is correct so the user's Claude Code OAuth token works.
#>
param(
    [int]$Hour = 3
)

$ErrorActionPreference = "Stop"

$repo = (Resolve-Path "$PSScriptRoot\..").Path
$python = Join-Path $repo ".venv\Scripts\python.exe"
if (-not (Test-Path $python)) {
    Write-Error "Python venv not found at $python — run 'python -m venv .venv && pip install -r requirements.txt' first."
}

$taskName = "BluetmAgentDaily"
$action = New-ScheduledTaskAction `
    -Execute $python `
    -Argument "-m agent.main" `
    -WorkingDirectory $repo

$trigger = New-ScheduledTaskTrigger -Daily -At ([datetime]("{0:D2}:00" -f $Hour))

$settings = New-ScheduledTaskSettingsSet `
    -StartWhenAvailable `
    -DontStopOnIdleEnd `
    -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
    -MultipleInstances IgnoreNew

$principal = New-ScheduledTaskPrincipal `
    -UserId $env:USERNAME `
    -LogonType S4U `
    -RunLevel Limited

Register-ScheduledTask `
    -TaskName $taskName `
    -Action $action `
    -Trigger $trigger `
    -Settings $settings `
    -Principal $principal `
    -Description "Bluetm Agent — daily maintenance for mytools-osint" `
    -Force | Out-Null

Write-Host "✓ Scheduled task '$taskName' registered." -ForegroundColor Green
Write-Host "  Repo:      $repo"
Write-Host "  Python:    $python"
Write-Host "  Schedule:  daily at $("{0:D2}:00" -f $Hour) local time"
Write-Host ""
Write-Host "Run once now (sanity check):"
Write-Host "  Start-ScheduledTask -TaskName $taskName"
Write-Host ""
Write-Host "Inspect last run:"
Write-Host "  Get-ScheduledTaskInfo -TaskName $taskName"
Write-Host ""
Write-Host "Uninstall:"
Write-Host "  Unregister-ScheduledTask -TaskName $taskName -Confirm:`$false"
