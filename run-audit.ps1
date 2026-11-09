<#
.SYNOPSIS
  Read-only mailbox audit: export -> local classification -> report.
  The IMAP password is typed into a hidden prompt (getpass) and is never stored, logged or passed as an argument.
.EXAMPLE
  .\run-audit.ps1 -TestConnection
  .\run-audit.ps1
  .\run-audit.ps1 -Llm ollama -Model qwen2.5:7b-instruct
#>
param(
    [string]$User,
    [switch]$TestConnection,
    [ValidateSet("off", "ollama", "openai")][string]$Llm = "off",
    [string]$Model = "qwen2.5:7b-instruct",
    [string]$LlmUrl,
    [int]$LlmMax = 300,
    [int]$Limit = 0,
    [switch]$ExcludeTrashJunk
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot
$py = if (Get-Command py -ErrorAction SilentlyContinue) { @("py", "-3") } else { @("python") }
function Run-Py([string[]]$PyArgs) {
    & $py[0] @($py | Select-Object -Skip 1) @PyArgs
    if ($LASTEXITCODE -ne 0) { throw "Step failed (exit $LASTEXITCODE)" }
}

if (-not $User) { $User = Read-Host "Full email address" }
New-Item -ItemType Directory -Force reports, logs | Out-Null

$audit = @("scripts\imap_audit.py", "--user", $User, "--output", "reports\mailbox-audit.jsonl")
if ($TestConnection) {
    Run-Py ($audit + "--test-connection")
    return
}
if (-not $ExcludeTrashJunk) { $audit += "--include-trash-junk" }
if ($Limit -gt 0) { $audit += @("--limit", $Limit) }

Write-Host "`n[1/3] Read-only export (EXAMINE + BODY.PEEK). Type the password when prompted."
Run-Py $audit

Write-Host "`n[2/3] Local classification (no data leaves the machine)"
$cls = @("scripts\classify.py", "--input", "reports\mailbox-audit.jsonl", "--output", "reports\classified.jsonl", "--llm", $Llm)
if ($Llm -ne "off") { $cls += @("--llm-model", $Model, "--llm-max", $LlmMax) }
if ($LlmUrl) { $cls += @("--llm-url", $LlmUrl) }
Run-Py $cls

Write-Host "`n[3/3] Report"
Run-Py @("scripts\report.py", "--classified", "reports\classified.jsonl")

Write-Host "`nDone. Open reports\report.md and reports\candidates.csv yourself. Nothing in the mailbox was changed."
