param([Parameter(Mandatory=$true)][string]$DriverPath)
$ErrorActionPreference = 'Stop'

$output = & dumpbin.exe /imports $DriverPath 2>&1
if ($LASTEXITCODE -ne 0) { throw "Cannot inspect driver imports: $DriverPath" }
$modules = @([regex]::Matches(($output -join "`n"), '(?im)^\s+([^\s]+\.(?:sys|dll|exe))\s*$') |
    ForEach-Object { $_.Groups[1].Value.ToLowerInvariant() } | Sort-Object -Unique)
# HAL.dll is a kernel module despite its suffix. User-mode WFP/CRT imports are not.
$allowed = @('ntoskrnl.exe', 'hal.dll', 'ndis.sys', 'netio.sys', 'fwpkclnt.sys')
$unexpected = @($modules | Where-Object { $_ -notin $allowed })
if ($modules.Count -eq 0 -or $unexpected.Count -ne 0) {
    throw ('Invalid kernel imports: ' + ($modules -join ', '))
}
Write-Host ('Kernel import verification passed: ' + ($modules -join ', '))
