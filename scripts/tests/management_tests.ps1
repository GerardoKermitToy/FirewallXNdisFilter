# Offline tests for the deliberately disabled legacy management scripts.
$ErrorActionPreference = 'Stop'
$script:passed = 0
$root = Split-Path $PSScriptRoot -Parent

function Assert-True {
    param([bool]$Condition, [string]$Message = 'Assertion failed')
    if (!$Condition) { throw $Message }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Text)
    $caught = $null
    try { & $Action } catch { $caught = $_.Exception.Message }
    Assert-True ($null -ne $caught -and $caught.Contains($Text)) "Expected '$Text', got '$caught'."
}
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    & $Action
    ++$script:passed
    Write-Host "PASS $Name"
}

# Guard against accidental network/registry operations if either retired script
# changes. Test the unchanged body without its administrator requirement so this
# no-driver test remains runnable in an unelevated shell.
function Get-NetAdapterBinding { throw 'Unexpected network query' }
function Enable-NetAdapterBinding { throw 'Unexpected binding change' }
function Disable-NetAdapterBinding { throw 'Unexpected binding change' }
function New-ItemProperty { throw 'Unexpected registry change' }
$bindingSource = (Get-Content -LiteralPath (Join-Path $root 'Set-Binding.ps1') -Raw) -replace '(?m)^#Requires[^\r\n]*(\r?\n|$)', ''
$binding = [scriptblock]::Create($bindingSource)

Test-Case 'obsolete binding enable refuses without system changes' {
    Assert-Throws { & $binding -Enable } 'no longer supported'
}
Test-Case 'obsolete binding disable refuses without system changes' {
    Assert-Throws { & $binding -Disable } 'no longer supported'
}
Test-Case 'obsolete switch script cannot mutate any switch' {
    Assert-Throws { & (Join-Path $root 'Set-Extension.ps1') -SwitchName 'Default Switch' -Enable } 'not a vSwitch extension'
}
Test-Case 'all management scripts parse on Windows PowerShell' {
    Get-ChildItem $root -Filter *.ps1 -Recurse | ForEach-Object {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "Parse errors in $($_.Name): $errors"
    }
}
Write-Host "$script:passed management tests passed (no driver, registry or network changes)."
