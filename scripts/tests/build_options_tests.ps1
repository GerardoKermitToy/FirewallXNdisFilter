# Offline tests: evaluate only parameters and signing arguments, never build actions.
$ErrorActionPreference = 'Stop'
$buildScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'Build.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($buildScript, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count -ne 0 -or $null -eq $ast.ParamBlock) { throw 'Build.ps1 parameter parsing failed.' }
$probe = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" + '$PfxPassword')
$timestampProbe = [scriptblock]::Create($ast.ParamBlock.Extent.Text + "`n" + '$TimestampUrl')
$oldPassword = $env:FIREWALLXNDISFILTER_PFX_PASSWORD
$script:passed = 0

function Test-Password {
    param([string]$Name, [string]$EnvironmentPassword, [hashtable]$Arguments, [string]$Expected)
    $env:FIREWALLXNDISFILTER_PFX_PASSWORD = $EnvironmentPassword
    $actual = & $probe @Arguments
    if ($actual -cne $Expected) { throw "Unexpected password selection: $Name" }
    ++$script:passed
    Write-Host "PASS $Name"
}

try {
    Test-Password 'default without an environment password' $null @{} '1'
    Test-Password 'environment overrides the default' 'environment-fixture' @{} 'environment-fixture'
    Test-Password 'explicit argument overrides environment' 'environment-fixture' @{ PfxPassword = 'argument-fixture' } 'argument-fixture'
    Test-Password 'explicit empty argument overrides environment' 'environment-fixture' @{ PfxPassword = '' } ''
    Test-Password 'explicit empty argument overrides default' $null @{ PfxPassword = '' } ''
    Test-Password 'zero is a nonempty environment password' '0' @{} '0'
    Test-Password 'whitespace is preserved when explicitly configured' ' ' @{} ' '
    Test-Password 'a PFX path does not change the default or open a file' $null @{ PfxPath = 'never-opened-by-parser.pfx' } '1'
    foreach ($case in @(
        @{ Name = 'timestamp service defaults to DigiCert'; Arguments = @{}; Expected = 'http://timestamp.digicert.com' },
        @{ Name = 'timestamp service can be overridden'; Arguments = @{ TimestampUrl = 'https://tsa.example.test' }; Expected = 'https://tsa.example.test' }
    )) {
        $arguments = $case.Arguments
        $actual = & $timestampProbe @arguments
        if ($actual -cne $case.Expected) { throw "Unexpected timestamp selection: $($case.Name)" }
        ++$script:passed
        Write-Host "PASS $($case.Name)"
    }
    foreach ($invalidUrl in @('', $null)) {
        $rejected = $false
        try { & $timestampProbe -TimestampUrl $invalidUrl | Out-Null }
        catch [System.Management.Automation.ParameterBindingException] { $rejected = $true }
        if (!$rejected) { throw 'Empty/null timestamp URL was accepted.' }
        ++$script:passed
        Write-Host 'PASS empty/null timestamp URL is rejected without a request'
    }
    $assignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$signArgs'
    }, $true)
    if ($null -eq $assignment) { throw 'Signing argument assignment not found.' }
    $TimestampUrl = 'https://tsa.example.test'
    $signArgs = & ([scriptblock]::Create($assignment.Right.Extent.Text))
    $expectedArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
    if (($signArgs -join "`0") -cne ($expectedArgs -join "`0")) { throw 'RFC 3161/SHA-256 signing arguments differ.' }
    ++$script:passed
    Write-Host 'PASS all signing uses RFC 3161 with SHA-256 and the selected URL'

    $rustFlagsAssignment = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.AssignmentStatementAst] -and
            $node.Left.Extent.Text -eq '$env:RUSTFLAGS'
    }, $true)
    if ($null -eq $rustFlagsAssignment) { throw 'Driver Rust flags assignment not found.' }
    $rustFlags = & ([scriptblock]::Create($rustFlagsAssignment.Right.Extent.Text))
    if ($rustFlags -notmatch '(?:^|\s)-C\s+target-feature=\+sse4\.2(?:\s|$)') {
        throw 'Driver Rust flags do not enable SSE4.2 for the complete Cargo target build.'
    }
    if ($rustFlags -match '(?i)target-cpu\s*=\s*native|target-feature=\S*\+avx') {
        throw 'Driver Rust flags enable the build machine CPU or AVX.'
    }
    ++$script:passed
    Write-Host 'PASS driver target build enables SSE4.2 without native CPU or AVX'

    $linkCommand = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.CommandAst] -and
            $node.GetCommandName() -eq 'link.exe'
    }, $true)
    if ($null -eq $linkCommand -or $linkCommand.Extent.Text -notmatch '(?i)/ENTRY:FwxCpuCheckedEntry(?:\s|$)') {
        throw 'The SYS entry does not point to the baseline CPU check.'
    }
    ++$script:passed
    Write-Host 'PASS SYS link uses the CPU-checked entry'

    $guard = $ast.Find({
        param($node)
        $node -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
            $node.Name -eq 'Assert-NoLegacyPackageFiles'
    }, $true)
    if ($null -eq $guard) { throw 'Legacy package guard not found.' }
    . ([scriptblock]::Create($guard.Extent.Text))
    $fixtureDir = Join-Path ([IO.Path]::GetTempPath()) ('firewallx-build-guard-' + [guid]::NewGuid())
    New-Item -ItemType Directory -Path $fixtureDir | Out-Null
    try {
        Assert-NoLegacyPackageFiles $fixtureDir
        foreach ($name in @('HyperVXNdisFilter.inf', 'HyperVGuard.sys', 'hyperv_monitor.exe',
                            'firewallx_monitor.exe', 'firewallx_monitor.pdb')) {
            $fixture = Join-Path $fixtureDir $name
            Set-Content -LiteralPath $fixture -Value 'legacy fixture'
            $rejected = $false
            try { Assert-NoLegacyPackageFiles $fixtureDir }
            catch { $rejected = $true }
            if (!$rejected -or !(Test-Path -LiteralPath $fixture)) {
                throw "Legacy artifact was not safely rejected: $name"
            }
            Remove-Item -LiteralPath $fixture
            ++$script:passed
            Write-Host "PASS preserves and rejects legacy artifact $name"
        }
        foreach ($name in @('FirewallXNdisFilter.inf', 'ndis_monitor.exe', 'ndis_monitor.pdb')) {
            Set-Content -LiteralPath (Join-Path $fixtureDir $name) -Value 'current fixture'
        }
        Assert-NoLegacyPackageFiles $fixtureDir
        ++$script:passed
        Write-Host 'PASS accepts current product artifacts'
    } finally {
        Remove-Item -LiteralPath $fixtureDir -Recurse -Force
    }
    Write-Host "PASS $script:passed build option cases (no compiler, signing tool, key, TSA or driver access)."
} finally {
    $env:FIREWALLXNDISFILTER_PFX_PASSWORD = $oldPassword
}
