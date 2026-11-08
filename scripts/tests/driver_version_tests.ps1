# Offline source/version-resource checks; an optional SYS is read as a file only.
[CmdletBinding()]
param([string]$DriverPath)

$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$resource = Get-Content -Raw -Encoding UTF8 -LiteralPath (Join-Path $root 'driver\version.rc')
$inf = Get-Content -Raw -LiteralPath (Join-Path $root 'install\FirewallXNdisFilter.inf')
$script:passed = 0

function Assert-Version {
    param([bool]$Condition, [string]$Name)
    if (!$Condition) { throw "Driver version resource check failed: $Name" }
    ++$script:passed
    Write-Host "PASS $Name"
}

function Get-ResourceVersion {
    param([string]$Content)
    $version = $null
    foreach ($field in @('FILEVERSION', 'PRODUCTVERSION')) {
        $match = [regex]::Match($Content, "(?m)^[ \t]*$field[ \t]+(\d+),[ \t]*(\d+),[ \t]*(\d+),[ \t]*(\d+)[ \t]*\r?$")
        if (!$match.Success) { throw "Driver version resource check failed: missing or malformed $field" }
        $actual = (1..4 | ForEach-Object { $match.Groups[$_].Value }) -join '.'
        if ($null -eq $version) { $version = $actual }
        elseif ($actual -cne $version) { throw "Driver version resource check failed: $field differs from FILEVERSION" }
    }
    foreach ($field in @('FileVersion', 'ProductVersion')) {
        $match = [regex]::Match($Content, 'VALUE\s+"' + $field + '",\s*"([^"]+)"')
        if (!$match.Success -or $match.Groups[1].Value -cne $version) {
            throw "Driver version resource check failed: $field differs from FILEVERSION"
        }
    }
    return $version
}

function Assert-RejectedResourceVersion {
    param([string]$Content, [string]$Name)
    $rejected = $false
    try { $null = Get-ResourceVersion $Content }
    catch { $rejected = $true }
    Assert-Version $rejected $Name
}

$package = [regex]::Match($inf, '(?m)^DriverVer=[^,\r\n]+,(\d+\.\d+\.\d+\.\d+)\s*$')
Assert-Version $package.Success 'INF contains a four-part package version'
$version = Get-ResourceVersion $resource
Assert-Version ($null -ne $version) "resource numeric and string versions agree at $version"

# The resource version is independent of the package version. Verify that all
# four resource fields still agree for revision bumps and version transitions.
$fixture = @'
 FILEVERSION 0,3,3,1
 PRODUCTVERSION 0,3,3,1
 VALUE "FileVersion", "0.3.3.1"
 VALUE "ProductVersion", "0.3.3.1"
'@
Assert-Version ((Get-ResourceVersion $fixture) -ceq '0.3.3.1') 'resource accepts a nonzero revision'
$nextVersion = $fixture.Replace('0,3,3,1', '0,3,4,0').Replace('0.3.3.1', '0.3.4.0')
Assert-Version ((Get-ResourceVersion $nextVersion) -ceq '0.3.4.0') 'resource accepts a new version with revision zero'
Assert-RejectedResourceVersion ($fixture.Replace('PRODUCTVERSION 0,3,3,1', 'PRODUCTVERSION 0,3,3,2')) 'numeric product version mismatch is rejected'
Assert-RejectedResourceVersion ($fixture.Replace('"FileVersion", "0.3.3.1"', '"FileVersion", "0.3.3.2"')) 'string file version mismatch is rejected'
Assert-RejectedResourceVersion ($fixture.Replace('"ProductVersion", "0.3.3.1"', '"ProductVersion", "0.3.3.2"')) 'string product version mismatch is rejected'
Assert-RejectedResourceVersion ($fixture.Replace('FILEVERSION 0,3,3,1', 'FILEVERSION 0,3,3')) 'malformed numeric file version is rejected'
$strings = @{
    Comments = 'https://github.com/GerardoKermitToy/FirewallXNdisFilter'
    FileDescription = [regex]::Match($inf, '(?m)^Description="([^"]+)"').Groups[1].Value
    FileVersion = $version
    InternalName = 'FirewallXNdisFilter'
    LegalCopyright = 'skrudjmdk (https://forum.ru-board.com/profile.cgi?action=show&member=skrudjmdk)'
    OriginalFilename = 'FirewallXNdisFilter.sys'
    ProductName = 'FirewallXNdisFilter'
    ProductVersion = $version
}
Assert-Version (![regex]::IsMatch($resource, '(?i)\bVALUE\s+"CompanyName"')) 'resource has no CompanyName'
foreach ($name in $strings.Keys) {
    $match = [regex]::Match($resource, 'VALUE\s+"' + $name + '",\s*"([^"]+)"')
    Assert-Version ($match.Success -and $match.Groups[1].Value -ceq $strings[$name]) "resource $name"
}
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILETYPE\s+VFT_DRV\s*$')) 'resource type is VFT_DRV'
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILESUBTYPE\s+VFT2_DRV_NETWORK\s*$')) 'resource subtype is VFT2_DRV_NETWORK'
Assert-Version ([regex]::IsMatch($resource, '(?m)^\s*FILEFLAGS\s+0\s*$')) 'resource has Release flags'
Assert-Version ([regex]::IsMatch($resource, 'VALUE\s+"Translation",\s*0x0409,\s*1200')) 'resource translation is US English/Unicode'

if ($DriverPath) {
    $path = (Resolve-Path -LiteralPath $DriverPath).Path
    $info = [System.Diagnostics.FileVersionInfo]::GetVersionInfo($path)
    $fileVersion = @($info.FileMajorPart, $info.FileMinorPart, $info.FileBuildPart, $info.FilePrivatePart) -join '.'
    $productVersion = @($info.ProductMajorPart, $info.ProductMinorPart, $info.ProductBuildPart, $info.ProductPrivatePart) -join '.'
    Assert-Version ($fileVersion -ceq $version) 'SYS numeric file version'
    Assert-Version ($productVersion -ceq $version) 'SYS numeric product version'
    Assert-Version ([string]::IsNullOrEmpty($info.CompanyName)) 'SYS has no CompanyName'
    foreach ($name in $strings.Keys) {
        Assert-Version ($info.$name -ceq $strings[$name]) "SYS $name"
    }
    Assert-Version (!($info.IsDebug -or $info.IsPreRelease -or $info.IsPatched -or $info.IsPrivateBuild -or $info.IsSpecialBuild)) 'SYS has Release flags'
}
Write-Host "PASS $script:passed driver version checks (no installation, device open or driver loading)."
