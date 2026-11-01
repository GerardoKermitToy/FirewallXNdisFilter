# Offline tests: every network/registry function used by helpers is mocked.
$ErrorActionPreference = 'Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'HyperVXNdisFilter.Common.ps1')
$script:passed = 0
$script:fixtureSwitchId = [guid]'10000000-0002-0003-0405-060708090a0b'
$targetGuid = [guid]'9eb6ca05-3905-4420-a34f-4fa09dcc6a2d'
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
function Get-HnsNetwork { [CmdletBinding()] param() $script:networks }
function Get-VMSwitch { [CmdletBinding()] param() $script:switches }
function Get-VMNetworkAdapter {
    [CmdletBinding()] param([switch]$ManagementOS)
    Assert-True ([bool]$ManagementOS) 'Guest adapters must not be queried.'
    $script:vnics
}
function Get-NetAdapter {
    [CmdletBinding()] param([switch]$IncludeHidden)
    Assert-True ([bool]$IncludeHidden)
    $script:adapters
}
function Get-NetAdapterBinding {
    [CmdletBinding()] param([string]$Name, [switch]$IncludeHidden, [switch]$AllBindings)
    Assert-True ($Name -eq '*' -and $IncludeHidden -and $AllBindings)
    $script:bindings
}
function Get-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath)
    Assert-True ($LiteralPath -eq $script:HyperVXNdisFilterConfigPath)
    [pscustomobject]$script:config
}
function New-Item {
    [CmdletBinding()] param([string]$Path, [switch]$Force)
    Assert-True ($Path -eq $script:HyperVXNdisFilterConfigPath -and $Force)
}
function New-ItemProperty {
    [CmdletBinding()] param([string]$LiteralPath, [string]$Name, [string]$PropertyType, [object]$Value, [switch]$Force)
    Assert-True ($LiteralPath -eq $script:HyperVXNdisFilterConfigPath -and $Force)
    $script:writes += "$Name/$PropertyType"
    $script:config[$Name] = $Value
}
function Reset-Fixtures {
    $script:networks = @([pscustomobject]@{ Name = 'Default Switch'; Type = 'ICS'; ID = $script:fixtureSwitchId; SwitchGuid = $script:fixtureSwitchId })
    $script:switches = @([pscustomobject]@{ Id = $script:fixtureSwitchId; Name = 'Default Switch' })
    $script:vnics = @([pscustomobject]@{ IsManagementOs = $true; SwitchId = $script:fixtureSwitchId; DeviceId = $targetGuid.ToString('B') })
    $script:adapters = @(
        [pscustomobject]@{ Name = 'vEthernet (Default Switch)'; InterfaceGuid = $targetGuid; NetLuid = [uint64]1689399750295552; Virtual = $true; HardwareInterface = $false; InterfaceType = 6 },
        [pscustomobject]@{ Name = 'Ethernet'; InterfaceGuid = [guid]::NewGuid(); NetLuid = [uint64]10; Virtual = $false; HardwareInterface = $true; InterfaceType = 6 }
    )
    $script:bindings = @(
        [pscustomobject]@{ Name = 'vEthernet (Default Switch)'; ComponentID = 'hyperv_xndis_filter'; Enabled = $false },
        [pscustomobject]@{ Name = 'Ethernet'; ComponentID = 'hyperv_xndis_filter'; Enabled = $false },
        [pscustomobject]@{ Name = 'Ethernet'; ComponentID = 'ms_tcpip'; Enabled = $true }
    )
    $script:config = @{ ConfigVersion = 3; TargetAdapters = (ConvertTo-HyperVXNdisFilterTargets -Adapters @($script:adapters[0])); AllowBindings = 0 }
    $script:writes = @()
}
function Test-Case {
    param([string]$Name, [scriptblock]$Action)
    Reset-Fixtures
    & $Action
    ++$script:passed
    Write-Host "PASS $Name"
}

Test-Case 'resolve actual management vNIC by Default Switch ID and interface GUID' {
    Assert-True ((Resolve-HyperVXNdisFilterAdapters).InterfaceGuid -eq $targetGuid)
}
Test-Case 'adapter alias is not an authorization identity' {
    $script:adapters[0].Name = 'Renamed host vNIC'
    Assert-True ((Resolve-HyperVXNdisFilterAdapters).Name -eq 'Renamed host vNIC')
}
Test-Case 'a matching display name on the wrong switch is rejected' {
    $script:switches[0].Id = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'switch is missing'
}
Test-Case 'an absent referenced ICS switch is rejected' {
    $script:switches = @()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'switch is missing'
}
Test-Case 'duplicate management vNIC identity is rejected' {
    $script:vnics += $script:vnics[0]
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'identities are ambiguous'
}
Test-Case 'guest vNIC cannot be selected' {
    $script:vnics[0].IsManagementOs = $false
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'Expected a management-OS vNIC'
}
Test-Case 'unrelated switch management vNIC cannot be selected' {
    $script:vnics[0].SwitchId = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'Expected a management-OS vNIC'
}
Test-Case 'invalid management device GUID is rejected' {
    $script:vnics[0].DeviceId = 'not-a-guid'
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'no valid interface GUID'
}
Test-Case 'same alias cannot substitute a different interface GUID' {
    $script:adapters[0].InterfaceGuid = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'exact host adapter was not found'
}
Test-Case 'physical adapter cannot be selected' {
    $script:adapters[0].HardwareInterface = $true
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'not an Ethernet host vNIC'
}
Test-Case 'nonvirtual adapter cannot be selected' {
    $script:adapters[0].Virtual = $false
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'not an Ethernet host vNIC'
}
Test-Case 'non-Ethernet adapter cannot be selected' {
    $script:adapters[0].InterfaceType = 71
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'not an Ethernet host vNIC'
}
Test-Case 'missing NET_LUID cannot be selected' {
    $script:adapters[0].NetLuid = 0
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'not an Ethernet host vNIC'
}
Test-Case 'only own-component bindings are enumerated' {
    Assert-True (@(Get-HyperVXNdisFilterBindings).Count -eq 2)
}
Test-Case 'disabled foreign bindings do not get enabled or edited' {
    $binding = Assert-HyperVXNdisFilterBindingScope -Adapters @($script:adapters[0]) -AllDisabled
    Assert-True ($binding.Name -eq $script:adapters[0].Name -and $script:writes.Count -eq 0)
    Assert-True (!$script:bindings[1].Enabled -and $script:bindings[2].Enabled)
}
Test-Case 'foreign enabled binding causes abort instead of editing that adapter' {
    $script:bindings[1].Enabled = $true
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapters @($script:adapters[0]) } 'unexpectedly enabled binding'
    Assert-True ($script:bindings[1].Enabled -and $script:writes.Count -eq 0)
}
Test-Case 'installation requires all new bindings to remain disabled' {
    $script:bindings[0].Enabled = $true
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapters @($script:adapters[0]) -AllDisabled } 'unexpectedly enabled binding'
}
Test-Case 'target enabled is accepted after explicit enable' {
    $script:bindings[0].Enabled = $true
    Assert-True ([bool](Assert-HyperVXNdisFilterBindingScope -Adapters @($script:adapters[0])).Enabled)
}
Test-Case 'matching GUID and NET_LUID configuration is accepted' {
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0])
}
Test-Case 'stale GUID configuration is rejected' {
    $script:config.TargetAdapters[4] = $script:config.TargetAdapters[4] -bxor 1
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
}
Test-Case 'stale NET_LUID configuration is rejected' {
    $script:config.TargetAdapters[20] = $script:config.TargetAdapters[20] -bxor 1
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
}
Test-Case 'old configuration schema is rejected' {
    $script:config.ConfigVersion = 1
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
}
Test-Case 'fresh configuration is disarmed first and versioned last' {
    Set-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0])
    Assert-True (($script:writes -join ',') -eq 'AllowBindings/DWord,TargetAdapters/Binary,ConfigVersion/DWord')
    Assert-True ($script:config.AllowBindings -eq 0 -and $script:config.ConfigVersion -eq 3)
    Assert-True ($script:config.TargetAdapters.Length -eq 28)
}
Test-Case 'arming changes only the own-component configuration' {
    Set-HyperVXNdisFilterBindingsAllowed -Allowed $true
    Assert-True ($script:config.AllowBindings -eq 1 -and $script:writes.Count -eq 1)
    Assert-True (!$script:bindings[1].Enabled -and $script:bindings[2].Enabled)
}
function Add-WslFixture {
    $id = [guid]'00000022-0002-0003-0405-060708090a0b'
    $guid = [guid]'00000011-0002-0003-0405-060708090a0b'
    $script:networks += [pscustomobject]@{ Name = 'WSL (Hyper-V firewall)'; ID = $id; SwitchGuid = $id; Type = 'ICS' }
    $script:switches += [pscustomobject]@{ Id = $id; Name = 'A renamed switch' }
    $script:vnics += [pscustomobject]@{ IsManagementOs = $true; SwitchId = $id; DeviceId = $guid.ToString('B') }
    $script:adapters += [pscustomobject]@{ Name = 'A renamed WSL vNIC'; InterfaceGuid = $guid; NetLuid = [uint64]0x1122334455667788; Virtual = $true; HardwareInterface = $false; InterfaceType = 6 }
    $script:bindings += [pscustomobject]@{ Name = 'A renamed WSL vNIC'; ComponentID = 'hyperv_xndis_filter'; Enabled = $false }
}

function Add-IcsFixture {
    param([int]$Index)
    $id = [guid]('{0:X8}-0000-0000-0000-000000000000' -f (0x20000000 + $Index))
    $guid = [guid]('{0:X8}-0000-0000-0000-000000000000' -f (0x30000000 + $Index))
    $name = "arbitrary ICS adapter $Index"
    $script:networks += [pscustomobject]@{ Type = 'ICS'; ID = $id; SwitchGuid = $id }
    $script:switches += [pscustomobject]@{ Id = $id; Name = 'arbitrary switch' }
    $script:vnics += [pscustomobject]@{ IsManagementOs = $true; SwitchId = $id; DeviceId = $guid.ToString('B') }
    $script:adapters += [pscustomobject]@{ Name = $name; InterfaceGuid = $guid; NetLuid = [uint64](2000 + $Index); Virtual = $true; HardwareInterface = $false; InterfaceType = 6 }
    $script:bindings += [pscustomobject]@{ Name = $name; ComponentID = 'hyperv_xndis_filter'; Enabled = $false }
}

Test-Case 'resolve all ICS vNICs through HNS and switch associations' {
    Add-WslFixture
    $targets = @(Resolve-HyperVXNdisFilterAdapters)
    Assert-True ($targets.Count -eq 2 -and @($targets | Where-Object { $_.Name -eq 'A renamed WSL vNIC' }).Count -eq 1)
    Assert-True (@(Assert-HyperVXNdisFilterBindingScope -Adapters $targets).Count -eq 2)
    Set-HyperVXNdisFilterTargetConfiguration -Adapters $targets
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters $targets
    Assert-True ($script:config.TargetAdapters.Length -eq 52 -and $script:config.TargetAdapters[0] -eq 2)
    Assert-True ([BitConverter]::ToUInt64($script:config.TargetAdapters, 44) -eq $targets[1].NetLuid)
}
Test-Case 'network and switch names never authorize or exclude adapters' {
    Add-WslFixture
    $script:networks[0].Name = 'not Default Switch'
    $script:networks[1].Name = 'not WSL'
    $script:switches[0].Name = 'renamed'
    Assert-True (@(Resolve-HyperVXNdisFilterAdapters).Count -eq 2)
    $script:networks[0].Type = 'NAT'
    Assert-True (@(Resolve-HyperVXNdisFilterAdapters).Count -eq 1)
    Assert-True ((Resolve-HyperVXNdisFilterAdapters).Name -eq 'A renamed WSL vNIC')
}
Test-Case 'empty or non-ICS HNS inventory never falls back to Default Switch' {
    $script:networks[0].Type = 'NAT'
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'No HNS ICS'
    $script:networks = @()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'No HNS ICS'
}
Test-Case 'all HNS ICS network IDs must be nonzero and unique' {
    Add-WslFixture
    $script:networks[1].ID = [guid]::Empty
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'invalid or ambiguous'
    $script:networks[1].ID = $script:networks[0].ID
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'invalid or ambiguous'
}
Test-Case 'HNS switch GUID, not the network name or network ID, selects the switch' {
    Add-WslFixture
    $script:networks[1].ID = [guid]::NewGuid()
    Assert-True (@(Resolve-HyperVXNdisFilterAdapters).Count -eq 2)
    $script:networks[1].SwitchGuid = [guid]::Empty
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'invalid or ambiguous'
}
Test-Case 'every ICS network requires a matching Hyper-V switch' {
    Add-WslFixture
    $script:switches = @($script:switches[0])
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'switch is missing'
}
Test-Case 'an adapter alias cannot substitute the associated interface GUID' {
    Add-WslFixture
    $script:adapters[2].Name = 'vEthernet (WSL (Hyper-V firewall))'
    $script:adapters[2].InterfaceGuid = [guid]::NewGuid()
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'exact host adapter was not found'
}
Test-Case 'all target identities must be unique' {
    Add-WslFixture
    $script:adapters[2].NetLuid = $script:adapters[0].NetLuid
    Assert-Throws { Resolve-HyperVXNdisFilterAdapters } 'identities are ambiguous'
}
Test-Case 'all host vNICs on a shared ICS switch are selected exactly once' {
    Add-WslFixture
    $script:networks[1].SwitchGuid = $script:fixtureSwitchId
    $script:vnics[1].SwitchId = $script:fixtureSwitchId
    Assert-True (@(Resolve-HyperVXNdisFilterAdapters).Count -eq 2)
}
Test-Case 'discovery and configuration support more than two ICS targets' {
    foreach ($i in 1..128) { Add-IcsFixture -Index $i }
    $targets = @(Resolve-HyperVXNdisFilterAdapters)
    Assert-True ($targets.Count -eq 129)
    Set-HyperVXNdisFilterTargetConfiguration -Adapters $targets
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters $targets
    Assert-True ([BitConverter]::ToUInt32($script:config.TargetAdapters, 0) -eq 129)
    Assert-True ($script:config.TargetAdapters.Length -eq 4 + 24 * 129)
}
Test-Case 'enumeration and stored entry order do not change the target set' {
    Add-WslFixture
    Add-IcsFixture -Index 1
    $targets = @(Resolve-HyperVXNdisFilterAdapters)
    Set-HyperVXNdisFilterTargetConfiguration -Adapters $targets
    [Array]::Reverse($script:networks)
    [Array]::Reverse($script:vnics)
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters)
    $reversed = [byte[]]$script:config.TargetAdapters.Clone()
    [Array]::Copy($script:config.TargetAdapters, 4, $reversed, 52, 24)
    [Array]::Copy($script:config.TargetAdapters, 52, $reversed, 4, 24)
    $script:config.TargetAdapters = $reversed
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters $targets
}
Test-Case 'new ICS targets cannot silently broaden stored configuration' {
    Add-WslFixture
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters) } 'does not match'
}
Test-Case 'ICS recreation or removal invalidates the stored set' {
    Add-WslFixture
    Set-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters)
    $script:adapters[2].NetLuid++
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters) } 'does not match'
    $script:networks = @($script:networks[0])
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters) } 'does not match'
}
Test-Case 'malformed, truncated and legacy target configurations fail closed' {
    foreach ($value in @([byte[]]@(1, 0, 0, 0), [byte[]]::new(52), 'not binary')) {
        $script:config.TargetAdapters = $value
        Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
    }
}
Test-Case 'malformed scalar registry types fail closed' {
    $script:config.ConfigVersion = '3'
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
    $script:config.ConfigVersion = 3
    $script:config.AllowBindings = '0'
    Assert-Throws { Assert-HyperVXNdisFilterTargetConfiguration -Adapters @($script:adapters[0]) } 'does not match'
}
Test-Case 'enabled ICS paths are allowed but enabled non-ICS paths still abort' {
    Add-WslFixture
    Add-IcsFixture -Index 1
    $script:bindings[3].Enabled = $script:bindings[4].Enabled = $true
    Assert-True (@(Assert-HyperVXNdisFilterBindingScope -Adapters @(Resolve-HyperVXNdisFilterAdapters)).Count -eq 3)
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapters @($script:adapters[0]) } 'unexpectedly enabled'
    $script:bindings[1].Enabled = $true
    Assert-Throws { Assert-HyperVXNdisFilterBindingScope -Adapters @(Resolve-HyperVXNdisFilterAdapters) } 'unexpectedly enabled'
}

Test-Case 'obsolete switch script cannot mutate any switch' {
    Assert-Throws { & (Join-Path (Split-Path $PSScriptRoot -Parent) 'Set-Extension.ps1') -SwitchName 'Default Switch' -Enable } 'not a vSwitch extension'
}
Test-Case 'all management scripts parse on Windows PowerShell' {
    Get-ChildItem (Split-Path $PSScriptRoot -Parent) -Filter *.ps1 -Recurse | ForEach-Object {
        $tokens = $null; $errors = $null
        [void][System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$tokens, [ref]$errors)
        Assert-True ($errors.Count -eq 0) "Parse errors in $($_.Name): $errors"
    }
}
Write-Host "$script:passed management tests passed (no driver, registry or network changes)."
