$script:HyperVXNdisFilterComponentId = 'hyperv_xndis_filter'
$script:HyperVXNdisFilterConfigPath = 'HKLM:\SOFTWARE\HyperVXNdisFilter\Lwf'

function Resolve-HyperVXNdisFilterAdapters {
    [CmdletBinding()]
    param()

    # Only HNS Type=ICS plus Hyper-V management-OS associations authorizes a
    # candidate. Network, switch and adapter display names are not identities.
    $networkIds = [System.Collections.Generic.HashSet[guid]]::new()
    $switchIds = [System.Collections.Generic.HashSet[guid]]::new()
    foreach ($network in @(Get-HnsNetwork -ErrorAction Stop)) {
        if ($network.Type -isnot [string]) { throw 'Invalid HNS network type.' }
        if ($network.Type -cne 'ICS') { continue }
        $id = [guid]::Empty
        $switchId = [guid]::Empty
        if (![guid]::TryParse([string]$network.ID, [ref]$id) -or $id -eq [guid]::Empty -or
            ![guid]::TryParse([string]$network.SwitchGuid, [ref]$switchId) -or $switchId -eq [guid]::Empty -or
            !$networkIds.Add($id)) {
            throw 'An HNS ICS network identity is invalid or ambiguous. No fallback is allowed.'
        }
        [void]$switchIds.Add($switchId)
    }
    if (!$switchIds.Count) { throw 'No HNS ICS networks were found. No adapter will be guessed.' }
    $switches = @(Get-VMSwitch -ErrorAction Stop)
    $vnics = @(Get-VMNetworkAdapter -ManagementOS -ErrorAction Stop)
    $inventory = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
    $targets = [System.Collections.Generic.List[object]]::new()
    foreach ($id in $switchIds) {
        if (@($switches | Where-Object { $_.Id -eq $id }).Count -ne 1) {
            throw 'An HNS ICS Hyper-V switch is missing or ambiguous. No alternate adapter will be selected.'
        }
        $ports = @($vnics | Where-Object { $_.IsManagementOs -and $_.SwitchId -eq $id })
        if (!$ports.Count) { throw 'Expected a management-OS vNIC on each HNS ICS switch. No binding was changed.' }
        foreach ($port in $ports) {
            $guid = [guid]::Empty
            if (![guid]::TryParse([string]$port.DeviceId, [ref]$guid) -or $guid -eq [guid]::Empty) {
                throw 'The management vNIC has no valid interface GUID.'
            }
            $adapters = @($inventory | Where-Object { [guid]$_.InterfaceGuid -eq $guid })
            if ($adapters.Count -ne 1) { throw 'The exact host adapter was not found or is ambiguous. No name-based fallback is allowed.' }
            $adapter = $adapters[0]
            if (!$adapter.Virtual -or $adapter.HardwareInterface -or $adapter.InterfaceType -ne 6 -or [uint64]$adapter.NetLuid -eq 0) {
                throw 'The selected device is not an Ethernet host vNIC with a valid NET_LUID.'
            }
            $targets.Add($adapter)
        }
    }
    [void](ConvertTo-HyperVXNdisFilterTargets -Adapters $targets.ToArray())
    return @($targets.ToArray() | Sort-Object { ([guid]$_.InterfaceGuid).ToString('N') })
}

function ConvertTo-HyperVXNdisFilterTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][object[]]$Adapters)

    $size = 4L + 24L * $Adapters.Count
    if (!$Adapters.Count -or $size -gt [uint32]::MaxValue) { throw 'Invalid target adapter count or registry byte-length overflow.' }
    $guids = [System.Collections.Generic.HashSet[guid]]::new()
    $luids = [System.Collections.Generic.HashSet[uint64]]::new()
    foreach ($adapter in $Adapters) {
        $guid = [guid]$adapter.InterfaceGuid
        $luid = [uint64]$adapter.NetLuid
        if ($guid -eq [guid]::Empty -or $luid -eq 0) { throw 'Invalid target GUID/NET_LUID.' }
        if (!$guids.Add($guid) -or !$luids.Add($luid)) { throw 'The HNS ICS target identities are ambiguous.' }
    }
    $ordered = @($Adapters | Sort-Object { ([guid]$_.InterfaceGuid).ToString('N') })
    $bytes = [byte[]]::new($size)
    [Array]::Copy([BitConverter]::GetBytes([uint32]$ordered.Count), 0, $bytes, 0, 4)
    for ($i = 0; $i -lt $ordered.Count; ++$i) {
        [Array]::Copy(([guid]$ordered[$i].InterfaceGuid).ToByteArray(), 0, $bytes, 4 + 24 * $i, 16)
        [Array]::Copy([BitConverter]::GetBytes([uint64]$ordered[$i].NetLuid), 0, $bytes, 20 + 24 * $i, 8)
    }
    return ,$bytes
}

function ConvertFrom-HyperVXNdisFilterTargets {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][AllowEmptyCollection()][byte[]]$Bytes)

    if ($Bytes.Length -lt 4) { throw 'Invalid target configuration length.' }
    $count = [BitConverter]::ToUInt32($Bytes, 0)
    $size = 4L + 24L * $count
    if (!$count -or $size -gt [uint32]::MaxValue -or $size -ne $Bytes.LongLength) { throw 'Invalid target configuration length.' }
    $targets = [System.Collections.Generic.List[object]]::new()
    for ($i = 0; $i -lt $count; ++$i) {
        $guidBytes = [byte[]]::new(16)
        [Array]::Copy($Bytes, 4 + 24L * $i, $guidBytes, 0, 16)
        $targets.Add([pscustomobject]@{ InterfaceGuid = [guid]::new($guidBytes); NetLuid = [BitConverter]::ToUInt64($Bytes, 20 + 24 * $i) })
    }
    [void](ConvertTo-HyperVXNdisFilterTargets -Adapters $targets.ToArray())
    return $targets.ToArray()
}

function Get-HyperVXNdisFilterBindings {
    [CmdletBinding()]
    param()
    Get-NetAdapterBinding -Name '*' -IncludeHidden -AllBindings -ErrorAction Stop |
        Where-Object { $_.ComponentID -eq $script:HyperVXNdisFilterComponentId }
}

function Assert-HyperVXNdisFilterBindingScope {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Adapters, [switch]$AllDisabled)

    [void](ConvertTo-HyperVXNdisFilterTargets -Adapters $Adapters)
    $names = @($Adapters | ForEach-Object { $_.Name })
    if (@($names | Select-Object -Unique).Count -ne $Adapters.Count) { throw 'Target adapter aliases are ambiguous.' }
    $bindings = @(Get-HyperVXNdisFilterBindings)
    $foreign = @($bindings | Where-Object { $_.Enabled -and ($AllDisabled -or $_.Name -notin $names) })
    if ($foreign.Count) {
        throw 'HyperVXNdisFilter has an unexpectedly enabled binding. No other adapter will be edited; abort and remove the component with Uninstall.exe.'
    }
    foreach ($name in $names) {
        $target = @($bindings | Where-Object { $_.Name -eq $name })
        if ($target.Count -ne 1) { throw 'Expected one HyperVXNdisFilter binding on each exact configured host adapter.' }
        $target[0]
    }
}

function Assert-HyperVXNdisFilterTargetConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Adapters)

    $expected = ConvertTo-HyperVXNdisFilterTargets -Adapters $Adapters
    $config = Get-ItemProperty -LiteralPath $script:HyperVXNdisFilterConfigPath -ErrorAction Stop
    try {
        if ($config.ConfigVersion -isnot [int] -or $config.ConfigVersion -ne 3 -or
            $config.AllowBindings -isnot [int] -or $config.AllowBindings -notin @(0, 1) -or $config.TargetAdapters -isnot [byte[]]) {
            throw 'Invalid target configuration types.'
        }
        $stored = ConvertTo-HyperVXNdisFilterTargets -Adapters @(ConvertFrom-HyperVXNdisFilterTargets -Bytes $config.TargetAdapters)
        if ([Convert]::ToBase64String($stored) -cne [Convert]::ToBase64String($expected)) { throw 'Target set changed.' }
    } catch {
        throw 'The configured GUID/NET_LUID allowlist does not match the current HNS ICS host vNICs. Uninstall and reinstall explicitly; no fallback or automatic retargeting is allowed.'
    }
}

function Set-HyperVXNdisFilterTargetConfiguration {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][object[]]$Adapters)

    $bytes = ConvertTo-HyperVXNdisFilterTargets -Adapters $Adapters
    # Called only for a fresh installation, before NetCfg can load either binary.
    New-Item -Path $script:HyperVXNdisFilterConfigPath -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVXNdisFilterConfigPath -Name AllowBindings -PropertyType DWord -Value 0 -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVXNdisFilterConfigPath -Name TargetAdapters -PropertyType Binary -Value $bytes -Force | Out-Null
    New-ItemProperty -LiteralPath $script:HyperVXNdisFilterConfigPath -Name ConfigVersion -PropertyType DWord -Value 3 -Force | Out-Null
}

function Set-HyperVXNdisFilterBindingsAllowed {
    [CmdletBinding()]
    param([Parameter(Mandatory = $true)][bool]$Allowed)
    New-ItemProperty -LiteralPath $script:HyperVXNdisFilterConfigPath -Name AllowBindings -PropertyType DWord -Value ([int]$Allowed) -Force | Out-Null
}
