#Requires -RunAsAdministrator
[CmdletBinding(SupportsShouldProcess = $true, ConfirmImpact = 'High')]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')][switch]$Enable,
    [Parameter(Mandatory = $true, ParameterSetName = 'Disable')][switch]$Disable
)
$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\HyperVXNdisFilter.Common.ps1"
Import-Module Hyper-V -ErrorAction Stop
Import-Module HostNetworkingService -ErrorAction Stop
$adapters = @(Resolve-HyperVXNdisFilterAdapters)
Assert-HyperVXNdisFilterTargetConfiguration -Adapters $adapters
$bindings = @(Assert-HyperVXNdisFilterBindingScope -Adapters $adapters)
$desiredEnabled = [bool]$Enable
if (@($bindings | Where-Object { [bool]$_.Enabled -ne $desiredEnabled }).Count -eq 0) {
    Write-Host "HyperVXNdisFilter already has Enabled=$desiredEnabled on all exact configured adapters."
} elseif ($PSCmdlet.ShouldProcess(($adapters.Name -join ', '), "Set ONLY the configured HyperVXNdisFilter bindings to Enabled=$desiredEnabled")) {
    $current = @(Resolve-HyperVXNdisFilterAdapters)
    Assert-HyperVXNdisFilterTargetConfiguration -Adapters $current
    for ($i = 0; $i -lt $adapters.Count; ++$i) {
        if ($current[$i].Name -ne $adapters[$i].Name -or
            [guid]$current[$i].InterfaceGuid -ne [guid]$adapters[$i].InterfaceGuid -or
            [uint64]$current[$i].NetLuid -ne [uint64]$adapters[$i].NetLuid) {
            throw 'A target changed while waiting for confirmation. No binding was changed.'
        }
    }
    $bindings = @(Assert-HyperVXNdisFilterBindingScope -Adapters $current)
    Set-HyperVXNdisFilterBindingsAllowed -Allowed $desiredEnabled
    try {
        foreach ($binding in $bindings) {
            if ([bool]$binding.Enabled -eq $desiredEnabled) { continue }
            if ($Enable) { Enable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
            else { Disable-NetAdapterBinding -InputObject $binding -Confirm:$false -ErrorAction Stop }
        }
        Assert-HyperVXNdisFilterTargetConfiguration -Adapters @(Resolve-HyperVXNdisFilterAdapters)
        $bindings = @(Assert-HyperVXNdisFilterBindingScope -Adapters $current)
        if (@($bindings | Where-Object { [bool]$_.Enabled -ne $desiredEnabled }).Count) {
            throw 'The exact target bindings did not reach the requested state.'
        }
    } catch {
        Set-HyperVXNdisFilterBindingsAllowed -Allowed $false
        throw
    }
}
$bindings | Format-List Name, DisplayName, ComponentID, Enabled
