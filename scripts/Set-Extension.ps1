[CmdletBinding()]
param(
    [string]$SwitchName,
    [switch]$Enable,
    [switch]$Disable
)
throw 'HyperVXNdisFilter is a host-adapter NDIS LWF, not a vSwitch extension. Use dist/Install.exe or dist/Uninstall.exe. Enable-VMSwitchExtension is not used; no switch configuration was changed.'
