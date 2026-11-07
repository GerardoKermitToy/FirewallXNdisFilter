#Requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true, ParameterSetName = 'Enable')][switch]$Enable,
    [Parameter(Mandatory = $true, ParameterSetName = 'Disable')][switch]$Disable
)

# The former helper selected only HNS ICS vNICs from schema-3 configuration.
# It must not silently apply that old scope to the all-compatible-adapter LWF.
throw 'Set-Binding.ps1 is no longer supported. Use dist/Install.exe --enable to enable eligible bindings, or dist/Uninstall.exe to disarm and remove the filter. No binding or configuration was changed.'
