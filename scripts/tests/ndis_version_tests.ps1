# Offline NDIS registration/build/package consistency; never load or install a driver.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$build = Get-Content -Raw -LiteralPath (Join-Path $root 'scripts\Build.ps1')
$shim = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\shim\ndis_shim.cpp')
$version = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\shim\ndis_version.h')
$inf = Get-Content -Raw -LiteralPath (Join-Path $root 'install\HyperVXNdisFilter.inf')
$checks = [ordered]@{
    'WDK exposes NDIS 6.89 declarations' = $build -match '/DNDIS689=1\s'
    'no conflicting NDIS 6.40 build override' = $build -notmatch '/DNDIS640|/DNDIS_SUPPORT_NDIS'
    'existing Windows DDI floor is preserved' = $build -match '/DNTDDI_VERSION=NTDDI_WIN10_NI\s'
    'runtime NDIS version is queried' = $shim -match 'FilterNdisVersion = HvNdisVersion\(NdisGetVersion\(\)\);'
    'registration follows runtime selection' = $shim -match 'HvSetNdisVersion\(&c, FilterNdisVersion\)'
    'unsupported old versions fail registration' = $shim -match 'status = NDIS_STATUS_BAD_VERSION;'
    'revision 2 and 3 sizes are selected explicitly' = $version -match 'NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2' -and $version -match 'NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_3'
    'compiler rejects a mismatched header target' = $shim -match 'C_ASSERT\(NDIS_FILTER_MAJOR_VERSION == 6 && NDIS_FILTER_MINOR_VERSION == 89\);'
    'URO support is not opted out' = $shim -match 'c\.Flags\s*=\s*0;' -and $shim -notmatch 'NDIS_FILTER_DRIVER_UDP_RSC_NOT_SUPPORTED'
    'synchronous OID request bypass' = $shim -match 'c\.SynchronousOidRequestHandler\s*=\s*NULL;'
    'synchronous OID completion bypass' = $shim -match 'c\.SynchronousOidRequestCompleteHandler\s*=\s*NULL;'
    'resource-copy OOB scan follows the runtime bound' = $shim -match 'HvCopyReceiveMetadataSupported\(source, HvNblInfoCount\(FilterNdisVersion\)\)'
    'existing notify-object package OS floor is preserved' = $inf -match '(?m)^%Provider%=Models,NTamd64\.10\.0\.\.\.25341\s*$'
}
foreach ($minor in @('640', '650', '651', '660', '670', '680', '681', '682', '683', '684', '685', '686', '687', '688', '689')) {
    $checks["runtime version $minor is supported"] = $version -match "NDIS_RUNTIME_VERSION_$minor"
}
foreach ($check in $checks.GetEnumerator()) {
    if (!$check.Value) { throw "NDIS compatibility check failed: $($check.Key)" }
    Write-Host "PASS $($check.Key)"
}
Write-Host "PASS $($checks.Count) NDIS compatibility checks (offline source inspection only)."
