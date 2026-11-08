# Offline native Rust NDIS registration/build/package consistency; no loading.
$ErrorActionPreference = 'Stop'
$root = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
$build = Get-Content -Raw -LiteralPath (Join-Path $root 'scripts\Build.ps1')
$bindings = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\build.rs')
$version = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\src\native_ndis.rs')
$device = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\src\native_device.rs')
$header = Get-Content -Raw -LiteralPath (Join-Path $root 'driver\wdk.h')
$inf = Get-Content -Raw -LiteralPath (Join-Path $root 'install\FirewallXNdisFilter.inf')
$checks = [ordered]@{
    'native Rust WDK feature is built' = $build -match '--features native-wdk'
    'kernel contains no C++ shim objects' = $build -notmatch 'ndis_shim\.obj|wfp_forward\.obj|foreach \(\$source'
    'WDK exposes NDIS 6.89 declarations' = $bindings -match '-DNDIS689=1'
    'no conflicting NDIS 6.40 build override' = $bindings -notmatch '-DNDIS640|-DNDIS_SUPPORT_NDIS'
    'existing Windows DDI floor is preserved' = $bindings -match '-DNTDDI_VERSION=NTDDI_WIN10_NI'
    'runtime NDIS version is queried' = $device -match 'ndis::ndis_version\(NdisGetVersion\(\)\)'
    'registration follows runtime selection' = $device -match 'ndis::configure_characteristics\(&mut characteristics, FILTER_NDIS_VERSION\)'
    'unsupported old versions fail registration' = $device -match 'FWX_WDK_NDIS_BAD_VERSION'
    'revision 2 and 3 WDK sizes are generated' = $header -match 'NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_2' -and $header -match 'NDIS_SIZEOF_FILTER_DRIVER_CHARACTERISTICS_REVISION_3'
    'NDIS characteristics start zeroed' = $version -match '\*c = unsafe \{ zeroed\(\) \}'
    'URO support is not opted out' = $version -notmatch 'NDIS_FILTER_DRIVER_UDP_RSC_NOT_SUPPORTED'
    'resource-copy OOB scan follows the runtime bound' = $version -match 'nbl_info_count\(FILTER_NDIS_VERSION\)'
    'existing notify-object package OS floor is preserved' = $inf -match '(?m)^%Provider%=Models,NTamd64\.10\.0\.\.\.25341\s*$'
}
foreach ($minor in @('640', '650', '651', '660', '670', '680', '681', '682', '683', '684', '685', '686', '687', '688', '689')) {
    $checks["runtime version $minor is supported"] = $version -match "NDIS_RUNTIME_VERSION_$minor"
}
foreach ($check in $checks.GetEnumerator()) {
    if (!$check.Value) { throw "NDIS compatibility check failed: $($check.Key)" }
    Write-Host "PASS $($check.Key)"
}
Write-Host "PASS $($checks.Count) Rust NDIS compatibility checks (offline source inspection only; native executable tests are separate)."
