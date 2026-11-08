[CmdletBinding()]
param(
    [switch]$SkipMonitor,
    [switch]$Test,
    [string]$SdkVersion = '10.0.28000.0',
    [string]$CertificateThumbprint,
    [string]$PfxPath,
    [string]$RootCertificate,
    [ValidateNotNullOrEmpty()][string]$TimestampUrl = 'http://timestamp.digicert.com',
    [string]$PfxPassword = $(if ($env:FIREWALLXNDISFILTER_PFX_PASSWORD) { $env:FIREWALLXNDISFILTER_PFX_PASSWORD } else { '1' })
)

function Assert-NoLegacyPackageFiles([string]$Directory) {
    foreach ($name in @('HyperVXNdisFilter.inf', 'HyperVXNdisFilter.cat', 'HyperVXNdisFilter.sys',
                         'HyperVXNdisFilter.pdb', 'HyperVXNdisFilterNotify.dll', 'HyperVXNdisFilterNotify.pdb',
                         'HyperVGuard.inf', 'HyperVGuard.cat', 'HyperVGuard.sys', 'HyperVGuard.pdb',
                         'HyperVGuardNotify.dll', 'HyperVGuardNotify.pdb', 'hyperv_monitor.exe', 'hyperv_monitor.pdb',
                         'firewallx_monitor.exe', 'firewallx_monitor.pdb')) {
        if (Test-Path -LiteralPath (Join-Path $Directory $name)) {
            throw "Previous package artifact '$name' is present in $Directory. Preserve and move the old package before rebuilding; no files were removed."
        }
    }
}

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$vswhere = "${env:ProgramFiles(x86)}\Microsoft Visual Studio\Installer\vswhere.exe"
if (!(Test-Path $vswhere)) { throw 'Visual Studio with C++ tools is required.' }
$vs = & $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath
if (!$vs) { throw 'Visual Studio C++ x64 tools were not found.' }
$vcvars = Join-Path $vs 'VC\Auxiliary\Build\vcvars64.bat'
$env:Path += ';' + (Split-Path $vswhere -Parent)
$environment = & $env:ComSpec /d /c "call `"$vcvars`" >nul && set"
if ($LASTEXITCODE) { throw 'vcvars64 failed.' }
foreach ($line in $environment) {
    if ($line -match '^([^=]+)=(.*)$') { [Environment]::SetEnvironmentVariable($matches[1], $matches[2], 'Process') }
}
$wdk = "${env:ProgramFiles(x86)}\Windows Kits\10"
$include = Join-Path $wdk "Include\$SdkVersion"
$lib = Join-Path $wdk "Lib\$SdkVersion\km\x64"
$bin = Join-Path $wdk "bin\$SdkVersion\x64"
foreach ($required in @("$include\km\ndis.h",
                        "$lib\ndis.lib", "$lib\netio.lib")) {
    if (!(Test-Path $required)) { throw "Missing WDK input: $required" }
}
$build = Join-Path $root 'build'
$dist = Join-Path $root 'dist'
Assert-NoLegacyPackageFiles $dist
New-Item -ItemType Directory -Force $build, $dist | Out-Null
$oldFlags = $env:RUSTFLAGS
$oldEncodedFlags = $env:CARGO_ENCODED_RUSTFLAGS
$oldSdkVersion = $env:FIREWALLXNDISFILTER_SDK_VERSION
$oldDir = Get-Location
try {
    Set-Location $root
    $env:RUSTFLAGS = '-C panic=abort -C no-redzone=yes -C debuginfo=2 -C link-arg=/DEBUG:FULL -C link-arg=/PDBALTPATH:%_PDB%'
    $env:CARGO_ENCODED_RUSTFLAGS = $null
    $env:FIREWALLXNDISFILTER_SDK_VERSION = $SdkVersion
    & cargo build --release --target x86_64-pc-windows-msvc -p firewallx-driver --features native-wdk --locked
    if ($LASTEXITCODE) { throw 'Rust driver build failed.' }
    $resource = Join-Path $build 'driver_version.res'
    & "$bin\rc.exe" /nologo "/I$include\um" "/I$include\shared" "/fo$resource" "$root\driver\version.rc"
    if ($LASTEXITCODE) { throw 'Driver version resource compilation failed.' }
    & link.exe /NOLOGO /DRIVER /SUBSYSTEM:NATIVE,10.00 /ENTRY:GsDriverEntry /MACHINE:X64 /MANIFEST:NO /NODEFAULTLIB /INCREMENTAL:NO /INTEGRITYCHECK /DYNAMICBASE /NXCOMPAT /OPT:REF /OPT:ICF /DEBUG:FULL '/PDBALTPATH:%_PDB%' /RELEASE "/OUT:$dist\FirewallXNdisFilter.sys" "/PDB:$dist\FirewallXNdisFilter.pdb" $resource "$root\target\x86_64-pc-windows-msvc\release\firewallx_driver.lib" "$lib\ndis.lib" "$lib\netio.lib" "$lib\ntoskrnl.lib" "$lib\hal.lib" "$lib\BufferOverflowK.lib"
    if ($LASTEXITCODE) { throw 'Kernel image link failed.' }
    & "$PSScriptRoot\tests\driver_import_tests.ps1" -DriverPath "$dist\FirewallXNdisFilter.sys"
    $cmake = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\CMake\bin\cmake.exe'
    $ninja = Join-Path $vs 'Common7\IDE\CommonExtensions\Microsoft\CMake\Ninja\ninja.exe'
    & $cmake -S "$root\monitor" -B "$build\monitor" -G Ninja "-DCMAKE_MAKE_PROGRAM=$ninja" -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=ON
    if ($LASTEXITCODE) { throw 'User-mode CMake configuration failed.' }
    if ($SkipMonitor) { & $cmake --build "$build\monitor" --target firewallx_ndis_filter_notify firewallx_Install firewallx_Uninstall }
    else { & $cmake --build "$build\monitor" }
    if ($LASTEXITCODE) { throw 'User-mode build failed.' }
    foreach ($file in @('FirewallXNdisFilterNotify.dll', 'FirewallXNdisFilterNotify.pdb',
                        'Install.exe', 'Install.pdb', 'Uninstall.exe', 'Uninstall.pdb')) {
        Copy-Item (Join-Path "$build\monitor" $file) $dist -Force
    }
    if (!$SkipMonitor) {
        foreach ($file in @('ndis_monitor.exe', 'ndis_monitor.pdb')) {
            Copy-Item (Join-Path "$build\monitor" $file) $dist -Force
        }
        if ($Test) {
            & (Join-Path (Split-Path $cmake -Parent) 'ctest.exe') --test-dir "$build\monitor" --output-on-failure
            if ($LASTEXITCODE) { throw 'Offline user-mode tests failed.' }
        }
    }
    Copy-Item "$root\install\FirewallXNdisFilter.inf" $dist -Force
    if ($CertificateThumbprint -and $PfxPath) { throw 'Choose a PFX or a certificate-store thumbprint, not both.' }
    $signArgs = @('sign', '/fd', 'SHA256', '/tr', $TimestampUrl, '/td', 'SHA256')
    $sign = $CertificateThumbprint -or $PfxPath
    if ($PfxPath) {
        $PfxPath = (Resolve-Path -LiteralPath $PfxPath).Path
        $signArgs += @('/f', $PfxPath, '/p', $PfxPassword)
        if ($RootCertificate) { $signArgs += @('/ac', (Resolve-Path -LiteralPath $RootCertificate).Path) }
    } elseif ($CertificateThumbprint) { $signArgs += @('/sha1', $CertificateThumbprint) }
    $signedFiles = @('FirewallXNdisFilter.sys', 'FirewallXNdisFilterNotify.dll', 'Install.exe', 'Uninstall.exe')
    if (!$SkipMonitor) { $signedFiles += 'ndis_monitor.exe' }
    if ($sign) {
        # Timestamp requests send a hash to the selected RFC 3161 service. The
        # PFX remains local; no key copy, certificate import or security change.
        foreach ($file in $signedFiles) {
            & "$bin\signtool.exe" @signArgs (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Signing failed: $file" }
        }
    }
    # Stage the installed Inf2Cat with matching x64 native DLLs. Never patch the
    # WDK's mixed-bitness tool directory (0x8007000B without private staging).
    $catalogTools = Join-Path $build 'catalog-tools'
    New-Item -ItemType Directory -Force $catalogTools | Out-Null
    $catalogSource = "$wdk\bin\$SdkVersion\x86"
    Copy-Item "$catalogSource\Inf2Cat.exe" $catalogTools -Force
    Copy-Item "$catalogSource\WindowsProtectedFiles.xml" $catalogTools -Force
    foreach ($dll in Get-ChildItem "$catalogSource\Microsoft*.dll") {
        $matching = Join-Path $bin $dll.Name
        if (Test-Path $matching) { Copy-Item $matching $catalogTools -Force }
        else { Copy-Item $dll.FullName $catalogTools -Force }
    }
    Copy-Item "$bin\DRIVERS.dll" $catalogTools -Force
    if (Test-Path "$catalogSource\Inf2Cat.exe.config") { Copy-Item "$catalogSource\Inf2Cat.exe.config" $catalogTools -Force }
    & "$catalogTools\Inf2Cat.exe" "/driver:$dist" /os:10_X64 /uselocaltime
    if ($LASTEXITCODE) { throw 'Inf2Cat package validation failed.' }
    if ($sign) {
        & "$bin\signtool.exe" @signArgs "$dist\FirewallXNdisFilter.cat"
        if ($LASTEXITCODE) { throw 'Catalog signing failed.' }
        foreach ($file in ($signedFiles + 'FirewallXNdisFilter.cat')) {
            & "$bin\signtool.exe" verify /pa /tw (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Authenticode verification failed: $file (not a kernel admission test)." }
        }
        foreach ($file in @('FirewallXNdisFilter.sys', 'FirewallXNdisFilterNotify.dll', 'FirewallXNdisFilter.inf')) {
            & "$bin\signtool.exe" verify /pa /c "$dist\FirewallXNdisFilter.cat" (Join-Path $dist $file)
            if ($LASTEXITCODE) { throw "Catalog membership verification failed: $file" }
        }
    }
    if ($Test) {
        & "$root\scripts\tests\driver_version_tests.ps1" -DriverPath "$dist\FirewallXNdisFilter.sys"
        $env:RUSTFLAGS = $null
        & cargo test --release -p firewallx-protocol -p firewallx-policy --locked
        if ($LASTEXITCODE) { throw 'Offline Rust tests failed.' }
    }
    Write-Host "Built $dist (FirewallXNdisFilter.sys; no driver was installed, loaded or bound; notify COM was not registered)."
    if (!$sign) { Write-Warning 'SYS, notify DLL, CAT and setup tools are unsigned. Driver package signatures must be trusted before installation.' }
} finally {
    $env:RUSTFLAGS = $oldFlags
    $env:CARGO_ENCODED_RUSTFLAGS = $oldEncodedFlags
    $env:FIREWALLXNDISFILTER_SDK_VERSION = $oldSdkVersion
    Set-Location $oldDir
}
