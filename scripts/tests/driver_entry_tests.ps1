param([Parameter(Mandatory=$true)][string]$DriverPath)
$ErrorActionPreference = 'Stop'

# Check the actual PE entry, not just the linker command or a source-level test.
# These baseline x64 bytes are the naked guard through both epilogues. Relative
# call/jump displacements depend on the link; all other instructions must match.
$pattern = @'
53 48 83 EC 30 48 89 4C 24 20 48 89 54 24 28 31 C0 0F A2
83 F8 01 72 63 B8 01 00 00 00 31 C9 0F A2
81 E1 01 02 18 00 81 F9 01 02 18 00 75 4C
B9 0D 00 00 00 E8 ?? ?? ?? ?? 84 C0 74 3E
B9 24 00 00 00 E8 ?? ?? ?? ?? 84 C0 74 30
B9 25 00 00 00 E8 ?? ?? ?? ?? 84 C0 74 22
B9 26 00 00 00 E8 ?? ?? ?? ?? 84 C0 74 14
48 8B 4C 24 20 48 8B 54 24 28 48 83 C4 30 5B E9 ?? ?? ?? ??
B8 BB 00 00 C0 48 83 C4 30 5B C3
'@ -split '\s+' | Where-Object { $_ }

function Resolve-Rva([byte[]]$Image, [long]$SectionTable, [int]$Sections, [long]$Rva, [int]$Length) {
    for ($i = 0; $i -lt $Sections; ++$i) {
        $section = $SectionTable + 40 * $i
        $virtualAddress = [BitConverter]::ToUInt32($Image, $section + 12)
        $rawSize = [BitConverter]::ToUInt32($Image, $section + 16)
        $rawOffset = [BitConverter]::ToUInt32($Image, $section + 20)
        if ($Rva -ge $virtualAddress -and $Rva - $virtualAddress + $Length -le $rawSize) {
            $offset = [long]$rawOffset + $Rva - $virtualAddress
            if ($offset + $Length -gt $Image.Length) { throw 'Truncated PE section.' }
            return $offset
        }
    }
    throw 'RVA does not map to a PE section.'
}

function Assert-SafeEntry([byte[]]$Image) {
    if ($Image.Length -lt 64 -or [BitConverter]::ToUInt16($Image, 0) -ne 0x5a4d) {
        throw 'Missing DOS header.'
    }
    $pe = [BitConverter]::ToUInt32($Image, 0x3c)
    if ([uint64]$pe + 24 -gt $Image.Length -or [BitConverter]::ToUInt32($Image, $pe) -ne 0x4550) {
        throw 'Missing PE header.'
    }
    if ([BitConverter]::ToUInt16($Image, $pe + 4) -ne 0x8664) { throw 'SYS is not x64.' }
    $sections = [BitConverter]::ToUInt16($Image, $pe + 6)
    $optionalSize = [BitConverter]::ToUInt16($Image, $pe + 20)
    $optional = $pe + 24
    if ($optionalSize -lt 192 -or [uint64]$optional + $optionalSize + 40 * $sections -gt $Image.Length -or
        [BitConverter]::ToUInt16($Image, $optional) -ne 0x20b) {
        throw 'Invalid PE32+ optional or section headers.'
    }
    $entryRva = [BitConverter]::ToUInt32($Image, $optional + 16)
    $directoryCount = [BitConverter]::ToUInt32($Image, $optional + 108)
    $tls = $optional + 112 + 9 * 8
    if ($directoryCount -le 9 -or [BitConverter]::ToUInt32($Image, $tls) -ne 0 -or
        [BitConverter]::ToUInt32($Image, $tls + 4) -ne 0) {
        throw 'A missing or nonempty TLS directory could run code before the CPU gate.'
    }
    $sectionTable = $optional + $optionalSize
    $entryOffset = $null
    for ($i = 0; $i -lt $sections; ++$i) {
        $section = $sectionTable + 40 * $i
        $virtualAddress = [BitConverter]::ToUInt32($Image, $section + 12)
        $rawSize = [BitConverter]::ToUInt32($Image, $section + 16)
        $rawOffset = [BitConverter]::ToUInt32($Image, $section + 20)
        if ($entryRva -ge $virtualAddress -and [uint64]$entryRva -lt [uint64]$virtualAddress + $rawSize) {
            $characteristics = [BitConverter]::ToUInt32($Image, $section + 36)
            if (($characteristics -band 0x20000000) -eq 0) { throw 'Entry section is not executable.' }
            $entryOffset = [uint64]$rawOffset + $entryRva - $virtualAddress
            if ($entryOffset + $pattern.Count -gt $Image.Length -or
                [uint64]$entryRva - $virtualAddress + $pattern.Count -gt $rawSize) {
                throw 'Truncated CPU gate.'
            }
            break
        }
    }
    if ($null -eq $entryOffset) { throw 'Entry does not map to a section.' }
    for ($i = 0; $i -lt $pattern.Count; ++$i) {
        if ($pattern[$i] -ne '??' -and $Image[$entryOffset + $i] -ne [Convert]::ToByte($pattern[$i], 16)) {
            throw "Unexpected instruction in CPU gate at offset $i."
        }
    }
    # All four calls must resolve to the same import thunk, not arbitrary code.
    $featureTarget = $null
    foreach ($callOffset in @(0x34, 0x42, 0x50, 0x5e)) {
        $target = [long]$entryRva + $callOffset + 5 +
            [BitConverter]::ToInt32($Image, $entryOffset + $callOffset + 1)
        if ($null -ne $featureTarget -and $target -ne $featureTarget) {
            throw 'Processor-feature calls do not share an import thunk.'
        }
        $featureTarget = $target
    }
    $thunk = Resolve-Rva $Image $sectionTable $sections $featureTarget 6
    if ($Image[$thunk] -ne 0xff -or $Image[$thunk + 1] -ne 0x25) {
        throw 'Processor-feature calls do not point to an import thunk.'
    }
    # The successful tail jump must still enter the pinned WDK GS wrapper,
    # which initializes the security cookie before calling DriverEntry.
    $jumpOffset = 0x76
    $gsRva = [long]$entryRva + $jumpOffset + 5 +
        [BitConverter]::ToInt32($Image, $entryOffset + $jumpOffset + 1)
    $gsPattern = @'
48 89 5C 24 08 57 48 83 EC 20 48 8B DA 48 8B F9 E8 ?? ?? ?? ??
48 8B D3 48 8B CF E8 ?? ?? ?? ?? 48 8B 5C 24 30 48 83 C4 20 5F C3
'@ -split '\s+' | Where-Object { $_ }
    $gsOffset = Resolve-Rva $Image $sectionTable $sections $gsRva $gsPattern.Count
    for ($i = 0; $i -lt $gsPattern.Count; ++$i) {
        if ($gsPattern[$i] -ne '??' -and $Image[$gsOffset + $i] -ne [Convert]::ToByte($gsPattern[$i], 16)) {
            throw "CPU gate does not tail-jump to the expected WDK GS wrapper (offset $i)."
        }
    }

    $exceptionDirectory = $optional + 112 + 3 * 8
    $exceptionRva = [BitConverter]::ToUInt32($Image, $exceptionDirectory)
    $exceptionSize = [BitConverter]::ToUInt32($Image, $exceptionDirectory + 4)
    if ($exceptionRva -eq 0 -or $exceptionSize -lt 12 -or $exceptionSize % 12 -ne 0) {
        throw 'Missing or malformed x64 exception directory.'
    }
    $exceptionOffset = Resolve-Rva $Image $sectionTable $sections $exceptionRva $exceptionSize
    $unwindOffset = $null
    for ($i = 0; $i -lt $exceptionSize; $i += 12) {
        $record = $exceptionOffset + $i
        if ([BitConverter]::ToUInt32($Image, $record) -eq $entryRva) {
            if ([BitConverter]::ToUInt32($Image, $record + 4) -ne $entryRva + $pattern.Count) {
                throw 'The entry unwind range does not match the complete gate.'
            }
            $unwindRva = [BitConverter]::ToUInt32($Image, $record + 8)
            $unwindOffset = Resolve-Rva $Image $sectionTable $sections $unwindRva 8
            break
        }
    }
    if ($null -eq $unwindOffset) { throw 'CPU gate has no x64 unwind record.' }
    # Version 1, five-byte prologue, no frame register, 48-byte allocation,
    # and preservation of RBX. These must describe the checked entry bytes.
    $unwindPattern = @(0x01, 0x05, 0x02, 0x00, 0x05, 0x52, 0x01, 0x30)
    for ($i = 0; $i -lt $unwindPattern.Count; ++$i) {
        if ($Image[$unwindOffset + $i] -ne $unwindPattern[$i]) { throw 'Unexpected CPU gate unwind metadata.' }
    }
    return @{ EntryOffset = $entryOffset; TlsOffset = $tls; UnwindOffset = $unwindOffset }
}

$image = [IO.File]::ReadAllBytes((Resolve-Path -LiteralPath $DriverPath).Path)
$layout = Assert-SafeEntry $image
Write-Host 'PASS SYS entry has the baseline CPUID/system-feature gate, valid unwind data and no TLS callbacks'

# Verify that the check rejects relevant damaged entrypoints and TLS metadata.
foreach ($case in @(
    @{ Name = 'entry prologue'; Offset = $layout.EntryOffset },
    @{ Name = 'CPUID instruction'; Offset = $layout.EntryOffset + 17 },
    @{ Name = 'feature-call target'; Offset = $layout.EntryOffset + 0x35 },
    @{ Name = 'GS tail-jump target'; Offset = $layout.EntryOffset + 0x77 },
    @{ Name = 'failure return'; Offset = $layout.EntryOffset + $pattern.Count - 1 },
    @{ Name = 'TLS directory'; Offset = $layout.TlsOffset },
    @{ Name = 'unwind metadata'; Offset = $layout.UnwindOffset }
)) {
    $mutant = [byte[]]$image.Clone()
    $mutant[$case.Offset] = $mutant[$case.Offset] -bxor 1
    $rejected = $false
    try { $null = Assert-SafeEntry $mutant }
    catch { $rejected = $true }
    if (!$rejected) { throw "Entry verifier accepted a changed $($case.Name)." }
    Write-Host "PASS entry verifier rejects changed $($case.Name)"
}
