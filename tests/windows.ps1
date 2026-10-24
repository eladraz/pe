# Build dumpPE against the peLib/xStl MSVC libraries and run it on PE32 and
# PE32+ DLLs.
# Usage: windows.ps1 -Configuration Debug|Release -Platform Win32|x64
# Requires a developer prompt for the matching architecture (cl.exe on PATH)
# and XSTL_PATH.
param(
    [Parameter(Mandatory)][ValidateSet('Debug', 'Release')][string]$Configuration,
    [Parameter(Mandatory)][ValidateSet('Win32', 'x64')][string]$Platform
)
$ErrorActionPreference = 'Stop'

$suffix = if ($Platform -eq 'x64') { '64' } else { '' }
$libDir = "lib$Configuration$suffix"
if ($Configuration -eq 'Debug') {
    $flags = '/MTd', '/DDEBUG', '/DPE_TRACE'
} else {
    $flags = '/MT', '/DNDEBUG'
}

$outDir = "out\dumpPE_$Configuration$Platform"
New-Item -ItemType Directory -Force $outDir | Out-Null

& cl /nologo /EHsc @flags /DWIN32 /DXSTL_UNICODE /D_MBCS /DUNICODE `
    /I Include /I "$env:XSTL_PATH\Include" tools\dumpPE.cpp `
    "/Fo:$outDir\" "/Fe:$outDir\dumpPE.exe" `
    /link "$env:XSTL_PATH\out\$libDir\xStl\xStl.lib" "out\$libDir\peLib\peLib.lib"
if ($LASTEXITCODE -ne 0) { throw "dumpPE build failed" }

# SysWOW64\kernel32.dll is a PE32 file and System32\kernel32.dll is a PE32+
# file, regardless of the architecture of dumpPE
foreach ($dll in "$env:SystemRoot\SysWOW64\kernel32.dll", "$env:SystemRoot\System32\kernel32.dll") {
    $out = & "$outDir\dumpPE.exe" $dll
    if ($LASTEXITCODE -ne 0) { throw "dumpPE exited with $LASTEXITCODE on $dll" }
    foreach ($name in 'CreateFileW', 'ReadFile', 'LoadLibraryW') {
        if (-not ($out | Select-String -SimpleMatch $name -Quiet)) {
            throw "export $name not found in $dll"
        }
    }
    Write-Host "PASS: $Configuration|$Platform $dll ($($out.Count) lines)"
}
