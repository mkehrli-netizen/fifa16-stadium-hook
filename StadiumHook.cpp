// ============================================================================
// FIFA 16 Stadium 419 Hook DLL v4 - NEAR TRAMPOLINE + ABSOLUTE JMP
// ============================================================================
// 
// v3 found the hash function but FAILED to install hook:
//   "ERROR: jz target out of 32-bit range"
// 
// Reason: VirtualAlloc returned a trampoline address far from hookTarget,
// so the relocated jz instruction couldn't reach its target with a 32-bit offset.
// 
// v4 fixes this by:
// 1. Allocating trampoline NEAR hookTarget (within 2GB)
// 2. Converting jz rel32 to: jne +0xe ; jmp [rip+0] ; dq absolute_target
//    (no relocation needed - uses 64-bit absolute address)
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>

// ============================================================================
// CONFIG
// ============================================================================
static const uint8_t HASH_SIGNATURE[15] = {
    0x49, 0x89, 0xC9, 0x45, 0x85, 0xC0, 0x0F, 0x84, 
    0x8E, 0x00, 0x00, 0x00, 0x41, 0xFF, 0xC8
};

typedef uint64_t (__fastcall *HashFunc)(const char* str, uint64_t init, int mode);

static HashFunc g_OriginalHash = nullptr;
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_LogLock;
static volatile bool g_EnableRedirect = false;
static uintptr_t g_HookTarget = 0;
static uintptr_t g_TrampolineAddr = 0;

// ============================================================================
// LOGGING
// ============================================================================
static void Log(const char* fmt, ...) {
    if (g_LogFile == INVALID_HANDLE_VALUE) return;
    
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    if (len < 0) return;
    if (len >= (int)sizeof(buf)) len = sizeof(buf) - 1;
    
    EnterCriticalSection(&g_LogLock);
    DWORD written;
    WriteFile(g_LogFile, buf, len, &written, NULL);
    FlushFileBuffers(g_LogFile);
    LeaveCriticalSection(&g_LogLock);
}

static bool SafeReadString(const char* p, char* out, size_t outSize) {
    if (!p || (uintptr_t)p < 0x10000) return false;
    __try {
        size_t i = 0;
        while (i < outSize - 1) {
            char c = p[i];
            if (c == 0) break;
            if ((unsigned char)c < 0x20 || (unsigned char)c > 0x7e) {
                if (i == 0) return false;
                break;
            }
            out[i] = c;
            i++;
        }
        out[i] = 0;
        return i > 0;
    } __except(EXCEPTION_EXECUTE_HANDLER) {
        return false;
    }
}

// ============================================================================
// HOOK FUNCTION
// ============================================================================
extern "C" uint64_t __fastcall HookedHash(const char* str, uint64_t init, int mode) {
    char buf[256] = {0};
    bool hasStr = SafeReadString(str, buf, sizeof(buf));
    
    if (hasStr) {
        Log("HASH: '%s' init=0x%llx mode=%d\n", buf, init, mode);
        
        if (g_EnableRedirect && strncmp(buf, "stad_419", 8) == 0) {
            char redirected[256];
            snprintf(redirected, sizeof(redirected), "stad_332%s", buf + 8);
            Log("  REDIRECT: '%s' -> '%s'\n", buf, redirected);
            return g_OriginalHash(redirected, init, mode);
        }
    }
    
    return g_OriginalHash(str, init, mode);
}

// ============================================================================
// SIGNATURE SCAN
// ============================================================================
static uintptr_t ScanForSignature(uintptr_t startAddr, uintptr_t endAddr) {
    MEMORY_BASIC_INFORMATION mbi;
    uintptr_t addr = startAddr;
    int regionsScanned = 0;
    
    while (addr < endAddr) {
        if (VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) == 0) {
            addr += 0x10000;
            continue;
        }
        
        bool isExecutable = (mbi.State == MEM_COMMIT) && 
                           (mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | 
                                          PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY));
        
        if (isExecutable && mbi.RegionSize > 0 && mbi.RegionSize < 0x80000000) {
            regionsScanned++;
            
            __try {
                const uint8_t* data = (const uint8_t*)mbi.BaseAddress;
                SIZE_T size = mbi.RegionSize;
                
                if (size >= 15) {
                    for (SIZE_T i = 0; i + 15 <= size; i++) {
                        if (data[i] != 0x49) continue;
                        if (data[i+1] != 0x89) continue;
                        if (data[i+2] != 0xC9) continue;
                        if (memcmp(data + i, HASH_SIGNATURE, 15) == 0) {
                            uintptr_t found = (uintptr_t)mbi.BaseAddress + i;
                            Log("FOUND signature at 0x%llx (region 0x%llx, size 0x%llx, prot 0x%x)\n",
                                found, (uintptr_t)mbi.BaseAddress, (uint64_t)mbi.RegionSize, mbi.Protect);
                            return found;
                        }
                    }
                }
            } __except(EXCEPTION_EXECUTE_HANDLER) {
                Log("Exception scanning region 0x%llx\n", (uintptr_t)mbi.BaseAddress);
            }
        }
        
        addr = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    }
    
    Log("Scan complete: %d executable regions\n", regionsScanned);
    return 0;
}

// ============================================================================
// ALLOCATE TRAMPOLINE NEAR HOOK TARGET (within 2GB)
// ============================================================================
static void* AllocateNearby(uintptr_t target, size_t size) {
    // Try to allocate within ±2GB of target
    // Walk backward and forward looking for free memory
    
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uintptr_t pageSize = si.dwAllocationGranularity;  // typically 0x10000
    
    Log("Looking for free memory near 0x%llx (page size 0x%llx)\n", target, (uint64_t)pageSize);
    
    // Try positions starting from target, walking back in pageSize increments
    // Within 2GB range = 0x80000000
    
    uintptr_t lowestAddr = (target > 0x7F000000) ? (target - 0x7F000000) : 0;
    uintptr_t highestAddr = target + 0x7F000000;
    
    // Align to page boundary
    lowestAddr = (lowestAddr + pageSize - 1) & ~(pageSize - 1);
    
    Log("Search range: 0x%llx - 0x%llx\n", lowestAddr, highestAddr);
    
    // Walk backward from target first (small offsets preferred)
    for (uintptr_t addr = target & ~(pageSize - 1); addr >= lowestAddr; addr -= pageSize) {
        void* p = VirtualAlloc((LPVOID)addr, size, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_EXECUTE_READWRITE);
        if (p) {
            Log("Allocated trampoline at 0x%llx (offset from target: -0x%llx)\n",
                (uintptr_t)p, target - (uintptr_t)p);
            return p;
        }
    }
    
    // Walk forward from target
    for (uintptr_t addr = (target + pageSize) & ~(pageSize - 1); addr <= highestAddr; addr += pageSize) {
        void* p = VirtualAlloc((LPVOID)addr, size, 
                              MEM_COMMIT | MEM_RESERVE, 
                              PAGE_EXECUTE_READWRITE);
        if (p) {
            Log("Allocated trampoline at 0x%llx (offset from target: +0x%llx)\n",
                (uintptr_t)p, (uintptr_t)p - target);
            return p;
        }
    }
    
    Log("Failed to allocate nearby memory - falling back to any address\n");
    return VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
}

// ============================================================================
// HOOK INSTALLATION
// ============================================================================
// Strategy: trampoline that uses ABSOLUTE JUMPS instead of relative
// Original function first 15 bytes:
//   49 89 C9           mov r9, rcx           (3 bytes)
//   45 85 C0           test r8d, r8d         (3 bytes)
//   0F 84 8E 00 00 00  jz +0x8e              (6 bytes) <- relative!
//   41 FF C8           dec r8d               (3 bytes)
// 
// Trampoline (no relocation needed):
//   49 89 C9                       mov r9, rcx
//   45 85 C0                       test r8d, r8d
//   75 0E                          jne +0xe              ; if NOT zero, skip absolute jump
//   FF 25 00 00 00 00              jmp [rip+0]           ; absolute jump for the jz target
//   <8 bytes>                      dq (hookTarget + 12 + 0x8e)
//   41 FF C8                       dec r8d
//   FF 25 00 00 00 00              jmp [rip+0]           ; return to hookTarget + 15
//   <8 bytes>                      dq (hookTarget + 15)
//
// Total trampoline size: 6 + 2 + 6 + 8 + 3 + 6 + 8 = 39 bytes

static bool InstallTrampolineHook(uintptr_t hookTarget) {
    // Allocate trampoline NEAR hookTarget
    g_TrampolineAddr = (uintptr_t)AllocateNearby(hookTarget, 64);
    
    if (!g_TrampolineAddr) {
        Log("VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }
    
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)hookTarget, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("VirtualProtect failed: %lu\n", GetLastError());
        return false;
    }
    
    uint8_t origBytes[16];
    memcpy(origBytes, (void*)hookTarget, 16);
    
    Log("Original bytes: ");
    for (int i = 0; i < 16; i++) Log("%02X ", origBytes[i]);
    Log("\n");
    
    if (memcmp(origBytes, HASH_SIGNATURE, 15) != 0) {
        Log("ERROR: Bytes no longer match signature\n");
        VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
        return false;
    }
    
    // Build trampoline with ABSOLUTE JUMPS (no relocation needed!)
    uint8_t* tramp = (uint8_t*)g_TrampolineAddr;
    int pos = 0;
    
    // Copy: mov r9, rcx; test r8d, r8d (6 bytes)
    memcpy(tramp + pos, origBytes, 6);
    pos += 6;
    
    // Convert jz +0x8e to: jne +0xe; jmp [rip+0]; dq abs_target
    // jne skips over the absolute jump if condition not met
    tramp[pos++] = 0x75;  // jne
    tramp[pos++] = 0x0E;  // skip 14 bytes (jmp [rip+0] + 8 bytes target)
    
    // jmp [rip+0]
    tramp[pos++] = 0xFF;
    tramp[pos++] = 0x25;
    *(uint32_t*)(tramp + pos) = 0;
    pos += 4;
    
    // Absolute target: hookTarget + 12 + 0x8e
    *(uintptr_t*)(tramp + pos) = hookTarget + 12 + 0x8e;
    pos += 8;
    
    // Copy: dec r8d (3 bytes)
    memcpy(tramp + pos, origBytes + 12, 3);
    pos += 3;
    
    // Return jump: jmp [rip+0] back to hookTarget + 15
    tramp[pos++] = 0xFF;
    tramp[pos++] = 0x25;
    *(uint32_t*)(tramp + pos) = 0;
    pos += 4;
    *(uintptr_t*)(tramp + pos) = hookTarget + 15;
    pos += 8;
    
    Log("Trampoline built: %d bytes\n", pos);
    Log("Trampoline bytes: ");
    for (int i = 0; i < pos; i++) Log("%02X ", tramp[i]);
    Log("\n");
    
    g_OriginalHash = (HashFunc)g_TrampolineAddr;
    
    // Now patch the hookTarget
    // Use 14-byte absolute jump: FF 25 00 00 00 00 + 8 bytes target
    // Need 15 bytes to fully overwrite the signature
    uint8_t patch[15];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    *(uint32_t*)(patch + 2) = 0;
    *(uintptr_t*)(patch + 6) = (uintptr_t)&HookedHash;
    patch[14] = 0x90;  // NOP
    
    memcpy((void*)hookTarget, patch, 15);
    VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
    
    Log("Hook installed at 0x%llx\n", hookTarget);
    Log("  Trampoline: 0x%llx\n", g_TrampolineAddr);
    Log("  HookedHash: 0x%llx\n", (uintptr_t)&HookedHash);
    return true;
}

// ============================================================================
// INIT THREAD
// ============================================================================
static DWORD WINAPI InitThread(LPVOID param) {
    HMODULE hModule = GetModuleHandleA(NULL);
    uintptr_t imageBase = (uintptr_t)hModule;
    
    char modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    
    Log("Init thread started\n");
    Log("Image base: 0x%llx\n", imageBase);
    Log("Module:     %s\n", modulePath);
    
    Sleep(5000);
    
    uintptr_t scanStart = imageBase + 0x01000000;
    uintptr_t scanEnd   = imageBase + 0x20000000;
    
    Log("\n=== SIGNATURE SCAN ===\n");
    Log("Scan range: 0x%llx - 0x%llx\n", scanStart, scanEnd);
    Log("Signature:  49 89 C9 45 85 C0 0F 84 8E 00 00 00 41 FF C8\n\n");
    
    uintptr_t found = 0;
    for (int attempt = 1; attempt <= 30 && !found; attempt++) {
        Log("--- Scan attempt %d/30 ---\n", attempt);
        found = ScanForSignature(scanStart, scanEnd);
        if (!found) {
            Log("Not found, waiting 3s...\n\n");
            Sleep(3000);
        }
    }
    
    if (!found) {
        Log("\nERROR: Hash function signature never found\n");
        return 1;
    }
    
    g_HookTarget = found;
    Log("\nHash function found at: 0x%llx (RVA 0x%llx)\n", found, found - imageBase);
    
    if (!InstallTrampolineHook(g_HookTarget)) {
        Log("Hook installation failed\n");
        return 1;
    }
    
    Log("\n*** HOOK INSTALLED - log-only mode for 15s ***\n\n");
    Sleep(15000);
    g_EnableRedirect = true;
    Log("\n*** REDIRECT ENABLED: stad_419_* -> stad_332_* ***\n\n");
    
    return 0;
}

// ============================================================================
// DLL ENTRY
// ============================================================================
BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        InitializeCriticalSection(&g_LogLock);
        
        char logPath[MAX_PATH];
        GetCurrentDirectoryA(MAX_PATH, logPath);
        strcat_s(logPath, MAX_PATH, "\\stadium_hook.log");
        
        g_LogFile = CreateFileA(
            logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        Log("============================================\n");
        Log("FIFA 16 Stadium 419 Hook DLL v4 (NEAR + ABS JMP)\n");
        Log("============================================\n");
        Log("DLL module: 0x%llx\n", (uintptr_t)hMod);
        Log("Process:    %lu\n", GetCurrentProcessId());
        
        CreateThread(NULL, 0, InitThread, NULL, 0, NULL);
    }
    else if (reason == DLL_PROCESS_DETACH) {
        if (g_LogFile != INVALID_HANDLE_VALUE) {
            Log("DLL detaching\n");
            CloseHandle(g_LogFile);
        }
        DeleteCriticalSection(&g_LogLock);
    }
    return TRUE;
}
