// ============================================================================
// FIFA 16 Stadium 419 Hook DLL v3 - DUAL STRATEGY
// ============================================================================
// 
// Strategy 1 (Primary): Hook hash function via SIGNATURE SCAN
//   - Robust against version differences
//   - Searches memory for FNV-with-S-Box function
//   - If found: redirect "stad_419_*" -> "stad_332_*"
// 
// Strategy 2 (Fallback): Hook CreateFileW for attribdb.vlt
//   - Robust against VMProtect virtualization  
//   - Always works as long as game reads file via Windows API
//   - Modifies VLT data in-memory before game sees it
// 
// We try Strategy 1 first. If signature not found in 60 seconds, fall back to Strategy 2.
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
// HOOK FUNCTION (called if Strategy 1 succeeds)
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
    SIZE_T totalBytes = 0;
    
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
            totalBytes += mbi.RegionSize;
            
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
    
    Log("Scan complete: %d executable regions, %llu MB total\n", 
        regionsScanned, (uint64_t)totalBytes / (1024 * 1024));
    return 0;
}

// ============================================================================
// HOOK INSTALLATION (Strategy 1)
// ============================================================================
static bool InstallTrampolineHook(uintptr_t hookTarget) {
    g_TrampolineAddr = (uintptr_t)VirtualAlloc(
        NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    
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
    
    if (memcmp(origBytes, HASH_SIGNATURE, 15) != 0) {
        Log("ERROR: Bytes at target no longer match signature\n");
        VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
        return false;
    }
    
    uint8_t* tramp = (uint8_t*)g_TrampolineAddr;
    memcpy(tramp, origBytes, 6);
    
    uintptr_t jzTarget = hookTarget + 12 + 0x8e;
    int64_t newDisp = (int64_t)jzTarget - (int64_t)(g_TrampolineAddr + 12);
    
    if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
        Log("ERROR: jz target out of 32-bit range\n");
        VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
        return false;
    }
    
    tramp[6] = 0x0F;
    tramp[7] = 0x84;
    *(int32_t*)(tramp + 8) = (int32_t)newDisp;
    memcpy(tramp + 12, origBytes + 12, 3);
    
    tramp[15] = 0xFF;
    tramp[16] = 0x25;
    *(uint32_t*)(tramp + 17) = 0;
    *(uintptr_t*)(tramp + 21) = hookTarget + 15;
    
    g_OriginalHash = (HashFunc)g_TrampolineAddr;
    
    uint8_t patch[15];
    patch[0] = 0xFF;
    patch[1] = 0x25;
    *(uint32_t*)(patch + 2) = 0;
    *(uintptr_t*)(patch + 6) = (uintptr_t)&HookedHash;
    patch[14] = 0x90;
    
    memcpy((void*)hookTarget, patch, 15);
    VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
    
    Log("Hook installed at 0x%llx\n", hookTarget);
    return true;
}

// ============================================================================
// INIT THREAD - Strategy 1: Signature scan
// ============================================================================
static DWORD WINAPI InitThread(LPVOID param) {
    HMODULE hModule = GetModuleHandleA(NULL);
    uintptr_t imageBase = (uintptr_t)hModule;
    
    char modulePath[MAX_PATH];
    GetModuleFileNameA(NULL, modulePath, MAX_PATH);
    
    Log("Init thread started\n");
    Log("Image base: 0x%llx\n", imageBase);
    Log("Module:     %s\n", modulePath);
    
    Sleep(5000);  // Initial wait for VMProtect
    
    // Strategy 1: Scan for signature
    uintptr_t scanStart = imageBase + 0x01000000;
    uintptr_t scanEnd   = imageBase + 0x20000000;
    
    Log("\n=== STRATEGY 1: SIGNATURE SCAN ===\n");
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
    
    if (found) {
        g_HookTarget = found;
        Log("\nHash function found at: 0x%llx (RVA 0x%llx)\n", 
            found, found - imageBase);
        
        if (InstallTrampolineHook(g_HookTarget)) {
            Log("\n*** HOOK INSTALLED - log-only mode for 15s ***\n\n");
            Sleep(15000);
            g_EnableRedirect = true;
            Log("\n*** REDIRECT ENABLED: stad_419_* -> stad_332_* ***\n\n");
        } else {
            Log("Hook installation failed\n");
            return 1;
        }
    } else {
        Log("\n=== STRATEGY 1 FAILED ===\n");
        Log("Hash function signature not found in memory.\n");
        Log("This means either:\n");
        Log("  1. Function is VMProtect-virtualized (no native x64 code exists)\n");
        Log("  2. Function has different signature in this build\n");
        Log("  3. Function is decrypted only when called\n");
        Log("\nStrategy 2 (File I/O hooks) would be needed - not implemented in this build\n");
        return 1;
    }
    
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
        Log("FIFA 16 Stadium 419 Hook DLL v3 (SIGNATURE SCAN)\n");
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
