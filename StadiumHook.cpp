// ============================================================================
// FIFA 16 Stadium Hook v3 - MinGW-KOMPATIBLE VERSION (godbolt.org ready)
// ============================================================================
//
// MinGW gcc unterstuetzt KEIN __try/__except (das ist MSVC-only).
// Diese Version nutzt stattdessen VirtualQuery zur Memory-Pruefung.
//
// COPY THIS ENTIRE FILE INTO https://godbolt.org/
//
// COMPILER SETUP:
//   1. Compiler: "MinGW gcc 13.1.0" (oder neuer, ABER NICHT 4.3.0!)
//   2. Compiler options (OHNE -o Flag!):
//      -O2 -shared -static-libgcc -static-libstdc++ -static -Wl,--enable-stdcall-fixup -lkernel32
//   3. Output panel: Zahnrad oeffnen, "Compile to binary object" AKTIVIEREN
//
// DOWNLOAD DLL:
//   Im Output-Panel: "Save" Knopf oder Download-Icon -> StadiumHook.dll
//
// CORRECTED ADDRESS:
//   HASH_FUNC_RVA = 0x3c8f100 (verified via FIFA memory dump)
//   (Original was 0x3c8e100 which pointed to padding bytes)
//
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>
#include <cstdarg>

// CORRECTED address: 0x3c8f100 (was incorrectly 0x3c8e100 in v1)
// Verified via FIFA memory dump analysis
constexpr uintptr_t HASH_FUNC_RVA = 0x3c8f100;

typedef uint64_t (__fastcall *HashFunc)(const char* str, uint64_t init, int mode);

static const uint8_t EXPECTED_SIG[] = {
    0x49, 0x89, 0xC9,
    0x45, 0x85, 0xC0,
    0x0F, 0x84, 0x8E, 0x00, 0x00, 0x00,
    0x41, 0xFF, 0xC8
};

static HashFunc g_OriginalHash = nullptr;
static HANDLE g_LogFile = INVALID_HANDLE_VALUE;
static CRITICAL_SECTION g_LogLock;
static bool g_HookActive = false;
static volatile bool g_EnableRedirect = true;
static uintptr_t g_TrampolineAddr = 0;

static void LogV(const char* fmt, va_list args) {
    if (g_LogFile == INVALID_HANDLE_VALUE) return;
    char buf[2048];
    int len = vsnprintf(buf, sizeof(buf), fmt, args);
    if (len < 0 || len >= (int)sizeof(buf)) {
        len = (int)sizeof(buf) - 1;
        buf[len] = 0;
    }
    EnterCriticalSection(&g_LogLock);
    DWORD written;
    WriteFile(g_LogFile, buf, len, &written, NULL);
    FlushFileBuffers(g_LogFile);
    LeaveCriticalSection(&g_LogLock);
}

static void Log(const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    LogV(fmt, args);
    va_end(args);
}

// Check if memory at p is readable using VirtualQuery (MinGW-compatible)
static bool IsMemoryReadable(const void* p, size_t size) {
    if (!p || (uintptr_t)p < 0x10000) return false;
    MEMORY_BASIC_INFORMATION mbi;
    if (VirtualQuery(p, &mbi, sizeof(mbi)) == 0) return false;
    if (mbi.State != MEM_COMMIT) return false;
    DWORD prot = mbi.Protect;
    // Must be readable
    if (prot & PAGE_NOACCESS) return false;
    if (prot & PAGE_GUARD) return false;
    // Check if entire range is within the same region (simplistic)
    uintptr_t region_end = (uintptr_t)mbi.BaseAddress + mbi.RegionSize;
    uintptr_t check_end = (uintptr_t)p + size;
    return check_end <= region_end;
}

static bool SafeReadString(const char* p, char* out, size_t outSize) {
    if (!p || (uintptr_t)p < 0x10000) return false;
    if (!IsMemoryReadable(p, 1)) return false;
    
    size_t i = 0;
    while (i < outSize - 1) {
        // Check each byte's page is readable (in case string crosses page boundary)
        if ((i & 0xFFF) == 0 && i > 0) {
            if (!IsMemoryReadable(p + i, 1)) break;
        }
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
}

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

static bool WaitForSignature(uintptr_t hookTarget) {
    for (int attempt = 0; attempt < 60; attempt++) {
        if (IsMemoryReadable((void*)hookTarget, sizeof(EXPECTED_SIG))) {
            if (memcmp((void*)hookTarget, EXPECTED_SIG, sizeof(EXPECTED_SIG)) == 0) {
                Log("Signature found after %d attempts\n", attempt);
                return true;
            }
        }
        
        if (attempt == 0 || attempt % 10 == 0) {
            Log("Waiting for function decryption (attempt %d/60)...\n", attempt);
            if (IsMemoryReadable((void*)hookTarget, 15)) {
                uint8_t* p = (uint8_t*)hookTarget;
                Log("  Current bytes: %02x %02x %02x %02x %02x %02x %02x %02x"
                    " %02x %02x %02x %02x %02x %02x %02x\n",
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                    p[8], p[9], p[10], p[11], p[12], p[13], p[14]);
            } else {
                Log("  Memory not yet readable\n");
            }
        }
        Sleep(1000);
    }
    Log("ERROR: Signature never appeared\n");
    return false;
}

static bool InstallTrampolineHook(uintptr_t hookTarget, void* hookFunc) {
    g_TrampolineAddr = (uintptr_t)VirtualAlloc(
        NULL, 64, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!g_TrampolineAddr) {
        Log("VirtualAlloc failed: %lu\n", GetLastError());
        return false;
    }
    Log("Trampoline allocated at 0x%llx\n", g_TrampolineAddr);
    
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)hookTarget, 32, PAGE_EXECUTE_READWRITE, &oldProtect)) {
        Log("VirtualProtect failed: %lu\n", GetLastError());
        return false;
    }
    
    uint8_t origBytes[16];
    memcpy(origBytes, (void*)hookTarget, 16);
    
    if (memcmp(origBytes, EXPECTED_SIG, sizeof(EXPECTED_SIG)) != 0) {
        Log("ERROR: Signature mismatch at hook install time!\n");
        VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
        return false;
    }
    
    uint8_t* tramp = (uint8_t*)g_TrampolineAddr;
    memcpy(tramp, origBytes, 6);
    
    uintptr_t jzTarget = hookTarget + 12 + 0x8e;
    int64_t newDisp = (int64_t)jzTarget - (int64_t)(g_TrampolineAddr + 12);
    if (newDisp < INT32_MIN || newDisp > INT32_MAX) {
        Log("ERROR: jz target out of range\n");
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
    
    uint8_t patch[14] = {
        0xFF, 0x25, 0x00, 0x00, 0x00, 0x00,
        0, 0, 0, 0, 0, 0, 0, 0
    };
    *(uintptr_t*)(patch + 6) = (uintptr_t)hookFunc;
    memcpy((void*)hookTarget, patch, 14);
    ((uint8_t*)hookTarget)[14] = 0x90;
    
    VirtualProtect((LPVOID)hookTarget, 32, oldProtect, &oldProtect);
    
    Log("Hook installed at 0x%llx (tramp 0x%llx, hook 0x%llx)\n",
        hookTarget, g_TrampolineAddr, (uintptr_t)hookFunc);
    return true;
}

static DWORD WINAPI InitThread(LPVOID param) {
    Log("Init thread started\n");
    Sleep(10000);
    
    HMODULE hModule = GetModuleHandleA(NULL);
    uintptr_t imageBase = (uintptr_t)hModule;
    uintptr_t hashFuncAddr = imageBase + HASH_FUNC_RVA;
    
    char moduleName[MAX_PATH] = {0};
    GetModuleFileNameA(hModule, moduleName, MAX_PATH);
    
    Log("Image base:    0x%llx\n", imageBase);
    Log("Module:        %s\n", moduleName);
    Log("Hash function: 0x%llx (RVA 0x%llx)\n", hashFuncAddr, (uintptr_t)HASH_FUNC_RVA);
    
    if (!WaitForSignature(hashFuncAddr)) {
        return 1;
    }
    
    if (InstallTrampolineHook(hashFuncAddr, (void*)&HookedHash)) {
        g_HookActive = true;
        Log("\n*** HOOK ACTIVE - Redirect %s ***\n\n",
            g_EnableRedirect ? "ENABLED" : "DISABLED");
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE hMod, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(hMod);
        InitializeCriticalSection(&g_LogLock);
        
        char logPath[MAX_PATH];
        DWORD len = GetCurrentDirectoryA(MAX_PATH, logPath);
        if (len > 0 && len + 20 < MAX_PATH) {
            // Append "\\stadium_hook.log" manually for MinGW compatibility
            const char* suffix = "\\stadium_hook.log";
            size_t suflen = 18; // length of suffix incl. null
            for (size_t i = 0; i < suflen && len + i < MAX_PATH - 1; i++) {
                logPath[len + i] = suffix[i];
            }
            logPath[MAX_PATH - 1] = 0;
        }
        
        g_LogFile = CreateFileA(
            logPath, GENERIC_WRITE, FILE_SHARE_READ, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        
        Log("============================================\n");
        Log("FIFA 16 Stadium 419 Hook DLL v2\n");
        Log("============================================\n");
        Log("DLL module:    0x%llx\n", (uintptr_t)hMod);
        Log("Process:       %lu\n", GetCurrentProcessId());
        Log("HASH_FUNC_RVA: 0x%llx (CORRECTED)\n", (uintptr_t)HASH_FUNC_RVA);
        
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
