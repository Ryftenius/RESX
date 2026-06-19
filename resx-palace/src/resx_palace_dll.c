#define WIN32_LEAN_AND_MEAN
#define RESX_PALACE_EXPORTS
#include <windows.h>
#include <intrin.h>
#include "resx_palace.h"

static volatile LONG g_resx_sink;
static const char g_resx_palace_protector_marker[] =
    "UPX! VMProtect Themida virtual machine kernel32.dll GetProcAddress";

static void NTAPI ResxPalaceTlsCallback(PVOID module, DWORD reason, PVOID reserved);

#pragma section(".text$resx", execute, read)
__declspec(allocate(".text$resx")) __declspec(align(16))
const unsigned char g_resx_palace_syscall_stub_bytes[] = {
    0x4C, 0x8B, 0xD1,             /* mov r10, rcx */
    0xB8, 0x34, 0x12, 0x00, 0x00, /* mov eax, 0x1234 */
    0x0F, 0x05,                   /* syscall */
    0xC3                          /* ret */
};

#pragma section(".CRT$XLB", long, read)
#ifdef _M_IX86
#pragma comment(linker, "/INCLUDE:__tls_used")
#else
#pragma comment(linker, "/INCLUDE:_tls_used")
#endif
__declspec(allocate(".CRT$XLB")) PIMAGE_TLS_CALLBACK g_resx_palace_tls_callback =
    ResxPalaceTlsCallback;

static int palace_add(int value) {
    return value + 17;
}

static int palace_xor(int value) {
    return value ^ 0x5A5A;
}

static int palace_mix(int value) {
    return (value * 3) - 9;
}

RESX_PALACE_API int ResxParsePacket(const unsigned char *data, unsigned int len) {
    unsigned int cursor = 0;
    int score = 0;

    while (cursor + 2 <= len) {
        unsigned char tag = data[cursor++];
        unsigned char size = data[cursor++];
        if (cursor + size > len) {
            return -10;
        }

        switch (tag) {
        case 0x01:
            score += size;
            break;
        case 0x02:
            score ^= data[cursor];
            break;
        case 0x10:
            if (size >= 4 && data[cursor] == 'R' && data[cursor + 1] == 'E') {
                score += 100;
            }
            break;
        default:
            score -= tag;
            break;
        }
        cursor += size;
    }

    InterlockedExchange(&g_resx_sink, score);
    return score;
}

RESX_PALACE_API int ResxDeviceIoctlDispatch(unsigned int code, void *buffer, unsigned int len) {
    unsigned char *bytes = (unsigned char *)buffer;

    if (buffer == 0 || len == 0) {
        return -1;
    }

    if (code == 0x222000) {
        bytes[0] ^= 0xA5;
        return (int)bytes[0];
    }
    if (code == 0x222004 && len >= 4) {
        return ResxParsePacket(bytes, len);
    }
    if ((code & 3) == 3) {
        return (int)(len + code);
    }
    return -2;
}

RESX_PALACE_API DWORD WINAPI ResxThreadCallbackEntry(void *ctx) {
    int value = ctx ? *(int *)ctx : 0;
    InterlockedAdd(&g_resx_sink, value);
    return (DWORD)(value + 1);
}

RESX_PALACE_API int ResxSwitchJumpTableDispatch(unsigned int opcode, int value) {
    switch (opcode) {
    case 0:
        return value + 1;
    case 1:
        return value - 1;
    case 2:
        return value * 2;
    case 3:
        return value / 2;
    case 4:
        return value ^ 0x33;
    case 5:
        return value | 0x100;
    case 6:
        return value & 0x7F;
    case 7:
        return value + palace_add(value);
    case 8:
        return palace_xor(value);
    case 9:
        return palace_mix(value);
    default:
        return -100;
    }
}

RESX_PALACE_API int ResxIndirectCallMessage(ResxPalaceCallback callback, int value) {
    ResxPalaceCallback table[3];
    unsigned int index = (unsigned int)value % 3;

    table[0] = palace_add;
    table[1] = palace_xor;
    table[2] = callback ? callback : palace_mix;

    return table[index](value);
}

RESX_PALACE_API int ResxBehaviorSignals(unsigned int selector) {
    int cpu_info[4] = {0, 0, 0, 0};
    DWORD old_protect = 0;
    unsigned char *code = (unsigned char *)VirtualAlloc(
        0,
        64,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);
    HMODULE kernel = LoadLibraryA("kernel32.dll");
    FARPROC tick_proc = kernel ? GetProcAddress(kernel, "GetTickCount") : 0;

    __cpuid(cpu_info, 1);
    if ((selector & 1U) != 0U) {
        __debugbreak();
    }

    if (code != 0) {
        code[0] = 0xC3;
        VirtualProtect(code, 64, PAGE_EXECUTE_READ, &old_protect);
        FlushInstructionCache(GetCurrentProcess(), code, 64);
        if ((selector & 2U) != 0U) {
            ((void (__cdecl *)(void))code)();
        }
        VirtualFree(code, 0, MEM_RELEASE);
    }

    if (kernel != 0) {
        FreeLibrary(kernel);
    }

    return cpu_info[0] ^ (tick_proc != 0 ? 0x55 : 0) ^ g_resx_palace_protector_marker[0];
}

static void NTAPI ResxPalaceTlsCallback(PVOID module, DWORD reason, PVOID reserved) {
    (void)module;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InterlockedExchange(&g_resx_sink, 7);
    }
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InterlockedExchange(&g_resx_sink, 1);
    }
    return TRUE;
}
