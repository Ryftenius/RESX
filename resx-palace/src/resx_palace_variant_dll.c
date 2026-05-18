#define WIN32_LEAN_AND_MEAN
#define RESX_PALACE_EXPORTS
#include <windows.h>
#include "resx_palace.h"

static volatile LONG g_resx_variant_sink;

static int palace_add(int value) {
    return value + 19;
}

static int palace_xor(int value) {
    return value ^ 0x6B6B;
}

static int palace_mix(int value) {
    return (value * 5) - 11;
}

static int palace_guard_score(const unsigned char *data, unsigned int len) {
    unsigned int i = 0;
    int score = 7;

    while (i < len) {
        score += (int)(data[i] ^ (unsigned char)i);
        if ((data[i] & 0x80) != 0) {
            score ^= 0x31;
        }
        ++i;
    }
    return score;
}

RESX_PALACE_API int ResxParsePacket(const unsigned char *data, unsigned int len) {
    unsigned int cursor = 0;
    int score = 0;

    while (cursor + 2 <= len) {
        unsigned char tag = data[cursor++];
        unsigned char size = data[cursor++];
        if (cursor + size > len) {
            return -12;
        }

        switch (tag) {
        case 0x01:
            score += (int)size + 1;
            break;
        case 0x02:
            score ^= (int)(data[cursor] + 3);
            break;
        case 0x10:
            if (size >= 4 && data[cursor] == 'R' && data[cursor + 1] == 'X') {
                score += 113;
            }
            break;
        case 0x20:
            score += palace_guard_score(data + cursor, size);
            break;
        default:
            score -= (int)(tag ^ 0x11);
            break;
        }
        cursor += size;
    }

    InterlockedExchange(&g_resx_variant_sink, score);
    return score;
}

RESX_PALACE_API int ResxDeviceIoctlDispatch(unsigned int code, void *buffer, unsigned int len) {
    unsigned char *bytes = (unsigned char *)buffer;

    if (buffer == 0 || len == 0) {
        return -1;
    }

    if (code == 0x222000) {
        bytes[0] ^= 0xB7;
        return (int)bytes[0];
    }
    if (code == 0x222004 && len >= 4) {
        return ResxParsePacket(bytes, len);
    }
    if (code == 0x222008 && len >= 2) {
        bytes[1] = (unsigned char)(bytes[1] + 9);
        return palace_guard_score(bytes, len);
    }
    if ((code & 3) == 3) {
        return (int)(len + code + 4);
    }
    return -3;
}

RESX_PALACE_API DWORD WINAPI ResxThreadCallbackEntry(void *ctx) {
    int value = ctx ? *(int *)ctx : 0;
    InterlockedAdd(&g_resx_variant_sink, value + 2);
    return (DWORD)(value + 2);
}

RESX_PALACE_API int ResxSwitchJumpTableDispatch(unsigned int opcode, int value) {
    switch (opcode) {
    case 0:
        return value + 1;
    case 1:
        return value - 2;
    case 2:
        return value * 2;
    case 3:
        return value / 2;
    case 4:
        return value ^ 0x44;
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
    case 10:
        return palace_guard_score((const unsigned char *)&value, sizeof(value));
    default:
        return -120;
    }
}

RESX_PALACE_API int ResxIndirectCallMessage(ResxPalaceCallback callback, int value) {
    ResxPalaceCallback table[4];
    unsigned int index = (unsigned int)value % 4;

    table[0] = palace_add;
    table[1] = palace_xor;
    table[2] = callback ? callback : palace_mix;
    table[3] = palace_mix;

    return table[index](value);
}

BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved) {
    (void)instance;
    (void)reserved;
    if (reason == DLL_PROCESS_ATTACH) {
        InterlockedExchange(&g_resx_variant_sink, 2);
    }
    return TRUE;
}
