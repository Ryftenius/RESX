#pragma once

#ifdef RESX_PALACE_EXPORTS
#define RESX_PALACE_API __declspec(dllexport)
#else
#define RESX_PALACE_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (__cdecl *ResxPalaceCallback)(int value);

RESX_PALACE_API int ResxParsePacket(const unsigned char *data, unsigned int len);
RESX_PALACE_API int ResxDeviceIoctlDispatch(unsigned int code, void *buffer, unsigned int len);
RESX_PALACE_API unsigned long __stdcall ResxThreadCallbackEntry(void *ctx);
RESX_PALACE_API int ResxSwitchJumpTableDispatch(unsigned int opcode, int value);
RESX_PALACE_API int ResxIndirectCallMessage(ResxPalaceCallback callback, int value);
RESX_PALACE_API int ResxBehaviorSignals(unsigned int selector);

#ifdef __cplusplus
}
#endif
