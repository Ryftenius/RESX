#pragma once

#ifdef RESX_FIXTURES_EXPORTS
#define RESX_FIXTURES_API __declspec(dllexport)
#else
#define RESX_FIXTURES_API __declspec(dllimport)
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef int (__cdecl *ResxFixturesCallback)(int value);

RESX_FIXTURES_API int ResxParsePacket(const unsigned char *data, unsigned int len);
RESX_FIXTURES_API int ResxDeviceIoctlDispatch(unsigned int code, void *buffer, unsigned int len);
RESX_FIXTURES_API unsigned long __stdcall ResxThreadCallbackEntry(void *ctx);
RESX_FIXTURES_API int ResxSwitchJumpTableDispatch(unsigned int opcode, int value);
RESX_FIXTURES_API int ResxIndirectCallMessage(ResxFixturesCallback callback, int value);
RESX_FIXTURES_API int ResxBehaviorSignals(unsigned int selector);

#ifdef __cplusplus
}
#endif
