#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include "resx_palace.h"

static int __cdecl local_callback(int value) {
    return value + 101;
}

int main(void) {
    unsigned char packet[] = {
        0x01, 0x02, 0xAA, 0x55,
        0x10, 0x04, 'R', 'E', 'S', 'X',
    };
    int thread_value = 7;
    DWORD thread_id = 0;
    DWORD bytes_returned = 0;
    HANDLE thread_handle;
    HANDLE console_handle;
    int result = 0;

    result += ResxParsePacket(packet, (unsigned int)sizeof(packet));
    result += ResxDeviceIoctlDispatch(0x222004, packet, (unsigned int)sizeof(packet));
    result += ResxSwitchJumpTableDispatch((unsigned int)(result & 7), result);
    result += ResxIndirectCallMessage(local_callback, result);

    thread_handle = CreateThread(
        0,
        0,
        ResxThreadCallbackEntry,
        &thread_value,
        0,
        &thread_id);
    if (thread_handle) {
        WaitForSingleObject(thread_handle, 1000);
        CloseHandle(thread_handle);
    }

    console_handle = GetStdHandle(STD_INPUT_HANDLE);
    DeviceIoControl(
        console_handle,
        0x222000,
        packet,
        (DWORD)sizeof(packet),
        packet,
        (DWORD)sizeof(packet),
        &bytes_returned,
        0);

    return result == 0 ? 1 : 0;
}
