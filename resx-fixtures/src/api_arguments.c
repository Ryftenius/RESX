#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winioctl.h>

/* Static analysis fixtures only. Integration tests must not load this DLL. */
__declspec(dllexport) BOOL ResxIoctlKnown(HANDLE device, void *output)
{
    DWORD returned = 0;
    return DeviceIoControl(device,
        CTL_CODE(0x8337u, 0x801, METHOD_BUFFERED, FILE_WRITE_ACCESS),
        NULL, 0, output, 32, &returned, NULL);
}

__declspec(dllexport) BOOL ResxOidKnown(HANDLE device, void *output)
{
    static const DWORD oid = 0x00010101;
    DWORD returned = 0;
    return DeviceIoControl(device,
        CTL_CODE(FILE_DEVICE_PHYSICAL_NETCARD, 0, METHOD_OUT_DIRECT, FILE_ANY_ACCESS),
        (void *)&oid, sizeof(oid), output, 32, &returned, NULL);
}

__declspec(dllexport) BOOL ResxNamedDevice(void)
{
    HANDLE device = CreateFileW(L"\\\\.\\RESX_FIXTURE_ONLY", GENERIC_READ,
        0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD returned = 0;
    BOOL result = DeviceIoControl(device,
        CTL_CODE(0x8337u, 0x802, METHOD_BUFFERED, FILE_READ_ACCESS),
        NULL, 0, NULL, 0, &returned, NULL);
    CloseHandle(device);
    return result;
}

__declspec(dllexport) DWORD ResxOnlyAConstant(void)
{
    return CTL_CODE(0x8337u, 0x803, METHOD_BUFFERED, FILE_READ_ACCESS);
}
