/* Static inspection fixtures. Exported functions are never invoked by tests. */
#define WIN32_LEAN_AND_MEAN
#include <winsock2.h>
#include <windows.h>
#include <winhttp.h>
#include <bcrypt.h>
#include <wincrypt.h>
#include <rpc.h>
#include <objbase.h>

__declspec(dllexport) __declspec(noinline) HANDLE ResxPipeServer(void) {
    HANDLE pipe = CreateNamedPipeW(L"\\\\.\\pipe\\resx-contract-fixture", PIPE_ACCESS_DUPLEX,
        PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE, 2, 1024, 2048, 50, NULL);
    ConnectNamedPipe(pipe, NULL);
    return pipe;
}

__declspec(dllexport) __declspec(noinline) HANDLE ResxPipeClient(void) {
    HANDLE pipe = CreateFileW(L"\\\\.\\pipe\\resx-contract-fixture", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, 0, NULL);
    DWORD received = 0;
    BYTE output[16];
    TransactNamedPipe(pipe, (void *)"request", 7, output, sizeof(output), &received, NULL);
    return pipe;
}

__declspec(dllexport) __declspec(noinline) void *ResxSharedMapping(void) {
    HANDLE section = CreateFileMappingW(INVALID_HANDLE_VALUE, NULL, PAGE_READWRITE, 0, 4096,
        L"Local\\RESX-Contract-Mapping");
    return MapViewOfFile(section, FILE_MAP_READ, 0, 0, 4096);
}

__declspec(dllexport) __declspec(noinline) RPC_STATUS ResxRpcEndpoint(void) {
    return RpcServerUseProtseqEpW((RPC_WSTR)L"ncalrpc", 8,
        (RPC_WSTR)L"RESX-Contract-RPC", NULL);
}

__declspec(dllexport) __declspec(noinline) HINTERNET ResxHttpConfiguration(void) {
    HINTERNET session = WinHttpOpen(L"RESX-Offline-Fixture", WINHTTP_ACCESS_TYPE_NO_PROXY,
        WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    HINTERNET connection = WinHttpConnect(session, L"fixture.invalid", 443, 0);
    return WinHttpOpenRequest(connection, L"POST", L"/fixture", NULL,
        WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, WINHTTP_FLAG_SECURE);
}

__declspec(dllexport) __declspec(noinline) int ResxSocketEndpoint(SOCKET socket_handle) {
    static const struct sockaddr_in address = { AF_INET, 0x901f, {{127,0,0,1}}, {0} };
    return connect(socket_handle, (const struct sockaddr *)&address, sizeof(address));
}

__declspec(dllexport) __declspec(noinline) NTSTATUS ResxCryptoConfiguration(void) {
    BCRYPT_ALG_HANDLE algorithm = NULL;
    NTSTATUS result = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    result |= BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
        (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    return result;
}

__declspec(dllexport) __declspec(noinline) BOOL ResxCryptoLegacy(HCRYPTPROV provider) {
    HCRYPTKEY key = 0;
    return CryptGenKey(provider, CALG_AES_256, 0, &key);
}

__declspec(dllexport) __declspec(noinline) HRESULT ResxComClass(void **object) {
    static const GUID class_id = {0x12345678,0x9abc,0xdef0,{0x81,0x23,0x45,0x67,0x89,0xab,0xcd,0xef}};
    static const GUID interface_id = {0x87654321,0xcba9,0x0fed,{0xfe,0xdc,0xba,0x98,0x76,0x54,0x32,0x10}};
    return CoCreateInstance(&class_id, NULL, CLSCTX_LOCAL_SERVER, &interface_id, object);
}

/* These import names previously generated incorrect networking/crypto hints. */
__declspec(dllexport) __declspec(noinline) LSTATUS ResxRegistryOnly(HKEY key) {
    return RegCloseKey(key);
}

__declspec(dllexport) __declspec(noinline) HINTERNET ResxUnknownHost(HINTERNET session, int select) {
    const WCHAR *host = select ? L"one.invalid" : L"two.invalid";
    return WinHttpConnect(session, host, 80, 0);
}

__declspec(dllexport) __declspec(noinline) NTSTATUS ResxTruncatedMode(BCRYPT_ALG_HANDLE algorithm) {
    return BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE, (PUCHAR)L"ChainingModeCBC", 4, 0);
}

/* A self-contained native UNICODE_STRING layout, checked by the compiler. */
typedef struct { USHORT Length; USHORT MaximumLength; const WCHAR *Buffer; } RESX_USTRING;
C_ASSERT(sizeof(RESX_USTRING) == 16);
C_ASSERT(FIELD_OFFSET(RESX_USTRING, Buffer) == 8);
__declspec(dllimport) LONG NTAPI NtAlpcConnectPort(void *, const RESX_USTRING *, void *, void *, ULONG, void *, void *, void *, void *, void *, void *);
__declspec(dllexport) __declspec(noinline) LONG ResxAlpcName(void) {
    static const WCHAR name[] = L"\\RPC Control\\RESX-Contract-ALPC";
    static const RESX_USTRING text = {sizeof(name)-2, sizeof(name), name};
    HANDLE port = NULL;
    return NtAlpcConnectPort(&port, &text, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
}

__declspec(dllexport) __declspec(noinline) LONG ResxAlpcBadLength(void) {
    static const WCHAR name[] = L"\\RPC Control\\invalid";
    static const RESX_USTRING text = {100, 2, name};
    HANDLE port = NULL;
    return NtAlpcConnectPort(&port, &text, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL);
}
