#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>

/*
 * Static-analysis fixture for hashed API resolution. Modules and exports are found by
 * ROR13 hashes instead of names, as shellcode and loaders commonly do. The executable
 * page holds only RET and is never called; the program prints lengths, not values.
 *
 * Module hash: ROR13 over the uppercase UTF-16 base name. Export hash: ROR13 over the
 * ASCII name. Neither name appears in the image.
 */
#define H_KERNEL32 0x6A4ABC5Bu      /* KERNEL32.DLL */
#define H_ADVAPI32 0xC78A43F4u      /* ADVAPI32.DLL */
#define H_LOADLIBRARYA 0xEC0E4E8Eu
#define H_VIRTUALALLOC 0x91AFCA54u
#define H_VIRTUALPROTECT 0x7946C61Bu
#define H_VIRTUALFREE 0x030633ACu
#define H_GETCOMPUTERNAMEW 0x96A422A5u
#define H_GETUSERNAMEW 0x5C52AA4Au

static __forceinline uint32_t ror13(uint32_t h) { return _rotr(h, 13); }

__declspec(noinline) static uint32_t hash_ascii(const char *s) {
    uint32_t h = 0;
    while (*s) h = ror13(h) + (uint8_t)*s++;
    return h;
}

__declspec(noinline) static uint32_t hash_module(const WCHAR *s, USHORT bytes) {
    uint32_t h = 0;
    USHORT i;
    for (i = 0; i < bytes / sizeof(WCHAR); ++i) {
        WCHAR c = s[i];
        if (c >= L'a' && c <= L'z') c -= L'a' - L'A';
        h = ror13(h) + (uint8_t)c;
        h = ror13(h);
    }
    return h;
}

__declspec(noinline) static BYTE *find_module(uint32_t wanted) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    LIST_ENTRY *head, *it;
    if (!peb || !peb->Ldr) return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (it = head->Flink; it && it != head; it = it->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(it, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        /* BaseDllName follows FullDllName in LDR_DATA_TABLE_ENTRY. */
        UNICODE_STRING *base_name = (UNICODE_STRING *)((BYTE *)&e->FullDllName + sizeof(UNICODE_STRING));
        if (base_name->Buffer && hash_module(base_name->Buffer, base_name->Length) == wanted)
            return (BYTE *)e->DllBase;
    }
    return NULL;
}

__declspec(noinline) static FARPROC find_export(BYTE *base, uint32_t wanted) {
    IMAGE_NT_HEADERS *nt;
    IMAGE_DATA_DIRECTORY dir;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names, *functions;
    WORD *ordinals;
    DWORD i;
    if (!base || ((IMAGE_DOS_HEADER *)base)->e_magic != IMAGE_DOS_SIGNATURE) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + ((IMAGE_DOS_HEADER *)base)->e_lfanew);
    dir = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (nt->Signature != IMAGE_NT_SIGNATURE || !dir.VirtualAddress) return NULL;
    exp = (IMAGE_EXPORT_DIRECTORY *)(base + dir.VirtualAddress);
    names = (DWORD *)(base + exp->AddressOfNames);
    functions = (DWORD *)(base + exp->AddressOfFunctions);
    ordinals = (WORD *)(base + exp->AddressOfNameOrdinals);
    for (i = 0; i < exp->NumberOfNames; ++i) {
        if (hash_ascii((const char *)(base + names[i])) == wanted && ordinals[i] < exp->NumberOfFunctions) {
            DWORD rva = functions[ordinals[i]];
            if (rva >= dir.VirtualAddress && rva - dir.VirtualAddress < dir.Size) return NULL;
            return (FARPROC)(base + rva);
        }
    }
    return NULL;
}

typedef HMODULE (WINAPI *loadlibrary_fn)(LPCSTR);
typedef LPVOID (WINAPI *alloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *protect_fn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *free_fn)(LPVOID, SIZE_T, DWORD);
typedef BOOL (WINAPI *computer_fn)(LPWSTR, LPDWORD);
typedef BOOL (WINAPI *user_fn)(LPWSTR, LPDWORD);

int main(void) {
    BYTE *kernel32 = find_module(H_KERNEL32);
    loadlibrary_fn load = (loadlibrary_fn)find_export(kernel32, H_LOADLIBRARYA);
    alloc_fn alloc = (alloc_fn)find_export(kernel32, H_VIRTUALALLOC);
    protect_fn protect = (protect_fn)find_export(kernel32, H_VIRTUALPROTECT);
    free_fn release = (free_fn)find_export(kernel32, H_VIRTUALFREE);
    computer_fn computer = (computer_fn)find_export(kernel32, H_GETCOMPUTERNAMEW);
    char advapi[] = {'a', 'd', 'v', 'a', 'p', 'i', '3', '2', 0};
    BYTE *advapi32;
    user_fn user;
    WCHAR name[256];
    DWORD size, old;
    BYTE *page;

    if (!load || !alloc || !protect || !release || !computer) {
        puts("API resolution failed");
        return 1;
    }
    load(advapi);
    advapi32 = find_module(H_ADVAPI32);
    user = (user_fn)find_export(advapi32, H_GETUSERNAMEW);
    if (!user) {
        puts("API resolution failed");
        return 1;
    }

    size = (DWORD)(sizeof(name) / sizeof(name[0]));
    printf("computer name length: %lu\n", computer(name, &size) ? size : 0);
    size = (DWORD)(sizeof(name) / sizeof(name[0]));
    printf("user name length: %lu\n", user(name, &size) ? size : 0);

    page = (BYTE *)alloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return 2;
    page[0] = 0xc3;
    if (!protect(page, 4096, PAGE_EXECUTE_READ, &old)) {
        release(page, 0, MEM_RELEASE);
        return 3;
    }
    if (!release(page, 0, MEM_RELEASE)) return 4;
    puts("Inert page: allocated, written, made executable, released.");
    return 0;
}
