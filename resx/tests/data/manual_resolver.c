#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <winternl.h>
#include <intrin.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* Static-analysis fixture. The executable page holds only RET and is never called. */
#define KEY 0x5a
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
static const unsigned char n_alloc[] = {0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x1b,0x36,0x36,0x35,0x39};
static const unsigned char n_protect[] = {0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x0a,0x28,0x35,0x2e,0x3f,0x39,0x2e};
static const unsigned char n_free[] = {0x0c,0x33,0x28,0x2e,0x2f,0x3b,0x36,0x1c,0x28,0x3f,0x3f};
static const unsigned char n_first[] = {0x1c,0x33,0x34,0x3e,0x1c,0x33,0x28,0x29,0x2e,0x1c,0x33,0x36,0x3f,0x0d};
static const unsigned char n_next[] = {0x1c,0x33,0x34,0x3e,0x14,0x3f,0x22,0x2e,0x1c,0x33,0x36,0x3f,0x0d};
static const unsigned char n_close[] = {0x1c,0x33,0x34,0x3e,0x19,0x36,0x35,0x29,0x3f};
static const unsigned char n_error[] = {0x1d,0x3f,0x2e,0x16,0x3b,0x29,0x2e,0x1f,0x28,0x28,0x35,0x28};

static int equal_ci_wide(const WCHAR *s, USHORT bytes, const WCHAR *wanted) {
    size_t n = bytes / sizeof(WCHAR), i, j = 0;
    for (i = 0; i < n; ++i) if (s[i] == L'\\' || s[i] == L'/') j = i + 1;
    for (i = j; i < n && *wanted; ++i, ++wanted) {
        WCHAR a = s[i], b = *wanted;
        if (a >= L'A' && a <= L'Z') a += L'a' - L'A';
        if (b >= L'A' && b <= L'Z') b += L'a' - L'A';
        if (a != b) return 0;
    }
    return i == n && !*wanted;
}

__declspec(noinline) static BYTE *find_module(const WCHAR *name) {
    PPEB peb = (PPEB)__readgsqword(0x60);
    LIST_ENTRY *head, *it;
    if (!peb || !peb->Ldr) return NULL;
    head = &peb->Ldr->InMemoryOrderModuleList;
    for (it = head->Flink; it && it != head; it = it->Flink) {
        PLDR_DATA_TABLE_ENTRY e = CONTAINING_RECORD(it, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (e->FullDllName.Buffer && equal_ci_wide(e->FullDllName.Buffer,
                e->FullDllName.Length, name)) return (BYTE *)e->DllBase;
    }
    return NULL;
}

__declspec(noinline) static FARPROC resolve_export(BYTE *base,
        const unsigned char *encoded, size_t len) {
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS *nt;
    IMAGE_EXPORT_DIRECTORY *exp;
    DWORD *names, *functions;
    WORD *ordinals;
    DWORD i;
    char decoded[64];
    size_t j;
    if (!base || len == 0 || len >= sizeof(decoded)) return NULL;
    for (j = 0; j < len; ++j) decoded[j] = (char)(encoded[j] ^ KEY);
    decoded[len] = 0;
    dos = (IMAGE_DOS_HEADER *)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE || dos->e_lfanew <= 0) return NULL;
    nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE ||
        !nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress) return NULL;
    exp = (IMAGE_EXPORT_DIRECTORY *)(base +
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
    names = (DWORD *)(base + exp->AddressOfNames);
    functions = (DWORD *)(base + exp->AddressOfFunctions);
    ordinals = (WORD *)(base + exp->AddressOfNameOrdinals);
    for (i = 0; i < exp->NumberOfNames; ++i) {
        const char *candidate = (const char *)(base + names[i]);
        if (!strcmp(candidate, decoded) && ordinals[i] < exp->NumberOfFunctions) {
            DWORD rva = functions[ordinals[i]];
            DWORD export_rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            DWORD export_size = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            if (rva >= export_rva && rva - export_rva < export_size) return NULL;
            return (FARPROC)(base + rva);
        }
    }
    return NULL;
}

typedef LPVOID (WINAPI *alloc_fn)(LPVOID, SIZE_T, DWORD, DWORD);
typedef BOOL (WINAPI *protect_fn)(LPVOID, SIZE_T, DWORD, PDWORD);
typedef BOOL (WINAPI *free_fn)(LPVOID, SIZE_T, DWORD);
typedef HANDLE (WINAPI *first_fn)(LPCWSTR, LPWIN32_FIND_DATAW);
typedef BOOL (WINAPI *next_fn)(HANDLE, LPWIN32_FIND_DATAW);
typedef BOOL (WINAPI *close_fn)(HANDLE);
typedef DWORD (WINAPI *error_fn)(void);

int main(void) {
    BYTE *module = find_module(L"kernelbase.dll");
    alloc_fn alloc = (alloc_fn)resolve_export(module, n_alloc, COUNT(n_alloc));
    protect_fn protect = (protect_fn)resolve_export(module, n_protect, COUNT(n_protect));
    free_fn release = (free_fn)resolve_export(module, n_free, COUNT(n_free));
    first_fn first = (first_fn)resolve_export(module, n_first, COUNT(n_first));
    next_fn next = (next_fn)resolve_export(module, n_next, COUNT(n_next));
    close_fn close = (close_fn)resolve_export(module, n_close, COUNT(n_close));
    error_fn last_error = (error_fn)resolve_export(module, n_error, COUNT(n_error));
    BYTE *page;
    DWORD old_protection, ignored;
    WIN32_FIND_DATAW data;
    HANDLE h;
    unsigned count = 0;
    if (!alloc || !protect || !release || !first || !next || !close || !last_error) {
        puts("API resolution failed");
        return 1;
    }
    page = (BYTE *)alloc(NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) return 2;
    page[0] = 0xc3;
    if (!protect(page, 4096, PAGE_EXECUTE_READ, &old_protection)) {
        release(page, 0, MEM_RELEASE);
        return 3;
    }
    if (!protect(page, 4096, PAGE_READWRITE, &ignored)) {
        release(page, 0, MEM_RELEASE);
        return 4;
    }
    page[0] ^= KEY;
    if (!release(page, 0, MEM_RELEASE)) return 5;
    puts("Inert page: allocated, written, made executable, encoded, released.");
    h = first(L"C:\\System Volume Information\\*", &data);
    if (h == INVALID_HANDLE_VALUE) {
        printf("Protected-directory listing failed; Win32 error %lu.\n", last_error());
        return 0;
    }
    do { ++count; } while (count < 32 && next(h, &data));
    close(h);
    printf("Protected-directory listing succeeded; counted up to %u entries.\n", count);
    return 0;
}
