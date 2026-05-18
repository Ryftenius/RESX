#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef int(__cdecl *RsxVersionFn)(char **out_utf8);
typedef int(__cdecl *RsxLocateFn)(const char *function_name, const char *options_json, char **out_json);
typedef int(__cdecl *RsxRunArgsFn)(size_t argc, const char *const *argv, char **out_utf8);
typedef void(__cdecl *RsxFreeStringFn)(char *value);

typedef struct ResxApi {
    RsxVersionFn version;
    RsxLocateFn locate;
    RsxRunArgsFn run_args;
    RsxFreeStringFn free_string;
} ResxApi;

static void usage(const char *exe) {
    fprintf(stderr,
            "usage: %s <resx.dll> [image] [function]\n"
            "\n"
            "default image   : %%WINDIR%%\\System32\\ntdll.dll\n"
            "default function: NtOpenProcess\n",
            exe);
}

static char *dup_string(const char *value) {
    size_t len = strlen(value) + 1;
    char *copy = (char *)malloc(len);
    if (copy != NULL) {
        memcpy(copy, value, len);
    }
    return copy;
}

static char *default_ntdll_path(void) {
    char win_dir[MAX_PATH] = {0};
    DWORD len = GetEnvironmentVariableA("WINDIR", win_dir, (DWORD)sizeof(win_dir));
    if (len == 0 || len >= sizeof(win_dir)) {
        return dup_string("C:\\Windows\\System32\\ntdll.dll");
    }

    const char *suffix = "\\System32\\ntdll.dll";
    size_t needed = strlen(win_dir) + strlen(suffix) + 1;
    char *path = (char *)malloc(needed);
    if (path == NULL) {
        return NULL;
    }
    snprintf(path, needed, "%s%s", win_dir, suffix);
    return path;
}

static wchar_t *utf8_to_wide(const char *value) {
    int needed = MultiByteToWideChar(CP_UTF8, 0, value, -1, NULL, 0);
    if (needed <= 0) {
        return NULL;
    }
    wchar_t *wide = (wchar_t *)calloc((size_t)needed, sizeof(wchar_t));
    if (wide == NULL) {
        return NULL;
    }
    if (MultiByteToWideChar(CP_UTF8, 0, value, -1, wide, needed) <= 0) {
        free(wide);
        return NULL;
    }
    return wide;
}

static FARPROC required_proc(HMODULE module, const char *name) {
    FARPROC proc = GetProcAddress(module, name);
    if (proc == NULL) {
        fprintf(stderr, "missing export: %s\n", name);
    }
    return proc;
}

static int load_resx(const char *dll_path, HMODULE *module_out, ResxApi *api) {
    wchar_t *wide_path = utf8_to_wide(dll_path);
    if (wide_path == NULL) {
        fprintf(stderr, "failed to convert DLL path to UTF-16: %s\n", dll_path);
        return 1;
    }

    HMODULE module = LoadLibraryW(wide_path);
    free(wide_path);
    if (module == NULL) {
        fprintf(stderr, "LoadLibraryW failed for %s (GetLastError=%lu)\n", dll_path, GetLastError());
        return 1;
    }

    api->version = (RsxVersionFn)required_proc(module, "RsxVersion");
    api->locate = (RsxLocateFn)required_proc(module, "RsxLocate");
    api->run_args = (RsxRunArgsFn)required_proc(module, "RsxRunArgs");
    api->free_string = (RsxFreeStringFn)required_proc(module, "RsxFreeString");
    if (api->version == NULL || api->locate == NULL || api->run_args == NULL || api->free_string == NULL) {
        FreeLibrary(module);
        return 1;
    }

    *module_out = module;
    return 0;
}

static char *json_escape(const char *value) {
    size_t needed = 1;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        switch (*p) {
        case '\\':
        case '"':
            needed += 2;
            break;
        case '\b':
        case '\f':
        case '\n':
        case '\r':
        case '\t':
            needed += 2;
            break;
        default:
            needed += (*p < 0x20) ? 6 : 1;
            break;
        }
    }

    char *escaped = (char *)malloc(needed);
    if (escaped == NULL) {
        return NULL;
    }

    char *out = escaped;
    for (const unsigned char *p = (const unsigned char *)value; *p != '\0'; ++p) {
        switch (*p) {
        case '\\':
            *out++ = '\\';
            *out++ = '\\';
            break;
        case '"':
            *out++ = '\\';
            *out++ = '"';
            break;
        case '\b':
            *out++ = '\\';
            *out++ = 'b';
            break;
        case '\f':
            *out++ = '\\';
            *out++ = 'f';
            break;
        case '\n':
            *out++ = '\\';
            *out++ = 'n';
            break;
        case '\r':
            *out++ = '\\';
            *out++ = 'r';
            break;
        case '\t':
            *out++ = '\\';
            *out++ = 't';
            break;
        default:
            if (*p < 0x20) {
                snprintf(out, 7, "\\u%04X", *p);
                out += 6;
            } else {
                *out++ = (char)*p;
            }
            break;
        }
    }
    *out = '\0';
    return escaped;
}

static char *make_locate_options(const char *image_path) {
    char *image = json_escape(image_path);
    if (image == NULL) {
        return NULL;
    }

    const char *prefix = "{\"include_image\":\"";
    const char *suffix = "\",\"no_system\":true,\"no_cwd\":true,\"no_path\":true,\"no_pdb\":true,\"max_total\":8}";
    size_t needed = strlen(prefix) + strlen(image) + strlen(suffix) + 1;
    char *json = (char *)malloc(needed);
    if (json != NULL) {
        snprintf(json, needed, "%s%s%s", prefix, image, suffix);
    }
    free(image);
    return json;
}

static int call_and_print_version(const ResxApi *api) {
    char *out = NULL;
    int status = api->version(&out);
    printf("[resx] RsxVersion status=%d\n", status);
    if (out != NULL) {
        printf("%s\n", out);
        api->free_string(out);
    }
    return status;
}

static int locate_function(const ResxApi *api, const char *image_path, const char *function_name) {
    char *options = make_locate_options(image_path);
    if (options == NULL) {
        fprintf(stderr, "failed to allocate locate options\n");
        return 1;
    }

    char *out = NULL;
    printf("\n[resx] RsxLocate(%s)\n", function_name);
    int status = api->locate(function_name, options, &out);
    free(options);
    printf("[resx] locate status=%d\n", status);
    if (out != NULL) {
        puts(out);
        api->free_string(out);
    }
    return status;
}

static int dump_function(const ResxApi *api, const char *image_path, const char *function_name) {
    const char *argv[] = {
        "dump",
        image_path,
        function_name,
        "--cfg",
        "text",
        "--funcs",
        "--funcs-depth",
        "1",
        "--xrefs",
        "--strings",
        "--max-insns",
        "90",
        "--no-color",
        "--quiet",
    };

    char *out = NULL;
    printf("\n[resx] RsxRunArgs dump %s!%s\n", image_path, function_name);
    int status = api->run_args(sizeof(argv) / sizeof(argv[0]), argv, &out);
    printf("[resx] dump status=%d\n", status);
    if (out != NULL) {
        puts(out);
        api->free_string(out);
    }
    return status;
}

int main(int argc, char **argv) {
    if (argc >= 2 && (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)) {
        usage(argv[0]);
        return 0;
    }
    if (argc < 2) {
        usage(argv[0]);
        return 2;
    }

    const char *dll_path = argv[1];
    char *default_image = NULL;
    const char *image_path = NULL;
    const char *function_name = (argc >= 4) ? argv[3] : "NtOpenProcess";
    if (argc >= 3) {
        image_path = argv[2];
    } else {
        default_image = default_ntdll_path();
        image_path = default_image;
    }

    if (image_path == NULL) {
        fprintf(stderr, "failed to determine default target image\n");
        return 1;
    }

    printf("[loader] DLL      : %s\n", dll_path);
    printf("[loader] image    : %s\n", image_path);
    printf("[loader] function : %s\n", function_name);

    HMODULE module = NULL;
    ResxApi api = {0};
    if (load_resx(dll_path, &module, &api) != 0) {
        free(default_image);
        return 1;
    }

    int exit_code = 0;
    if (call_and_print_version(&api) != 0) {
        exit_code = 1;
    }
    if (exit_code == 0 && locate_function(&api, image_path, function_name) != 0) {
        exit_code = 1;
    }
    if (exit_code == 0 && dump_function(&api, image_path, function_name) != 0) {
        exit_code = 1;
    }

    FreeLibrary(module);
    free(default_image);
    return exit_code;
}
