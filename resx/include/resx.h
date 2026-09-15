#ifndef RESX_H
#define RESX_H

#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#if defined(RSX_BUILD)
#define RSX_API __declspec(dllexport)
#else
#define RSX_API __declspec(dllimport)
#endif
#else
#define RSX_API
#endif

#ifdef __cplusplus
extern "C" {
#endif

typedef enum ResxStatus {
    RSX_STATUS_OK = 0,
    RSX_STATUS_NULL_ARGUMENT = 1,
    RSX_STATUS_INVALID_UTF8 = 2,
    RSX_STATUS_INVALID_JSON = 3,
    RSX_STATUS_INVALID_OPTIONS = 4,
    RSX_STATUS_EXECUTION_ERROR = 5,
    RSX_STATUS_PANIC = 255
} ResxStatus;

/* Every returned string is UTF-8 allocated by RESX. Release it with ResxFreeString. */
RSX_API void ResxFreeString(char *value);
RSX_API int ResxVersion(char **out_utf8);
RSX_API int ResxHelp(char **out_utf8);

/*
 * Runs the CLI router directly. argv may include "resx" as argv[0], or may start
 * with the command name. Returns captured command output in out_utf8.
 */
RSX_API int ResxRunArgs(size_t argc, const char *const *argv, char **out_utf8);

/*
 * Request JSON:
 *   {"command":"diff","args":["old.dll","new.dll"],"options":{"no_pdb":true}}
 * or:
 *   {"argv":["diff","old.dll","new.dll","--json"],"options":{"quiet":true}}
 *
 * Returns a JSON envelope. If the command emitted JSON, the parsed document is in
 * "payload"; otherwise captured text is in "text".
 */
RSX_API int ResxRunCommandJson(const char *request_json, char **out_json);

RSX_API int ResxDump(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int ResxDumpAt(const char *image_path, const char *rva, const char *options_json, char **out_json);
RSX_API int ResxDumpOrdinal(const char *image_path, uint32_t ordinal, const char *options_json, char **out_json);
RSX_API int ResxCfg(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int ResxCfgAt(const char *image_path, const char *rva, const char *options_json, char **out_json);
RSX_API int ResxCfgOrdinal(const char *image_path, uint32_t ordinal, const char *options_json, char **out_json);
RSX_API int ResxReconstructCfg(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxIntelli(const char *image_path, const char *function_name_or_null, const char *options_json, char **out_json);
RSX_API int ResxPeInfo(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxSections(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxPeCheck(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxShowEat(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxShowIat(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxShowSyms(const char *image_path, const char *options_json, char **out_json);
RSX_API int ResxTypes(const char *image_path, const char *query_or_null, const char *options_json, char **out_json);
RSX_API int ResxFollowCallers(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int ResxLocate(const char *function_name, const char *options_json, char **out_json);
RSX_API int ResxLocateSymbols(const char *function_name, const char *options_json, char **out_json);
RSX_API int ResxDiff(const char *left_image_path, const char *right_image_path, const char *options_json, char **out_json);
RSX_API int ResxCfgDiff(const char *left_image_path, const char *right_image_path, const char *target, const char *options_json, char **out_json);
RSX_API int ResxIndex(const char *root_path, const char *options_json, char **out_json);
RSX_API int ResxHunt(const char *sample_path, const char *options_json, char **out_json);
RSX_API int ResxScan(const char *root_path, const char *options_json, char **out_json);
RSX_API int ResxYara(const char *image_path, const char *rule_path, const char *options_json, char **out_json);
RSX_API int ResxPriority(const char *options_json, char **out_json);
RSX_API int ResxUpdate(const char *options_json, char **out_json);

#ifdef __cplusplus
}
#endif

#endif
