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

typedef enum RsxStatus {
    RSX_STATUS_OK = 0,
    RSX_STATUS_NULL_ARGUMENT = 1,
    RSX_STATUS_INVALID_UTF8 = 2,
    RSX_STATUS_INVALID_JSON = 3,
    RSX_STATUS_INVALID_OPTIONS = 4,
    RSX_STATUS_EXECUTION_ERROR = 5,
    RSX_STATUS_PANIC = 255
} RsxStatus;

/* Every returned string is UTF-8 allocated by RESX. Release it with RsxFreeString. */
RSX_API void RsxFreeString(char *value);
RSX_API int RsxVersion(char **out_utf8);
RSX_API int RsxHelp(char **out_utf8);

/*
 * Runs the CLI router directly. argv may include "resx" as argv[0], or may start
 * with the command name. Returns captured command output in out_utf8.
 */
RSX_API int RsxRunArgs(size_t argc, const char *const *argv, char **out_utf8);

/*
 * Request JSON:
 *   {"command":"diff","args":["old.dll","new.dll"],"options":{"no_pdb":true}}
 * or:
 *   {"argv":["diff","old.dll","new.dll","--json"],"options":{"quiet":true}}
 *
 * Returns a JSON envelope. If the command emitted JSON, the parsed document is in
 * "payload"; otherwise captured text is in "text".
 */
RSX_API int RsxRunCommandJson(const char *request_json, char **out_json);

RSX_API int RsxDump(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int RsxDumpAt(const char *image_path, const char *rva, const char *options_json, char **out_json);
RSX_API int RsxDumpOrdinal(const char *image_path, uint32_t ordinal, const char *options_json, char **out_json);
RSX_API int RsxCfg(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int RsxCfgAt(const char *image_path, const char *rva, const char *options_json, char **out_json);
RSX_API int RsxCfgOrdinal(const char *image_path, uint32_t ordinal, const char *options_json, char **out_json);
RSX_API int RsxReconstructCfg(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxIntelli(const char *image_path, const char *function_name_or_null, const char *options_json, char **out_json);
RSX_API int RsxPeInfo(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxSections(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxPeCheck(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxShowEat(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxShowIat(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxShowSyms(const char *image_path, const char *options_json, char **out_json);
RSX_API int RsxTypes(const char *image_path, const char *query_or_null, const char *options_json, char **out_json);
RSX_API int RsxFollowCallers(const char *image_path, const char *function_name, const char *options_json, char **out_json);
RSX_API int RsxLocate(const char *function_name, const char *options_json, char **out_json);
RSX_API int RsxLocateSymbols(const char *function_name, const char *options_json, char **out_json);
RSX_API int RsxExplain(const char *term, const char *options_json, char **out_json);
RSX_API int RsxDiff(const char *left_image_path, const char *right_image_path, const char *options_json, char **out_json);
RSX_API int RsxCfgDiff(const char *left_image_path, const char *right_image_path, const char *target, const char *options_json, char **out_json);
RSX_API int RsxIndex(const char *root_path, const char *options_json, char **out_json);
RSX_API int RsxHunt(const char *sample_path, const char *options_json, char **out_json);
RSX_API int RsxScan(const char *root_path, const char *options_json, char **out_json);
RSX_API int RsxYara(const char *image_path, const char *rule_path, const char *options_json, char **out_json);
RSX_API int RsxPriority(const char *options_json, char **out_json);
RSX_API int RsxUpdate(const char *options_json, char **out_json);

#ifdef __cplusplus
}
#endif

#endif
