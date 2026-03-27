#pragma once

#include <windows.h>
#include <filesystem>
#include <unordered_map>
#include <vector>

#ifndef USER_DEFAULT_SCREEN_DPI
#define USER_DEFAULT_SCREEN_DPI 96
#endif

inline int ScaleDPI(int value, UINT dpi)
{
	return MulDiv(value, dpi, USER_DEFAULT_SCREEN_DPI);
}

namespace fs = std::filesystem;

/* We cannot use the default WM_CLOSE since there
 * are various things outside of our control that
 * can send this event (such as right click and close).
 * However, we also cannot send a WM_DESTROY notification
 * either (it causes jank and unexpected behavior since
 * it's expected that DestroyWindow be called). So we
 * create a custom message type here and send it to be
 * executed in the main thread instead to properly call
 * DestroyWindow for us. */
#define CUSTOM_CLOSE_MSG (WM_USER + 1)

/* Same as above but this differentiates behavior.
  * It allows us to assume there's an error and to
  * handle that error before closing. */
#define CUSTOM_ERROR_MSG (WM_USER + 2)

#define CLS_PROGRESS_LABEL (1)
#define CLS_BLOCKERS_LIST (2)

void LogLastError(LPCWSTR lpFunctionName);

BOOL StartApplication(const char *lpCommandLine, const char *lpWorkingDir);
BOOL StartApplication(LPWSTR lpCommandLine, LPCWSTR lpWorkingDirectory);

LPWSTR ConvertToUtf16LP(const char *from, int *from_size);
std::wstring ConvertToUtf16WS(std::string from);
std::string ConvertToUtf8(std::wstring from);

fs::path prepare_file_path(const fs::path &base, const std::string &target);
bool is_system_folder(const fs::path &path);
std::string unfixup_uri(const std::string &source);
std::string fixup_uri(const std::string &source);
std::string encimpl(std::string::value_type v);
std::string urlencode(const std::string &url);

std::string calculate_files_checksum(const fs::path &path);
std::string calculate_files_checksum_safe(const fs::path &path);

void setup_locale();

/* Because Windows doesn't provide us a Unicode
 * command line by default and the command line
 * it does provide us is in UTF-16LE. */
class MultiByteCommandLine {
public:
	MultiByteCommandLine();
	MultiByteCommandLine(bool skip_load);
	virtual ~MultiByteCommandLine();

	MultiByteCommandLine(const MultiByteCommandLine &) = delete;
	MultiByteCommandLine(MultiByteCommandLine &&) = delete;
	MultiByteCommandLine &operator=(const MultiByteCommandLine &) = delete;
	MultiByteCommandLine &operator=(MultiByteCommandLine &&) = delete;

	LPSTR *argv() { return m_argv; };
	int argc() { return m_argc; };

protected:
	int m_argc{0};
	LPSTR *m_argv{nullptr};
};

struct manifest_entry_t {
	std::string hash_sum;
	bool compared_to_local;

	bool remove_at_update;
	bool skip_update;

	manifest_entry_t(std::string &file_hash_sum) : hash_sum(file_hash_sum), compared_to_local(false), remove_at_update(false), skip_update(false) {}
};

using manifest_map_t = std::unordered_map<std::string, manifest_entry_t>;
using local_manifest_t = std::vector<std::pair<fs::path, std::string>>;