#pragma once

#include <windows.h>

#include <RestartManager.h>
#include <list>
#include <map>
#include <mutex>
#include <string>
#include <vector>

#include <filesystem>

namespace fs = std::filesystem;

struct blockers_map_t {
	std::map<DWORD, RM_PROCESS_INFO> list;
	std::mutex mtx;
};

struct blocker_info {
	DWORD pid;
	std::wstring app_name;
	std::wstring exe_path;
	bool has_window;
};

// === Update exceptions

class update_exception_blocked : public std::exception {};

class update_exception_failed : public std::exception {};

// === Update blockers check

// return true if successfuly get info on blocker process
bool get_blockers_list(fs::path &check_path, blockers_map_t &blockers);

// check if file ok to read or write
// return : false if file blocked
// blockers list updated with blocker process info
bool check_file_updatable(fs::path &check_path, bool check_read, blockers_map_t &blockers);

bool get_blockers_names(blockers_map_t &blockers);

std::vector<blocker_info> get_blocker_details(blockers_map_t &blockers);

/* Who is holding a hook open in the shared graphics hook directory. Best
 * effort, and separate from check_file_updatable: what fails there is a
 * directory rename rather than an open, and its ERROR_ACCESS_DENIED means a
 * holder rather than the unrecoverable failure that switch reads it as. */
std::vector<blocker_info> get_hook_dir_blockers();

// write the blocker list to the log, which is attached to the crash report
void log_blockers(const char *lead, const std::vector<blocker_info> &blockers);

// check if the relative file path refers to a virtual camera DLL
bool is_virtualcam_file(const fs::path &relative_path);