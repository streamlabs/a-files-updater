#pragma once

#include <windows.h>

#include <RestartManager.h>
#include <list>
#include <map>
#include <mutex>

#include <filesystem>

namespace fs = std::filesystem;

struct blockers_map_t {
	std::map<DWORD, RM_PROCESS_INFO> list;
	std::mutex mtx;
};

// === Update exceptions

class update_exception_blocked : public std::exception {
};

class update_exception_failed : public std::exception {
};

// === Update blockers check

// return true if successfuly get info on blocker process
bool get_blockers_list(fs::path &check_path, blockers_map_t &blockers);

// check if file ok to read or write
// return : false if file blocked
// blockers list updated with blocker process info
bool check_file_updatable(fs::path &check_path, bool check_read, blockers_map_t &blockers);

bool get_blockers_names(blockers_map_t &blockers);

// check if the relative file path refers to a virtual camera DLL
bool is_virtualcam_file(const fs::path &relative_path);