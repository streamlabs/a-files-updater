#pragma once

#include <string>
#include <vector>

#include "uri-parser.hpp"

#include <filesystem>

namespace fs = std::filesystem;
struct UpdaterStorageDiagnostics;

/* We want this to be C compatible eventually */
struct update_parameters {
	struct uri_components host;

	fs::path temp_dir;
	fs::path app_dir;
	/* Resolved once at startup: %ProgramData%\obs-studio-hook unless
	 * --hook-dir moved it, which only the tests do. */
	fs::path hook_dir;
	std::string exec;
	std::string exec_no_update;
	std::string exec_cwd;
	std::vector<int> pids;
	std::string version;
	fs::path log_file_path;
	FILE *log_file = nullptr;
	void *temp_dir_lock = nullptr;
	bool cleanup_temp_dir_lock = false;
	std::string startup_error_category;
	std::string startup_error_reason;
	std::string startup_diagnostic;
	std::string storage_ancestor_warning;
	std::string storage_root_replaced;
	std::string storage_prune_warning;
	bool owns_temp_dir = false;
	bool retain_temp_dir = false;
	bool cleanup_failure_reported = false;
	bool enforce_temp_ancestors = true;
	bool interactive = true;
	/* Whether a process holding the graphics hook directory open is worth
	 * stopping the user over. Off still repairs and still reports; it only
	 * takes away the ask, so the app can withdraw it without a new updater. */
	bool hook_prompt = true;
	bool restart_on_fail = false;
	bool enable_removing_old_files = false;
	std::string details;

	bool cleanup_temp_dir(UpdaterStorageDiagnostics *diagnostics = nullptr);
	~update_parameters();
};
