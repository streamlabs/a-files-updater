#pragma once

#include <string>
#include <vector>

#include "uri-parser.hpp"

#include <filesystem>

namespace fs = std::filesystem;

/* We want this to be C compatible eventually */
struct update_parameters {
	struct uri_components host;

	fs::path temp_dir;
	fs::path app_dir;
	std::string exec;
	std::string exec_no_update;
	std::string exec_cwd;
	std::vector<int> pids;
	std::string version;
	std::string log_file_path;
	FILE *log_file = nullptr;
	bool interactive = true;
	bool restart_on_fail = false;
	bool enable_removing_old_files = false;
	std::string details;

	~update_parameters()
	{
		if (log_file)
			fclose(log_file);
	}
};