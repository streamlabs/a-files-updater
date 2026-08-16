#include "update-parameters.hpp"

#include "logger/log.h"
#include "updater-storage.hpp"

bool update_parameters::cleanup_temp_dir(UpdaterStorageDiagnostics *diagnostics)
{
	if (log_file) {
		log_set_fp(nullptr);
		fclose(log_file);
		log_file = nullptr;
	}
	if (temp_dir_lock) {
		release_updater_run_lock(temp_dir_lock);
		temp_dir_lock = nullptr;
	}

	if (!owns_temp_dir || retain_temp_dir || temp_dir.empty())
		return true;

	if (!cleanup_updater_temp_dir(temp_dir, enforce_temp_ancestors, diagnostics))
		return false;

	owns_temp_dir = false;
	return true;
}

update_parameters::~update_parameters()
{
	cleanup_temp_dir();
}
