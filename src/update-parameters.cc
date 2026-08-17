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
	if (cleanup_temp_dir_lock && !owns_temp_dir) {
		if (!remove_updater_run_lock(temp_dir, diagnostics))
			return false;
		cleanup_temp_dir_lock = false;
	}

	if (!owns_temp_dir || retain_temp_dir || temp_dir.empty())
		return true;

	if (!cleanup_updater_temp_dir(temp_dir, enforce_temp_ancestors, diagnostics))
		return false;

	owns_temp_dir = false;
	cleanup_temp_dir_lock = false;
	return true;
}

update_parameters::~update_parameters()
{
	if (cleanup_failure_reported)
		return;

	try {
		cleanup_temp_dir();
	} catch (...) {
		wlog_warn(L"Unexpected exception while cleaning updater storage during shutdown");
	}
}
