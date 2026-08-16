#include "update-parameters.hpp"

#include "logger/log.h"
#include "updater-storage.hpp"

update_parameters::~update_parameters()
{
	if (log_file) {
		log_set_fp(nullptr);
		fclose(log_file);
		log_file = nullptr;
	}

	if (owns_temp_dir && !retain_temp_dir && !temp_dir.empty())
		cleanup_updater_temp_dir(temp_dir);
}
