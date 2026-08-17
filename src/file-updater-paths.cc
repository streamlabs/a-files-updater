#include "file-updater-paths.hpp"

namespace fs = std::filesystem;

bool remove_revert_destination(const fs::path &path, std::error_code &ec)
{
	ec.clear();
	const fs::file_status status = fs::symlink_status(path, ec);
	if (ec == std::errc::no_such_file_or_directory) {
		ec.clear();
		return true;
	}
	if (ec) {
		return false;
	}

	/* Recurse only into a real directory; remove reparse points as leaf entries. */
	if (fs::is_directory(status)) {
		fs::remove_all(path, ec);
	} else {
		fs::remove(path, ec);
	}

	return !ec;
}
