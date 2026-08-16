#pragma once

#include <filesystem>

namespace fs = std::filesystem;

/* Persistent administrator-owned parent for updater runs. */
fs::path programdata_updater_root();

/* Creates a fresh administrator-owned run directory below the ProgramData
 * root. Returns an empty path when the root cannot be established safely. */
fs::path create_default_updater_temp_dir();

/* Creates an exact run directory with the updater ACL, or verifies an existing
 * one before reuse when allow_existing is true. Never repairs or adopts an
 * untrusted directory. */
bool prepare_updater_temp_dir(const fs::path &dir, bool allow_existing);
