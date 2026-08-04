#pragma once

#include <filesystem>

namespace fs = std::filesystem;

/* Locks down %ProgramData%\obs-studio-hook, the directory the graphics hook is
 * injected into other processes from. Releases up to 1.21 left it writable by
 * BUILTIN\Users, so it may be owned by a standard user and full of files that
 * user planted.
 *
 * The permission work never depends on app_dir. Republishing the hook out of
 * the copy under it is a best-effort tail: a payload that is missing, or that
 * sits somewhere a standard user could rewrite, is skipped rather than treated
 * as a failure. It is worth attempting because only an elevated writer can put
 * files into the hardened directory and the app usually is not one, so a
 * quarantined machine would otherwise have no hook until its next reinstall.
 *
 * Requires elevation, and fails closed: any directory this cannot leave holding
 * a full set of trusted hooks ends with the vulkan implicit layer unregistered
 * rather than pointing at it. Reports only through the log. */
void repair_hook_directory(const fs::path &app_dir);
