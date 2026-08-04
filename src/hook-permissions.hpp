#pragma once

#include <filesystem>

namespace fs = std::filesystem;

/* Locks down %ProgramData%\obs-studio-hook, the directory the graphics hook is
 * injected into other processes from. Releases up to 1.21 left it writable by
 * BUILTIN\Users, so it may be owned by a standard user and full of files that
 * user planted.
 *
 * Permissions only. It never installs a hook - it has no opinion on which
 * version should win, and the app already arbitrates that. What it will do is
 * delete a hook file it cannot vouch for, since the alternative is leaving one
 * behind for the app to load.
 *
 * Requires elevation, and fails closed: any directory it cannot leave holding a
 * full set of trusted hooks ends with the vulkan implicit layer unregistered
 * rather than pointing at it. Reports only through the log. */
void repair_hook_directory();
