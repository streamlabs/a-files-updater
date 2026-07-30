#pragma once

#include <filesystem>

namespace fs = std::filesystem;

/* Re-provisions %ProgramData%\obs-studio-hook, the directory the graphics hook
 * is injected into other processes from. Releases up to 1.21 left it writable
 * by BUILTIN\Users, so it may be owned by a standard user and hold files that
 * user planted. Requires elevation; failures are logged and ignored. */
void repair_hook_directory(const fs::path &app_dir);
