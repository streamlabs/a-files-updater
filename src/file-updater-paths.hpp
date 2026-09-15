#pragma once

#include <filesystem>
#include <system_error>

bool remove_revert_destination(const std::filesystem::path &path, std::error_code &ec);
