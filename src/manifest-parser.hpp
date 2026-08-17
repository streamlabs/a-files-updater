#pragma once

#include <string>
#include <string_view>

#include "utils.hpp"

/* Accepts only relative Windows file paths that cannot escape the updater's
 * staging or application roots. The returned key uses preferred separators. */
bool normalize_manifest_path(std::string_view input, std::string &normalized, std::string &error);

/* Parses a complete checksum manifest without modifying output on failure. */
bool parse_update_manifest(const std::string &content, manifest_map_t &output, std::string &error);
