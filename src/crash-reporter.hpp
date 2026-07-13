#pragma once

#include <string>

void setup_crash_reporting();
void handle_exit() noexcept;
void save_exit_error(const std::string &category, const std::string &reason) noexcept;
void report_handled_error(const std::string &category, const std::string &reason) noexcept;
bool is_launched_by_explorer();