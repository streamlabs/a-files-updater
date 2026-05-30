#pragma once

void setup_crash_reporting();
void handle_exit() noexcept;
void save_exit_error(const std::string &category, const std::string &reason) noexcept;
bool is_launched_by_explorer();