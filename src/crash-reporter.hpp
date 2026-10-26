#pragma once

#include <string>

#include "exit-error.hpp"

void setup_crash_reporting();
void handle_exit() noexcept;
void report_handled_error(const std::string &category, const std::string &reason) noexcept;
bool is_launched_by_explorer();