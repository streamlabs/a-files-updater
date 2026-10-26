#pragma once

#include <string>

enum class report_level { info, warning, error, fatal };

const char *report_level_name(report_level level) noexcept;

report_level level_for_report(const std::string &category, const std::string &reason) noexcept;
