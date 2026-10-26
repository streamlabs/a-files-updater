#pragma once

#include <string>

const std::string &get_exit_error_category() noexcept;
const std::string &get_exit_error_reason() noexcept;

void save_exit_error(const std::string &category, const std::string &reason) noexcept;

// Buffers a handled error for the lifetime of the scope, then restores whatever handle_exit() still has to report.
class scoped_exit_error {
public:
	scoped_exit_error(const std::string &category, const std::string &reason) noexcept;
	~scoped_exit_error() noexcept;

	scoped_exit_error(const scoped_exit_error &) = delete;
	scoped_exit_error &operator=(const scoped_exit_error &) = delete;

private:
	std::string previous_category;
	std::string previous_reason;
};
