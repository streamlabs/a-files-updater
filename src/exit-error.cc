#include "exit-error.hpp"

namespace {

std::string last_error_category;
std::string last_error_reason;

} // namespace

const std::string &get_exit_error_category() noexcept
{
	return last_error_category;
}

const std::string &get_exit_error_reason() noexcept
{
	return last_error_reason;
}

void save_exit_error(const std::string &category, const std::string &reason) noexcept
{
	try {
		last_error_category = category;
		last_error_reason = reason;
	} catch (...) {
		// best effort; nothing to do if we can't even copy a string
	}
}

scoped_exit_error::scoped_exit_error(const std::string &category, const std::string &reason) noexcept
{
	try {
		previous_category = last_error_category;
		previous_reason = last_error_reason;
	} catch (...) {
		// best effort, same as save_exit_error(); a failed snapshot only costs us the buffered report
	}

	save_exit_error(category, reason);
}

scoped_exit_error::~scoped_exit_error() noexcept
{
	save_exit_error(previous_category, previous_reason);
}
