#include <cstdio>
#include <string>

#include "exit-error.hpp"

namespace {

int failures = 0;

void check(bool ok, const char *expression, int line)
{
	if (ok)
		return;

	failures++;
	printf("FAIL line %d: %s\n", line, expression);
}

#define CHECK(cond) check((cond), #cond, __LINE__)

void buffer_starts_empty()
{
	CHECK(get_exit_error_category().empty());
	CHECK(get_exit_error_reason().empty());
}

void guard_reports_hook_category_then_restores_update_failure()
{
	// The scenario that broke before this class existed: an update failure buffered for handle_exit()
	// must survive the unconditional hook repair's own handled report.
	save_exit_error("UpdateFailure", "Failed to update");

	{
		scoped_exit_error handled_error("HookRepairFailure", "");
		CHECK(get_exit_error_category() == "HookRepairFailure");
		CHECK(get_exit_error_reason() == "");
	}

	CHECK(get_exit_error_category() == "UpdateFailure");
	CHECK(get_exit_error_reason() == "Failed to update");
}

void guard_with_no_prior_error_restores_empty()
{
	save_exit_error("", "");

	{
		scoped_exit_error handled_error("HookRepairFailure", "");
		CHECK(get_exit_error_category() == "HookRepairFailure");
	}

	CHECK(get_exit_error_category().empty());
	CHECK(get_exit_error_reason().empty());
}

void nested_guards_restore_in_order()
{
	save_exit_error("UpdateFailure", "Failed to update");

	{
		scoped_exit_error outer("HookRepairFailure", "");
		{
			scoped_exit_error inner("HookContainmentFailure", "");
			CHECK(get_exit_error_category() == "HookContainmentFailure");
		}
		CHECK(get_exit_error_category() == "HookRepairFailure");
	}

	CHECK(get_exit_error_category() == "UpdateFailure");
	CHECK(get_exit_error_reason() == "Failed to update");

	save_exit_error("", "");
}

} // namespace

int main()
{
	buffer_starts_empty();
	guard_reports_hook_category_then_restores_update_failure();
	guard_with_no_prior_error_restores_empty();
	nested_guards_restore_in_order();

	printf("exit error tests: %d failed\n", failures);
	return failures == 0 ? 0 : 1;
}
