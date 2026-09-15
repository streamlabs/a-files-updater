#include <cstdio>
#include <string>

#include "report-level.hpp"

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

void crash_and_broken_install_are_fatal()
{
	CHECK(level_for_report("UpdateFailure", "Failed to revert on fail") == report_level::fatal);
}

void update_failures_are_error()
{
	CHECK(level_for_report("UpdateFailure", "Failed to update") == report_level::error);
	CHECK(level_for_report("UpdateFailure", "Network error") == report_level::error);
	CHECK(level_for_report("UpdateFailure", "Invalid update manifest") == report_level::error);
	CHECK(level_for_report("UpdateFailure", "File access error") == report_level::error);
	CHECK(level_for_report("UpdateFailure", "File operation error") == report_level::error);
}

void cancellation_is_info()
{
	CHECK(level_for_report("UserAction", "Canceled") == report_level::info);
}

void startup_skips_are_info()
{
	CHECK(level_for_report("StartupSkipped", "Launched manually") == report_level::info);
	CHECK(level_for_report("StartupSkipped", "App in system folder") == report_level::info);
}

void startup_failures_are_error()
{
	CHECK(level_for_report("StartupFailure", "Failed parsing arguments") == report_level::error);
	CHECK(level_for_report("StartupFailure", "Failed to render UI") == report_level::error);
	CHECK(level_for_report("UpdaterStorageFailure", "") == report_level::error);
	CHECK(level_for_report("UpdaterStorageQuarantineBlocked", "") == report_level::error);
	CHECK(level_for_report("PostUpdateFailure", "Failed to autorestart") == report_level::error);
}

void successful_update_side_effects_are_warning()
{
	/* The production report: the update succeeded and only the temp directory was left behind. */
	CHECK(level_for_report("UpdaterStorageCleanupFailure", "") == report_level::warning);
	CHECK(level_for_report("UpdaterStoragePruneFailure", "") == report_level::warning);
	CHECK(level_for_report("UpdaterStorageAncestorUntrusted", "") == report_level::warning);
	CHECK(level_for_report("UpdaterStorageRootReplaced", "") == report_level::warning);
	CHECK(level_for_report("PackageInstallFailure", "vcredist") == report_level::warning);
}

void hook_outcomes_split_by_exposure()
{
	CHECK(level_for_report("HookRepairFailure", "") == report_level::error);
	CHECK(level_for_report("HookContainmentFailure", "") == report_level::error);
	CHECK(level_for_report("HookQuarantineBlocked", "") == report_level::warning);
	CHECK(level_for_report("HookQuarantineAccessDenied", "") == report_level::warning);
	CHECK(level_for_report("HookDirAncestorUntrusted", "") == report_level::warning);
}

void unknown_category_defaults_to_error()
{
	CHECK(level_for_report("SomethingNew", "") == report_level::error);
	/* An empty category is suppressed before it reaches a report, not levelled down here. */
	CHECK(level_for_report("", "") == report_level::error);
}

void level_names_match_sentry_vocabulary()
{
	CHECK(std::string(report_level_name(report_level::info)) == "info");
	CHECK(std::string(report_level_name(report_level::warning)) == "warning");
	CHECK(std::string(report_level_name(report_level::error)) == "error");
	CHECK(std::string(report_level_name(report_level::fatal)) == "fatal");
}

} // namespace

int main()
{
	crash_and_broken_install_are_fatal();
	update_failures_are_error();
	cancellation_is_info();
	startup_skips_are_info();
	startup_failures_are_error();
	successful_update_side_effects_are_warning();
	hook_outcomes_split_by_exposure();
	unknown_category_defaults_to_error();
	level_names_match_sentry_vocabulary();

	printf("report level tests: %d failed\n", failures);
	return failures == 0 ? 0 : 1;
}
