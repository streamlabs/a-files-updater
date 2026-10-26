#include "report-level.hpp"

const char *report_level_name(report_level level) noexcept
{
	switch (level) {
	case report_level::info:
		return "info";
	case report_level::warning:
		return "warning";
	case report_level::error:
		return "error";
	case report_level::fatal:
		return "fatal";
	}

	return "error";
}

report_level level_for_report(const std::string &category, const std::string &reason) noexcept
{
	/* Severity follows the outcome, not the call site: fatal = the process died or the install was
	 * left half-written, error = the update did not complete or an exposure is still open, warning =
	 * the update was not blocked but something needs attention, info = the user or policy declined. */
	if (category == "UpdateFailure")
		return reason == "Failed to revert on fail" ? report_level::fatal : report_level::error;

	if (category == "UserAction" || category == "StartupSkipped")
		return report_level::info;

	if (category == "PackageInstallFailure" || category == "UpdaterStorageCleanupFailure" || category == "UpdaterStoragePruneFailure" ||
	    category == "UpdaterStorageAncestorUntrusted" || category == "UpdaterStorageRootReplaced" || category == "HookDirAncestorUntrusted" ||
	    category == "HookQuarantineBlocked" || category == "HookQuarantineAccessDenied")
		return report_level::warning;

	/* UpdaterStorageFailure, UpdaterStorageQuarantineBlocked, StartupFailure, PostUpdateFailure,
	 * HookContainmentFailure, HookRepairFailure, and anything added after this table. */
	return report_level::error;
}
