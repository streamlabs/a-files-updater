#pragma once

#include <filesystem>
#include <string>

namespace fs = std::filesystem;

struct UpdaterStorageDiagnostics {
	std::wstring failure;
	std::string failure_category;
	std::wstring ancestor_warning;
	std::wstring root_replaced_reason;
	std::wstring cleanup_warning;
	bool created = false;
	bool root_replaced = false;
};

/* Persistent administrator-owned parent for updater runs. */
fs::path programdata_updater_root();

/* Creates a fresh administrator-owned run directory below the ProgramData
 * root. Returns an empty path and fills diagnostics on failure. */
fs::path create_default_updater_temp_dir(UpdaterStorageDiagnostics *diagnostics = nullptr);

/* Creates an exact run directory with the updater ACL, or verifies an existing
 * one before reuse when allow_existing is true. Explicit paths enforce both
 * object and ancestor trust. Never repairs or adopts an untrusted directory. */
bool prepare_updater_temp_dir(const fs::path &dir, bool allow_existing, UpdaterStorageDiagnostics *diagnostics = nullptr);

/* Root-specific policy: replace an untrusted fixed-name container, and report
 * but temporarily tolerate an untrusted ancestor while field telemetry is
 * collected. Exported so native tests can exercise the same policy safely. */
bool prepare_updater_root(const fs::path &root, UpdaterStorageDiagnostics *diagnostics = nullptr);

/* Holds a run-specific file without sharing so another updater can distinguish
 * an active run from an abandoned one. */
bool acquire_updater_run_lock(const fs::path &dir, void **lock_handle, UpdaterStorageDiagnostics *diagnostics = nullptr);
void release_updater_run_lock(void *lock_handle);
bool remove_updater_run_lock(const fs::path &dir, UpdaterStorageDiagnostics *diagnostics = nullptr);

/* Removes abandoned run-* children. Runs without rollback originals are
 * eligible after one day; recovery backups become eligible after seven days.
 * Active runs are always skipped. Also retries non-recursive removal of exact
 * root-quarantine siblings; non-empty quarantine trees remain untouched. */
void prune_updater_runs(const fs::path &root, bool enforce_ancestors = true, UpdaterStorageDiagnostics *diagnostics = nullptr);

/* Removes a run directory only after verifying the object is still trusted. */
bool cleanup_updater_temp_dir(const fs::path &dir, bool enforce_ancestors = true, UpdaterStorageDiagnostics *diagnostics = nullptr);
