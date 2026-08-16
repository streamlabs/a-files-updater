/* Drives the shipped hook-permissions.cc against scratch directories, so the
 * shapes a real machine only produces occasionally - a directory owned by a
 * standard user, a hook held open by a running game, a junction where the
 * directory should be - can be built on purpose and asserted on.
 *
 * Needs elevation for the same reason the repair does: it takes ownership and
 * rewrites DACLs. It never touches %ProgramData%\obs-studio-hook itself; the
 * scratch root defaults to a sibling of it, because the ancestor walk means a
 * tree under %TEMP% or a user-owned directory would report AncestorUntrusted
 * in every case and prove nothing.
 *
 * Each quarantine also queues its directory for deletion at the next reboot.
 * The cases delete their own, so those become no-ops, but PendingFileRenameOperations
 * does collect an entry per quarantine until then. */

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

#include "hook-permissions.hpp"
#include "stub-reporter.hpp"
#include "update-blockers.hpp"
#include "updater-storage.hpp"

namespace {

int g_checks = 0;
int g_failures = 0;
const char *g_case = "";

void check(bool ok, const char *expression, int line)
{
	g_checks++;
	if (ok)
		return;

	g_failures++;
	printf("  FAIL %s:%d  %s\n", g_case, line, expression);
}

#define CHECK(cond) check((cond), #cond, __LINE__)

/* ---------------------------------------------------------------- helpers */

std::wstring current_user_sid()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return {};

	DWORD size = 0;
	GetTokenInformation(token, TokenUser, nullptr, 0, &size);

	std::vector<BYTE> buffer(size);
	std::wstring result;

	if (GetTokenInformation(token, TokenUser, buffer.data(), size, &size)) {
		wchar_t *text = nullptr;
		if (ConvertSidToStringSidW(reinterpret_cast<TOKEN_USER *>(buffer.data())->User.Sid, &text)) {
			result = text;
			LocalFree(text);
		}
	}

	CloseHandle(token);
	return result;
}

bool elevated()
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &token))
		return false;

	TOKEN_ELEVATION elevation = {};
	DWORD size = sizeof(elevation);
	const bool ok = GetTokenInformation(token, TokenElevation, &elevation, size, &size) && elevation.TokenIsElevated;

	CloseHandle(token);
	return ok;
}

bool apply_sddl(const fs::path &path, const std::wstring &sddl)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
		return false;

	PSID owner = nullptr;
	PACL dacl = nullptr;
	BOOL present = false;
	BOOL defaulted = false;
	bool ok = false;

	std::wstring text = path.wstring();

	if (GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) && GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present) {
		SECURITY_INFORMATION what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;

		ok = SetNamedSecurityInfoW(text.data(), SE_FILE_OBJECT, what, owner, nullptr, dacl, nullptr) == ERROR_SUCCESS;
	}

	LocalFree(descriptor);
	return ok;
}

bool apply_dacl(const fs::path &path, const std::wstring &sddl)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl.c_str(), SDDL_REVISION_1, &descriptor, nullptr))
		return false;

	PACL dacl = nullptr;
	BOOL present = false;
	BOOL defaulted = false;
	bool ok = false;

	if (GetSecurityDescriptorDacl(descriptor, &present, &dacl, &defaulted) && present) {
		std::wstring text = path.wstring();
		const SECURITY_INFORMATION what = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
		ok = SetNamedSecurityInfoW(text.data(), SE_FILE_OBJECT, what, nullptr, nullptr, dacl, nullptr) == ERROR_SUCCESS;
	}

	LocalFree(descriptor);
	return ok;
}

std::wstring read_sddl(const fs::path &path)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	const SECURITY_INFORMATION what = OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;

	if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, what, nullptr, nullptr, nullptr, nullptr, &descriptor) != ERROR_SUCCESS)
		return {};

	wchar_t *text = nullptr;
	std::wstring result;

	if (ConvertSecurityDescriptorToStringSecurityDescriptorW(descriptor, SDDL_REVISION_1, what, &text, nullptr)) {
		result = text;
		LocalFree(text);
	}

	LocalFree(descriptor);
	return result;
}

/* Administrators own it and nobody else may write, which is what the repair
 * has to leave behind. Checked through the descriptor rather than by calling
 * back into the code under test. */
void check_hardened(const fs::path &path, int line)
{
	const std::wstring sddl = read_sddl(path);

	check(sddl.rfind(L"O:BA", 0) == 0, "owner is Administrators", line);
	check(sddl.find(L"PAI") != std::wstring::npos, "DACL is protected from inheritance", line);
	check(sddl.find(current_user_sid()) == std::wstring::npos, "no ACE for the standard user", line);
	check(sddl.find(L"FA;;;BU") == std::wstring::npos, "Users are not granted full access", line);
}

void check_updater_hardened(const fs::path &path, int line)
{
	const std::wstring sddl = read_sddl(path);

	check(sddl.rfind(L"O:BA", 0) == 0, "owner is Administrators", line);
	check(sddl.find(L"D:P") != std::wstring::npos, "DACL is protected from inheritance", line);
	check(sddl.find(L";;;BU") == std::wstring::npos, "Users have no access", line);
	check(sddl.find(current_user_sid()) == std::wstring::npos, "current user has no ACE", line);
}

/* Owned by the user running the tests rather than by Administrators, and
 * writable by BUILTIN\Users - the 1.21-era shape the repair exists for. */
bool make_untrusted(const fs::path &dir)
{
	std::error_code ec;
	fs::create_directories(dir, ec);

	const std::wstring sid = current_user_sid();
	return apply_sddl(dir, L"O:" + sid + L"D:(A;OICI;FA;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)");
}

bool make_trusted(const fs::path &dir)
{
	std::error_code ec;
	fs::create_directories(dir, ec);

	return apply_sddl(dir, L"O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;OICI;FRFX;;;BU)");
}

bool make_creation_only_parent(const fs::path &dir)
{
	std::error_code ec;
	fs::create_directories(dir, ec);

	/* ProgramData's relevant shape: Users may add a subdirectory (0x4), but
	 * cannot delete/rename existing children or rewrite this DACL. */
	return apply_sddl(dir, L"O:BAD:PAI(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)(A;CI;0x4;;;BU)");
}

void write_file(const fs::path &path, const char *contents)
{
	FILE *file = nullptr;
	if (_wfopen_s(&file, path.c_str(), L"wb") == 0 && file) {
		fwrite(contents, 1, strlen(contents), file);
		fclose(file);
	}
}

std::string read_file(const fs::path &path)
{
	FILE *file = nullptr;
	if (_wfopen_s(&file, path.c_str(), L"rb") != 0 || !file)
		return {};

	std::string contents;
	char buffer[256];
	for (size_t read = 0; (read = fread(buffer, 1, sizeof(buffer), file)) != 0;)
		contents.append(buffer, read);
	fclose(file);
	return contents;
}

/* What a hooked process does to the directory: a mapped DLL is open without
 * FILE_SHARE_DELETE, and no rename can take it down. */
HANDLE hold_open(const fs::path &path)
{
	return CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

bool quarantine_exists(const fs::path &dir)
{
	std::error_code ec;
	const std::wstring prefix = dir.filename().wstring() + L".quarantine";

	for (const auto &entry : fs::directory_iterator(dir.parent_path(), ec)) {
		if (entry.path().filename().wstring().rfind(prefix, 0) == 0)
			return true;
	}

	return false;
}

bool updater_log_sidecar_exists(const fs::path &dir)
{
	std::error_code ec;
	for (const auto &entry : fs::directory_iterator(dir.parent_path(), ec)) {
		if (entry.path().filename().wstring().rfind(L".updater-log-", 0) == 0)
			return true;
	}

	return false;
}

bool file_exists(const fs::path &path)
{
	std::error_code ec;
	return fs::exists(path, ec);
}

/* A fake install tree holding a publishable payload, laid out where
 * trusted_hook_payload looks for it. */
fs::path make_payload(const fs::path &app_dir)
{
	const fs::path source =
		app_dir / L"resources" / L"app.asar.unpacked" / L"node_modules" / L"obs-studio-node" / L"data" / L"obs-plugins" / L"win-capture";

	make_trusted(app_dir);
	make_trusted(source);

	for (const wchar_t *name : {L"graphics-hook32.dll", L"graphics-hook64.dll", L"obs-vulkan32.json", L"obs-vulkan64.json"}) {
		write_file(source / name, "payload");
		apply_sddl(source / name, L"O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;BU)");
	}

	return source;
}

struct Case {
	fs::path root;
	fs::path hook_dir;
	fs::path app_dir;

	explicit Case(const fs::path &scratch, const char *name)
	{
		g_case = name;
		printf("  %s\n", name);

		root = scratch / name;
		hook_dir = root / L"obs-studio-hook";
		app_dir = root / L"app";

		std::error_code ec;
		fs::remove_all(root, ec);
		make_trusted(root);
		clear_reported_category();
	}
};

/* ------------------------------------------------------------------ cases */

void updater_directory_is_created_and_verified(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_is_created_and_verified");
	const fs::path temp_dir = c.root / L"run";

	CHECK(prepare_updater_temp_dir(temp_dir, false));
	check_updater_hardened(temp_dir, __LINE__);

	CHECK(!prepare_updater_temp_dir(temp_dir, false));
	CHECK(prepare_updater_temp_dir(temp_dir, true));
}

void untrusted_updater_directory_is_not_adopted(const fs::path &scratch)
{
	Case c(scratch, "untrusted_updater_directory_is_not_adopted");
	const fs::path temp_dir = c.root / L"run";

	CHECK(make_untrusted(temp_dir));
	write_file(temp_dir / L"planted.dll", "theirs");

	CHECK(!prepare_updater_temp_dir(temp_dir, true));
	CHECK(file_exists(temp_dir / L"planted.dll"));
	CHECK(read_sddl(temp_dir).find(L"FA;;;BU") != std::wstring::npos);
}

void updater_directory_requires_the_updater_acl(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_requires_the_updater_acl");
	const fs::path missing_admin = c.root / L"missing-admin";
	const fs::path extra_reader = c.root / L"extra-reader";
	const std::wstring removable_dacl = L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

	/* Older runs left this leaf with no Administrators ACE, so an interrupted
	 * test could not repair or remove it on the next run. The owner can always
	 * replace the DACL without also requesting WRITE_OWNER. */
	if (file_exists(missing_admin)) {
		CHECK(apply_dacl(missing_admin, removable_dacl));
		std::error_code ec;
		CHECK(fs::remove(missing_admin, ec));
	}

	CHECK(prepare_updater_temp_dir(missing_admin, false));
	CHECK(apply_sddl(missing_admin, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;;FA;;;BA)"));
	CHECK(!prepare_updater_temp_dir(missing_admin, true));
	CHECK(apply_dacl(missing_admin, removable_dacl));

	CHECK(prepare_updater_temp_dir(extra_reader, false));
	CHECK(apply_sddl(extra_reader, L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)"));
	CHECK(!prepare_updater_temp_dir(extra_reader, true));
}

void updater_directory_needs_a_trusted_parent(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_needs_a_trusted_parent");
	const fs::path loose = c.root / L"loose";
	const fs::path temp_dir = loose / L"run";

	CHECK(make_untrusted(loose));
	CHECK(!prepare_updater_temp_dir(temp_dir, false));
	CHECK(!file_exists(temp_dir));
}

void updater_directory_accepts_a_creation_only_parent(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_accepts_a_creation_only_parent");
	const fs::path parent = c.root / L"programdata-shape";
	const fs::path temp_dir = parent / L"run";

	CHECK(make_creation_only_parent(parent));
	CHECK(prepare_updater_temp_dir(temp_dir, false));
	check_updater_hardened(temp_dir, __LINE__);
}

void updater_directory_rejects_non_normal_paths(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_rejects_non_normal_paths");
	const fs::path temp_dir = c.root / L"missing" / L".." / L"run";

	CHECK(!prepare_updater_temp_dir(temp_dir, false));
	CHECK(!file_exists(c.root / L"run"));
}

void updater_directory_rejects_reserved_prune_names(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_rejects_reserved_prune_names");
	const fs::path claimed = c.root / L".prune-00000000000000000000000000000001";

	CHECK(!prepare_updater_temp_dir(claimed, false));
	CHECK(!file_exists(claimed));
}

void updater_directory_rejects_a_reparse_point(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_rejects_a_reparse_point");
	const fs::path elsewhere = c.root / L"elsewhere";
	const fs::path temp_dir = c.root / L"run";

	CHECK(make_trusted(elsewhere));
	write_file(elsewhere / L"planted.dll", "theirs");

	std::error_code ec;
	fs::create_directory_symlink(elsewhere, temp_dir, ec);
	if (ec) {
		printf("      skipped: could not create a junction (%d)\n", ec.value());
		return;
	}

	CHECK(!prepare_updater_temp_dir(temp_dir, true));
	CHECK(file_exists(elsewhere / L"planted.dll"));
}

void updater_root_is_resolved_from_programdata(const fs::path &scratch)
{
	Case c(scratch, "updater_root_is_resolved_from_programdata");
	CHECK(programdata_updater_root() == programdata_hook_dir().parent_path() / L"slobs-updater");
}

void untrusted_updater_root_is_replaced(const fs::path &scratch)
{
	Case c(scratch, "untrusted_updater_root_is_replaced");
	const fs::path root = c.root / L"updater-root";

	CHECK(make_untrusted(root));
	write_file(root / L"planted.dll", "theirs");

	UpdaterStorageDiagnostics diagnostics;
	CHECK(prepare_updater_root(root, &diagnostics));
	CHECK(diagnostics.root_replaced);
	CHECK(!diagnostics.root_replaced_reason.empty());
	check_updater_hardened(root, __LINE__);
	CHECK(!file_exists(root / L"planted.dll"));
	CHECK(quarantine_exists(root));
}

void updater_root_replaces_a_file(const fs::path &scratch)
{
	Case c(scratch, "updater_root_replaces_a_file");
	const fs::path root = c.root / L"updater-root";

	write_file(root, "squatted");
	CHECK(prepare_updater_root(root));
	check_updater_hardened(root, __LINE__);
	CHECK(!quarantine_exists(root));
}

void blocked_updater_root_quarantine_is_distinct(const fs::path &scratch)
{
	Case c(scratch, "blocked_updater_root_quarantine_is_distinct");
	const fs::path root = c.root / L"updater-root";

	CHECK(make_untrusted(root));
	HANDLE held = CreateFileW(root.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (held == INVALID_HANDLE_VALUE) {
		CHECK(false);
		return;
	}

	UpdaterStorageDiagnostics diagnostics;
	CHECK(!prepare_updater_root(root, &diagnostics));
	CHECK(diagnostics.failure_category == "UpdaterStorageQuarantineBlocked");
	CloseHandle(held);
}

void updater_directory_rejects_a_file(const fs::path &scratch)
{
	Case c(scratch, "updater_directory_rejects_a_file");
	const fs::path temp_dir = c.root / L"run";

	write_file(temp_dir, "not a directory");
	CHECK(!prepare_updater_temp_dir(temp_dir, true));
	CHECK(file_exists(temp_dir));
}

void owned_updater_directory_is_cleaned(const fs::path &scratch)
{
	Case c(scratch, "owned_updater_directory_is_cleaned");
	const fs::path temp_dir = c.root / L"run";

	CHECK(prepare_updater_temp_dir(temp_dir, false));
	write_file(temp_dir / L"payload.dll", "payload");
	write_file(temp_dir / L"slobs-updater.log", "diagnostic log");
	CHECK(cleanup_updater_temp_dir(temp_dir));
	CHECK(!file_exists(temp_dir));
	CHECK(!updater_log_sidecar_exists(temp_dir));
}

void failed_cleanup_preserves_updater_log(const fs::path &scratch)
{
	Case c(scratch, "failed_cleanup_preserves_updater_log");
	const fs::path temp_dir = c.root / L"run";
	const fs::path log = temp_dir / L"slobs-updater.log";
	const fs::path locked = temp_dir / L"locked.dll";

	CHECK(prepare_updater_temp_dir(temp_dir, false));
	write_file(log, "diagnostic log");
	write_file(locked, "locked");
	HANDLE held = hold_open(locked);
	if (held == INVALID_HANDLE_VALUE) {
		CHECK(false);
		return;
	}

	UpdaterStorageDiagnostics diagnostics;
	CHECK(!cleanup_updater_temp_dir(temp_dir, true, &diagnostics));
	CHECK(file_exists(log));
	CHECK(read_file(log) == "diagnostic log");
	CHECK(diagnostics.failure.find(L"updater log retained at") != std::wstring::npos);

	CloseHandle(held);
	CHECK(cleanup_updater_temp_dir(temp_dir));
	CHECK(!file_exists(temp_dir));
}

void open_directory_handle_blocks_final_cleanup_without_a_sidecar(const fs::path &scratch)
{
	Case c(scratch, "open_directory_handle_blocks_final_cleanup_without_a_sidecar");
	const fs::path temp_dir = c.root / L"run";
	const fs::path log = temp_dir / L"slobs-updater.log";

	CHECK(prepare_updater_temp_dir(temp_dir, false));
	write_file(log, "diagnostic log");
	HANDLE held =
		CreateFileW(temp_dir.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
	if (held == INVALID_HANDLE_VALUE) {
		CHECK(false);
		return;
	}

	UpdaterStorageDiagnostics diagnostics;
	CHECK(!cleanup_updater_temp_dir(temp_dir, true, &diagnostics));
	CHECK(file_exists(temp_dir));
	CHECK(!file_exists(log));
	CHECK(!updater_log_sidecar_exists(temp_dir));

	CloseHandle(held);
	CHECK(cleanup_updater_temp_dir(temp_dir));
	CHECK(!file_exists(temp_dir));
}

void vanished_updater_directory_is_already_clean(const fs::path &scratch)
{
	Case c(scratch, "vanished_updater_directory_is_already_clean");
	CHECK(cleanup_updater_temp_dir(c.root / L"missing"));
}

void updater_run_lock_can_be_removed(const fs::path &scratch)
{
	Case c(scratch, "updater_run_lock_can_be_removed");
	const fs::path temp_dir = c.root / L"run";
	CHECK(prepare_updater_temp_dir(temp_dir, false));

	void *lock = nullptr;
	CHECK(acquire_updater_run_lock(temp_dir, &lock));
	release_updater_run_lock(lock);
	CHECK(remove_updater_run_lock(temp_dir));
	CHECK(!file_exists(temp_dir / L".run-lock"));
}

void preview_ancestor_policy_is_used_for_cleanup(const fs::path &scratch)
{
	Case c(scratch, "preview_ancestor_policy_is_used_for_cleanup");
	const fs::path temp_dir = c.root / L"run";

	CHECK(prepare_updater_temp_dir(temp_dir, false));
	CHECK(make_untrusted(c.root));

	UpdaterStorageDiagnostics diagnostics;
	CHECK(cleanup_updater_temp_dir(temp_dir, false, &diagnostics));
	CHECK(!file_exists(temp_dir));
}

void preview_ancestor_policy_is_used_for_pruning(const fs::path &scratch)
{
	Case c(scratch, "preview_ancestor_policy_is_used_for_pruning");
	const fs::path root = c.root / L"updater-root";
	const fs::path run = root / L"run-00000000000000000000000000000001";

	CHECK(prepare_updater_temp_dir(root, false));
	CHECK(prepare_updater_temp_dir(run, false));

	std::error_code ec;
	fs::last_write_time(run, fs::file_time_type::clock::now() - std::chrono::hours(48), ec);
	CHECK(make_untrusted(c.root));
	prune_updater_runs(root, false);
	CHECK(!file_exists(run));
}

void stale_updater_runs_are_pruned(const fs::path &scratch)
{
	Case c(scratch, "stale_updater_runs_are_pruned");
	const fs::path root = c.root / L"updater-root";
	const fs::path abandoned = root / L"run-00000000000000000000000000000001";
	const fs::path recovery = root / L"run-00000000000000000000000000000002";
	const fs::path fresh = root / L"run-00000000000000000000000000000003";
	const fs::path interrupted = root / L"run-00000000000000000000000000000004";
	const fs::path claimed = root / L".prune-00000000000000000000000000000005";

	CHECK(prepare_updater_temp_dir(root, false));
	CHECK(prepare_updater_temp_dir(abandoned, false));
	CHECK(prepare_updater_temp_dir(recovery, false));
	CHECK(prepare_updater_temp_dir(fresh, false));
	CHECK(prepare_updater_temp_dir(interrupted, false));

	std::error_code ec;
	fs::create_directories(abandoned / L"new-files", ec);
	fs::create_directories(recovery / L"old-files", ec);
	fs::last_write_time(abandoned, fs::file_time_type::clock::now() - std::chrono::hours(48), ec);
	fs::last_write_time(recovery, fs::file_time_type::clock::now() - std::chrono::hours(24 * 8), ec);
	fs::rename(interrupted, claimed, ec);
	CHECK(!ec);

	prune_updater_runs(root);
	CHECK(!file_exists(abandoned));
	CHECK(!file_exists(recovery));
	CHECK(file_exists(fresh));
	CHECK(!file_exists(claimed));
}

void updater_root_quarantine_sweep_is_non_recursive(const fs::path &scratch)
{
	Case c(scratch, "updater_root_quarantine_sweep_is_non_recursive");
	const fs::path root = c.root / L"updater-root";
	const fs::path nonempty = c.root / L"updater-root.quarantine-00000000000000000000000000000001";
	const fs::path empty = c.root / L"updater-root.quarantine-00000000000000000000000000000002";
	const fs::path unrelated = c.root / L"updater-root.quarantine-not-random";

	CHECK(prepare_updater_temp_dir(root, false));
	CHECK(make_untrusted(nonempty));
	CHECK(make_untrusted(empty));
	CHECK(make_untrusted(unrelated));
	write_file(nonempty / L"planted.dll", "theirs");

	prune_updater_runs(root);
	CHECK(file_exists(nonempty));
	CHECK(!file_exists(empty));
	CHECK(file_exists(nonempty / L"planted.dll"));
	CHECK(file_exists(unrelated));

	std::error_code ec;
	CHECK(fs::remove(nonempty / L"planted.dll", ec));
	prune_updater_runs(root);
	CHECK(!file_exists(nonempty));
}

void active_updater_run_is_not_pruned(const fs::path &scratch)
{
	Case c(scratch, "active_updater_run_is_not_pruned");
	const fs::path root = c.root / L"updater-root";
	const fs::path run = root / L"run-00000000000000000000000000000001";

	CHECK(prepare_updater_temp_dir(root, false));
	CHECK(prepare_updater_temp_dir(run, false));
	void *lock = nullptr;
	CHECK(acquire_updater_run_lock(run, &lock));

	std::error_code ec;
	fs::last_write_time(run, fs::file_time_type::clock::now() - std::chrono::hours(48), ec);

	prune_updater_runs(root);
	CHECK(file_exists(run));

	release_updater_run_lock(lock);
	prune_updater_runs(root);
	CHECK(!file_exists(run));
}

void untrusted_stale_run_is_not_pruned(const fs::path &scratch)
{
	Case c(scratch, "untrusted_stale_run_is_not_pruned");
	const fs::path root = c.root / L"updater-root";
	const fs::path run = root / L"run-00000000000000000000000000000001";

	CHECK(prepare_updater_temp_dir(root, false));
	CHECK(make_untrusted(run));
	std::error_code ec;
	CHECK(fs::create_directory(run / L".run-lock", ec));

	fs::last_write_time(run, fs::file_time_type::clock::now() - std::chrono::hours(48), ec);
	UpdaterStorageDiagnostics diagnostics;
	prune_updater_runs(root, true, &diagnostics);
	CHECK(file_exists(run));
	CHECK(diagnostics.cleanup_warning.find(L"Refusing updater directory") != std::wstring::npos);
}

void untrusted_directory_is_replaced(const fs::path &scratch)
{
	Case c(scratch, "untrusted_directory_is_replaced");

	make_untrusted(c.hook_dir);
	write_file(c.hook_dir / L"graphics-hook64.dll", "planted");

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Secured);

	check_hardened(c.hook_dir, __LINE__);
	CHECK(quarantine_exists(c.hook_dir));
	CHECK(!file_exists(c.hook_dir / L"graphics-hook64.dll"));
}

void secured_directory_is_left_alone(const fs::path &scratch)
{
	Case c(scratch, "secured_directory_is_left_alone");

	make_untrusted(c.hook_dir);

	HookRepairState first;
	CHECK(secure_hook_directory(c.hook_dir, first) == HookSecure::Secured);

	/* only an elevated writer could have put this here, so the second pass
	 * has no reason to take the directory away */
	write_file(c.hook_dir / L"graphics-hook64.dll", "ours");
	apply_sddl(c.hook_dir / L"graphics-hook64.dll", L"O:BAD:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FRFX;;;BU)");

	/* clear the first pass's quarantine, so what the second one leaves
	 * behind is the only thing quarantine_exists can see */
	std::error_code ec;
	for (const auto &entry : fs::directory_iterator(c.root, ec)) {
		if (entry.path() != c.hook_dir)
			fs::remove_all(entry.path(), ec);
	}

	HookRepairState second;
	CHECK(secure_hook_directory(c.hook_dir, second) == HookSecure::Secured);
	CHECK(!quarantine_exists(c.hook_dir));
	CHECK(file_exists(c.hook_dir / L"graphics-hook64.dll"));
}

void open_handle_blocks_quarantine(const fs::path &scratch)
{
	Case c(scratch, "open_handle_blocks_quarantine");

	make_untrusted(c.hook_dir);
	write_file(c.hook_dir / L"graphics-hook64.dll", "planted");

	HANDLE holder = hold_open(c.hook_dir / L"graphics-hook64.dll");
	CHECK(holder != INVALID_HANDLE_VALUE);

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Blocked);

	/* left exactly as found, planted file and all */
	CHECK(!quarantine_exists(c.hook_dir));
	CHECK(file_exists(c.hook_dir / L"graphics-hook64.dll"));
	CHECK(read_sddl(c.hook_dir).find(L"FA;;;BU") != std::wstring::npos);

	CloseHandle(holder);
}

void blocked_holder_is_named(const fs::path &scratch)
{
	Case c(scratch, "blocked_holder_is_named");

	make_untrusted(c.hook_dir);
	write_file(c.hook_dir / L"graphics-hook64.dll", "planted");

	HANDLE holder = hold_open(c.hook_dir / L"graphics-hook64.dll");
	CHECK(holder != INVALID_HANDLE_VALUE);

	const std::vector<blocker_info> blockers = get_hook_dir_blockers(c.hook_dir);
	bool found_us = false;

	for (const blocker_info &info : blockers)
		found_us = found_us || info.pid == GetCurrentProcessId();

	CHECK(!blockers.empty());
	CHECK(found_us);

	CloseHandle(holder);
}

void publish_reports_blocked(const fs::path &scratch)
{
	Case c(scratch, "publish_reports_blocked");

	make_untrusted(c.hook_dir);
	write_file(c.hook_dir / L"graphics-hook64.dll", "planted");
	make_payload(c.app_dir);

	HANDLE holder = hold_open(c.hook_dir / L"graphics-hook64.dll");

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Blocked);

	const HookRepair result = publish_hook_payload(c.app_dir, c.hook_dir, state);
	report_hook_repair(result);

	CHECK(result == HookRepair::QuarantineBlocked);
	CHECK(last_reported_category() == "HookQuarantineBlocked");
	/* nothing of ours goes into a directory that is still theirs */
	CHECK(!file_exists(c.hook_dir / L"obs-vulkan64.json"));

	CloseHandle(holder);
}

void releasing_the_holder_lets_publish_finish(const fs::path &scratch)
{
	Case c(scratch, "releasing_the_holder_lets_publish_finish");

	make_untrusted(c.hook_dir);
	write_file(c.hook_dir / L"graphics-hook64.dll", "planted");
	make_payload(c.app_dir);

	HANDLE holder = hold_open(c.hook_dir / L"graphics-hook64.dll");

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Blocked);

	/* the user closed their game while the files downloaded */
	CloseHandle(holder);

	const HookRepair result = publish_hook_payload(c.app_dir, c.hook_dir, state);
	report_hook_repair(result);

	CHECK(result == HookRepair::Secured);
	check_hardened(c.hook_dir, __LINE__);
	CHECK(file_exists(c.hook_dir / L"graphics-hook64.dll"));
	CHECK(file_exists(c.hook_dir / L"obs-vulkan64.json"));
	CHECK(last_reported_category().empty());
}

void drifted_directory_is_secured_again(const fs::path &scratch)
{
	Case c(scratch, "drifted_directory_is_secured_again");

	make_untrusted(c.hook_dir);
	make_payload(c.app_dir);

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Secured);

	/* whoever we took it from took it back while the files downloaded */
	CHECK(make_untrusted(c.hook_dir));
	write_file(c.hook_dir / L"graphics-hook64.dll", "theirs");

	CHECK(publish_hook_payload(c.app_dir, c.hook_dir, state) == HookRepair::Secured);
	check_hardened(c.hook_dir, __LINE__);
	CHECK(quarantine_exists(c.hook_dir));
}

void reparse_point_is_unlinked(const fs::path &scratch)
{
	Case c(scratch, "reparse_point_is_unlinked");

	const fs::path elsewhere = c.root / L"elsewhere";
	make_trusted(elsewhere);
	write_file(elsewhere / L"bystander.txt", "not ours to delete");

	std::error_code ec;
	fs::create_directory_symlink(elsewhere, c.hook_dir, ec);
	if (ec) {
		printf("      skipped: could not create a junction (%d)\n", ec.value());
		return;
	}

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Secured);

	check_hardened(c.hook_dir, __LINE__);
	CHECK(!fs::is_symlink(fs::symlink_status(c.hook_dir, ec)));
	/* worked on the link, never through it */
	CHECK(file_exists(elsewhere / L"bystander.txt"));
}

void untrusted_ancestor_is_reported_not_repaired(const fs::path &scratch)
{
	Case c(scratch, "untrusted_ancestor_is_reported_not_repaired");

	const fs::path loose = c.root / L"loose";
	const fs::path hook_dir = loose / L"obs-studio-hook";

	make_trusted(loose);
	make_trusted(hook_dir);
	make_payload(c.app_dir);

	/* a standard user who can rename the parent, which no elevated writer
	 * can repair and which the repair deliberately does not act on */
	CHECK(apply_sddl(loose, L"O:" + current_user_sid() + L"D:(A;OICI;FA;;;BU)(A;OICI;FA;;;BA)(A;OICI;FA;;;SY)"));

	HookRepairState state;
	CHECK(secure_hook_directory(hook_dir, state) == HookSecure::Secured);

	const HookRepair result = publish_hook_payload(c.app_dir, hook_dir, state);
	report_hook_repair(result);

	CHECK(result == HookRepair::AncestorUntrusted);
	CHECK(last_reported_category() == "HookDirAncestorUntrusted");
	/* the directory itself was sound, so it stays where it is */
	CHECK(!quarantine_exists(hook_dir));
	CHECK(file_exists(hook_dir / L"graphics-hook64.dll"));
}

void payload_is_published(const fs::path &scratch)
{
	Case c(scratch, "payload_is_published");

	make_untrusted(c.hook_dir);
	make_payload(c.app_dir);

	HookRepairState state;
	const HookRepair result = publish_hook_payload(c.app_dir, c.hook_dir, state);
	report_hook_repair(result);

	CHECK(result == HookRepair::Secured);

	for (const wchar_t *name : {L"graphics-hook32.dll", L"graphics-hook64.dll", L"obs-vulkan32.json", L"obs-vulkan64.json"})
		CHECK(file_exists(c.hook_dir / name));

	check_hardened(c.hook_dir, __LINE__);
	CHECK(last_reported_category().empty());
}

void untrusted_payload_is_not_published(const fs::path &scratch)
{
	Case c(scratch, "untrusted_payload_is_not_published");

	make_untrusted(c.hook_dir);

	const fs::path source = make_payload(c.app_dir);
	/* an install directory a standard user can rewrite is not a source of
	 * anything we publish machine-wide */
	CHECK(apply_sddl(source, L"O:" + current_user_sid() + L"D:(A;OICI;FA;;;BU)(A;OICI;FA;;;BA)"));

	HookRepairState state;
	CHECK(publish_hook_payload(c.app_dir, c.hook_dir, state) == HookRepair::Secured);

	check_hardened(c.hook_dir, __LINE__);
	CHECK(!file_exists(c.hook_dir / L"graphics-hook64.dll"));
}

/* Only with --volume-root: the ACE every drive root carries grants DELETE to
 * Authenticated Users, and counting that against the path rejected real
 * machines. Needs a scratch volume, since C: is not ours to re-permission. */
void volume_root_delete_is_not_held_against_the_path(const fs::path &volume_root)
{
	Case c(volume_root, "volume_root_delete_is_not_held_against_the_path");

	make_untrusted(c.hook_dir);
	make_payload(c.app_dir);

	HookRepairState state;
	CHECK(secure_hook_directory(c.hook_dir, state) == HookSecure::Secured);

	const HookRepair result = publish_hook_payload(c.app_dir, c.hook_dir, state);
	report_hook_repair(result);

	/* AncestorUntrusted here means the root's inherit-only DELETE ACE is
	 * being counted against every path on the volume again */
	CHECK(result == HookRepair::Secured);
	CHECK(last_reported_category().empty());

	std::error_code ec;
	fs::remove_all(c.root, ec);
}

const wchar_t *const kScratchLeaf = L"slobs-hook-tests";

std::wstring lowered(std::wstring text)
{
	for (wchar_t &c : text)
		c = towlower(c);

	return text;
}

bool inside(const fs::path &path, const wchar_t *variable)
{
	wchar_t *value = nullptr;
	size_t length = 0;

	if (_wdupenv_s(&value, &length, variable) != 0 || !value)
		return false;

	const std::wstring prefix = lowered(fs::path(value).make_preferred().wstring()) + L"\\";
	const bool within = lowered(path.wstring()).rfind(prefix, 0) == 0;

	free(value);
	return within;
}

/* Everything below the scratch root is deleted recursively by a process
 * running elevated, so the path has to be one that cannot be anything else.
 * Resolved first, because .. and a symlink both spell a path that is not the
 * one it looks like, and compared without case, because Windows does. The leaf
 * name is the load-bearing rule: nothing that matters is called this, and no
 * volume root or system directory can be. */
bool resolve_scratch(fs::path &scratch)
{
	std::error_code ec;
	const fs::path resolved = fs::weakly_canonical(fs::absolute(scratch, ec), ec).make_preferred();

	if (ec) {
		printf("Refusing --scratch %ls: it cannot be resolved (%d)\n", scratch.c_str(), ec.value());
		return false;
	}

	if (!resolved.has_relative_path() || !resolved.parent_path().has_relative_path()) {
		printf("Refusing --scratch %ls: it is a volume root or sits directly in one\n", resolved.c_str());
		return false;
	}

	if (lowered(resolved.filename().wstring()) != kScratchLeaf) {
		printf("Refusing --scratch %ls: the leaf must be %ls\n", resolved.c_str(), kScratchLeaf);
		return false;
	}

	if (inside(resolved, L"SystemRoot") || inside(resolved, L"ProgramFiles") || inside(resolved, L"ProgramFiles(x86)")) {
		printf("Refusing --scratch %ls: it is inside a system directory\n", resolved.c_str());
		return false;
	}

	scratch = resolved;
	return true;
}

/* The volume root case needs an actual root, and never deletes it - only the
 * case directory made below it. Still not the system drive: a mistake there
 * would land in the one place nobody can re-provision. */
bool resolve_volume_root(fs::path &volume_root)
{
	std::error_code ec;
	const fs::path resolved = fs::weakly_canonical(fs::absolute(volume_root, ec), ec).make_preferred();

	if (ec || resolved.has_relative_path()) {
		printf("Refusing --volume-root %ls: it must be a volume root, such as X:\\\n", volume_root.c_str());
		return false;
	}

	wchar_t *system_drive = nullptr;
	size_t length = 0;
	bool is_system = false;

	if (_wdupenv_s(&system_drive, &length, L"SystemDrive") == 0 && system_drive) {
		is_system = lowered(resolved.root_name().wstring()) == lowered(system_drive);
		free(system_drive);
	}

	if (is_system) {
		printf("Refusing --volume-root %ls: mount a scratch volume instead of using the system drive\n", resolved.c_str());
		return false;
	}

	volume_root = resolved;
	return true;
}

} // namespace

int wmain(int argc, wchar_t **argv)
{
	/* Beside the real hook directory rather than under %TEMP%: the ancestor
	 * walk reaches the drive root, and a tree below a user-owned directory
	 * reports AncestorUntrusted in every case. */
	fs::path scratch = programdata_hook_dir().parent_path() / kScratchLeaf;
	fs::path volume_root;

	for (int i = 1; i < argc; i++) {
		const std::wstring arg = argv[i];

		if (arg == L"--scratch" && i + 1 < argc)
			scratch = argv[++i];
		else if (arg == L"--volume-root" && i + 1 < argc)
			volume_root = argv[++i];
	}

	/* before the elevation check, so a bad path is answered as the argument
	 * error it is rather than hiding behind a missing privilege */
	if (!resolve_scratch(scratch))
		return 2;

	if (!volume_root.empty() && !resolve_volume_root(volume_root))
		return 2;

	if (!elevated()) {
		printf("These tests take ownership and rewrite DACLs; run them from an elevated terminal.\n");
		return 2;
	}

	printf("hook directory tests, scratch root %ls\n", scratch.c_str());

	std::error_code ec;
	fs::remove_all(scratch, ec);
	if (!make_trusted(scratch)) {
		printf("Could not create %ls\n", scratch.c_str());
		return 2;
	}

	updater_directory_is_created_and_verified(scratch);
	untrusted_updater_directory_is_not_adopted(scratch);
	updater_directory_requires_the_updater_acl(scratch);
	updater_directory_needs_a_trusted_parent(scratch);
	updater_directory_accepts_a_creation_only_parent(scratch);
	updater_directory_rejects_non_normal_paths(scratch);
	updater_directory_rejects_reserved_prune_names(scratch);
	updater_directory_rejects_a_reparse_point(scratch);
	updater_root_is_resolved_from_programdata(scratch);
	untrusted_updater_root_is_replaced(scratch);
	updater_root_replaces_a_file(scratch);
	blocked_updater_root_quarantine_is_distinct(scratch);
	updater_directory_rejects_a_file(scratch);
	owned_updater_directory_is_cleaned(scratch);
	failed_cleanup_preserves_updater_log(scratch);
	open_directory_handle_blocks_final_cleanup_without_a_sidecar(scratch);
	vanished_updater_directory_is_already_clean(scratch);
	updater_run_lock_can_be_removed(scratch);
	preview_ancestor_policy_is_used_for_cleanup(scratch);
	preview_ancestor_policy_is_used_for_pruning(scratch);
	stale_updater_runs_are_pruned(scratch);
	updater_root_quarantine_sweep_is_non_recursive(scratch);
	active_updater_run_is_not_pruned(scratch);
	untrusted_stale_run_is_not_pruned(scratch);
	untrusted_directory_is_replaced(scratch);
	secured_directory_is_left_alone(scratch);
	open_handle_blocks_quarantine(scratch);
	blocked_holder_is_named(scratch);
	publish_reports_blocked(scratch);
	releasing_the_holder_lets_publish_finish(scratch);
	drifted_directory_is_secured_again(scratch);
	reparse_point_is_unlinked(scratch);
	untrusted_ancestor_is_reported_not_repaired(scratch);
	payload_is_published(scratch);
	untrusted_payload_is_not_published(scratch);

	if (!volume_root.empty())
		volume_root_delete_is_not_held_against_the_path(volume_root);
	else
		printf("  (skipped the volume root case: pass --volume-root X:\\ to run it)\n");

	fs::remove_all(scratch, ec);

	printf("\n%d checks, %d failed\n", g_checks, g_failures);
	return g_failures == 0 ? 0 : 1;
}
