#include "updater-storage.hpp"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <chrono>
#include <cwctype>
#include <string>
#include <vector>

#include "hook-permissions.hpp"
#include "logger/log.h"
#include "security-random.hpp"

namespace {

const wchar_t *const kUpdaterDirSddl = L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
constexpr auto kAbandonedRunAge = std::chrono::hours(24);
constexpr auto kRecoveryRunAge = std::chrono::hours(24 * 7);

enum class PrepareResult { Ready, Collision, Failed };

void set_failure(UpdaterStorageDiagnostics *diagnostics, const std::wstring &reason)
{
	if (diagnostics)
		diagnostics->failure = reason;
	wlog_warn(L"%s", reason.c_str());
}

void set_ancestor_warning(UpdaterStorageDiagnostics *diagnostics, const fs::path &dir, const TrustReport &trust)
{
	const std::wstring reason = L"Updater storage " + dir.wstring() + L" is reached through " + trust.ancestor.wstring() + L", which " + trust.ancestor_why;
	if (diagnostics && diagnostics->ancestor_warning.empty())
		diagnostics->ancestor_warning = reason;
	wlog_warn(L"%s; continuing in preview mode", reason.c_str());
}

bool dacl_is_protected(const fs::path &dir, std::wstring &why)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	const DWORD read = GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, nullptr, nullptr, nullptr, nullptr, &descriptor);
	if (read != ERROR_SUCCESS) {
		why = L"has an unreadable DACL control: " + std::to_wstring(read);
		return false;
	}

	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	const bool protected_dacl = GetSecurityDescriptorControl(descriptor, &control, &revision) && (control & SE_DACL_PROTECTED) != 0;
	if (!protected_dacl)
		why = L"has a DACL that inherits from its parent";

	LocalFree(descriptor);
	return protected_dacl;
}

bool trusted_directory(const fs::path &dir, bool enforce_ancestors, UpdaterStorageDiagnostics *diagnostics)
{
	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
		set_failure(diagnostics, L"Refusing updater directory " + dir.wstring() + L": it is not a directory");
		return false;
	}

	const TrustReport trust = chain_trust(dir);
	if (!trust.object) {
		set_failure(diagnostics, L"Refusing updater directory " + dir.wstring() + L": it " + trust.object_why);
		return false;
	}

	std::wstring dacl_why;
	if (!dacl_is_protected(dir, dacl_why)) {
		set_failure(diagnostics, L"Refusing updater directory " + dir.wstring() + L": it " + dacl_why);
		return false;
	}

	if (!trust.ancestors) {
		if (enforce_ancestors) {
			set_failure(diagnostics,
				    L"Refusing updater directory " + dir.wstring() + L": ancestor " + trust.ancestor.wstring() + L" " + trust.ancestor_why);
			return false;
		}
		set_ancestor_warning(diagnostics, dir, trust);
	}

	return true;
}

PrepareResult create_secure_directory(const fs::path &dir, bool enforce_ancestors, UpdaterStorageDiagnostics *diagnostics)
{
	SECURITY_ATTRIBUTES attributes = {sizeof(attributes), nullptr, false};
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kUpdaterDirSddl, SDDL_REVISION_1, &attributes.lpSecurityDescriptor, nullptr)) {
		set_failure(diagnostics, L"Failed to build updater directory descriptor: " + std::to_wstring(GetLastError()));
		return PrepareResult::Failed;
	}

	const bool created = CreateDirectoryW(dir.c_str(), &attributes) != 0;
	const DWORD error = created ? ERROR_SUCCESS : GetLastError();
	LocalFree(attributes.lpSecurityDescriptor);

	if (!created) {
		if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
			return PrepareResult::Collision;
		set_failure(diagnostics, L"Failed to create updater directory " + dir.wstring() + L": " + std::to_wstring(error));
		return PrepareResult::Failed;
	}

	if (diagnostics)
		diagnostics->created = true;

	if (!trusted_directory(dir, enforce_ancestors, diagnostics)) {
		if (!RemoveDirectoryW(dir.c_str()))
			wlog_warn(L"Failed to remove rejected updater directory %s: %lu", dir.c_str(), GetLastError());
		return PrepareResult::Failed;
	}

	return PrepareResult::Ready;
}

PrepareResult prepare_directory(const fs::path &dir, bool allow_existing, bool enforce_ancestors, UpdaterStorageDiagnostics *diagnostics)
{
	if (dir.empty() || !dir.is_absolute() || !dir.has_relative_path()) {
		set_failure(diagnostics, L"Refusing invalid updater directory " + dir.wstring());
		return PrepareResult::Failed;
	}
	for (const fs::path &component : dir.relative_path()) {
		if (component == L"." || component == L"..") {
			set_failure(diagnostics, L"Refusing non-normal updater directory " + dir.wstring());
			return PrepareResult::Failed;
		}
	}

	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (!allow_existing)
			return PrepareResult::Collision;
		return trusted_directory(dir, enforce_ancestors, diagnostics) ? PrepareResult::Ready : PrepareResult::Failed;
	}

	const DWORD lookup_error = GetLastError();
	if (lookup_error != ERROR_FILE_NOT_FOUND && lookup_error != ERROR_PATH_NOT_FOUND) {
		set_failure(diagnostics, L"Could not inspect updater directory " + dir.wstring() + L": " + std::to_wstring(lookup_error));
		return PrepareResult::Failed;
	}

	const TrustReport destination = chain_trust(dir);
	if (!destination.ancestors) {
		if (enforce_ancestors) {
			set_failure(diagnostics, L"Refusing to create updater directory " + dir.wstring() + L": ancestor " + destination.ancestor.wstring() +
							 L" " + destination.ancestor_why);
			return PrepareResult::Failed;
		}
		set_ancestor_warning(diagnostics, dir, destination);
	}

	return create_secure_directory(dir, enforce_ancestors, diagnostics);
}

bool run_leaf(const fs::path &path)
{
	const std::wstring name = path.filename().wstring();
	if (name.size() != 36 || name.rfind(L"run-", 0) != 0)
		return false;

	for (size_t i = 4; i < name.size(); i++) {
		if (!iswxdigit(name[i]))
			return false;
	}
	return true;
}

bool quarantine_root(const fs::path &root, UpdaterStorageDiagnostics *diagnostics)
{
	for (int attempt = 0; attempt < 8; attempt++) {
		const std::wstring suffix = security_random_hex(4);
		if (suffix.empty()) {
			set_failure(diagnostics, L"Could not name an updater root quarantine: no randomness available");
			return false;
		}

		fs::path aside = root;
		aside += L".quarantine-" + suffix;
		if (MoveFileExW(root.c_str(), aside.c_str(), 0)) {
			if (diagnostics)
				diagnostics->root_replaced = true;
			wlog_warn(L"Moved untrusted updater root %s to %s", root.c_str(), aside.c_str());
			return true;
		}

		const DWORD error = GetLastError();
		if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) {
			set_failure(diagnostics, L"Could not move untrusted updater root " + root.wstring() + L" aside: " + std::to_wstring(error));
			return false;
		}
	}

	set_failure(diagnostics, L"Could not find a unique updater root quarantine name");
	return false;
}

} // namespace

fs::path programdata_updater_root()
{
	wchar_t path[MAX_PATH] = {};
	if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path)))
		return {};

	return fs::path(path) / L"slobs-updater";
}

bool prepare_updater_temp_dir(const fs::path &dir, bool allow_existing, UpdaterStorageDiagnostics *diagnostics)
{
	return prepare_directory(dir, allow_existing, true, diagnostics) == PrepareResult::Ready;
}

bool prepare_updater_root(const fs::path &root, UpdaterStorageDiagnostics *diagnostics)
{
	UpdaterStorageDiagnostics check;
	const DWORD attributes = GetFileAttributesW(root.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (trusted_directory(root, false, &check)) {
			if (diagnostics && !check.ancestor_warning.empty())
				diagnostics->ancestor_warning = check.ancestor_warning;
			return true;
		}

		if (!quarantine_root(root, diagnostics))
			return false;
	}

	const PrepareResult created = prepare_directory(root, false, false, diagnostics);
	if (created == PrepareResult::Collision) {
		set_failure(diagnostics, L"Updater root " + root.wstring() + L" was recreated while it was being secured");
		return false;
	}
	return created == PrepareResult::Ready;
}

void prune_updater_runs(const fs::path &root)
{
	std::error_code ec;
	const auto now = fs::file_time_type::clock::now();
	std::vector<fs::path> stale_runs;
	for (const fs::directory_entry &entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, ec)) {
		if (!entry.is_directory(ec) || entry.is_symlink(ec) || !run_leaf(entry.path()))
			continue;

		const auto modified = entry.last_write_time(ec);
		if (ec)
			continue;

		const bool has_backup = fs::exists(entry.path() / L"old-files", ec);
		if (ec)
			continue;

		const auto retention = has_backup ? kRecoveryRunAge : kAbandonedRunAge;
		if (now - modified < retention)
			continue;

		stale_runs.push_back(entry.path());
	}

	for (const fs::path &run : stale_runs) {
		if (cleanup_updater_temp_dir(run))
			wlog_info(L"Pruned abandoned updater run %s", run.c_str());
	}
}

fs::path create_default_updater_temp_dir(UpdaterStorageDiagnostics *diagnostics)
{
	const fs::path root = programdata_updater_root();
	if (root.empty()) {
		set_failure(diagnostics, L"Failed to resolve the system ProgramData directory");
		return {};
	}

	if (!prepare_updater_root(root, diagnostics))
		return {};

	prune_updater_runs(root);

	for (int attempt = 0; attempt < 8; attempt++) {
		const std::wstring suffix = security_random_hex(4);
		if (suffix.empty()) {
			set_failure(diagnostics, L"Failed to generate a random updater directory name");
			return {};
		}

		const fs::path run_dir = root / (L"run-" + suffix);
		UpdaterStorageDiagnostics run_diagnostics;
		const PrepareResult prepared = prepare_directory(run_dir, false, false, &run_diagnostics);
		if (prepared == PrepareResult::Ready) {
			if (diagnostics) {
				diagnostics->created = true;
				if (diagnostics->ancestor_warning.empty())
					diagnostics->ancestor_warning = run_diagnostics.ancestor_warning;
			}
			return run_dir;
		}
		if (prepared != PrepareResult::Collision) {
			if (diagnostics)
				diagnostics->failure = run_diagnostics.failure;
			return {};
		}
	}

	set_failure(diagnostics, L"Failed to create a unique updater directory after eight name collisions");
	return {};
}

bool cleanup_updater_temp_dir(const fs::path &dir)
{
	UpdaterStorageDiagnostics diagnostics;
	if (!trusted_directory(dir, true, &diagnostics))
		return false;

	std::error_code ec;
	fs::remove_all(dir, ec);
	if (ec) {
		wlog_warn(L"Failed to clean updater run %s: %d %S", dir.c_str(), ec.value(), ec.message().c_str());
		return false;
	}
	return true;
}
