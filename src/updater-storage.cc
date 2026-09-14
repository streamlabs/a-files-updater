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
#include "update-blockers.hpp"

namespace {

const wchar_t *const kUpdaterDirSddl = L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";
const wchar_t *const kRunLockName = L".run-lock";
const wchar_t *const kUpdaterLogName = L"slobs-updater.log";
const wchar_t *const kRunCompleteName = L".update-complete";
constexpr auto kAbandonedRunAge = std::chrono::hours(24);
constexpr auto kRecoveryRunAge = std::chrono::hours(24 * 7);
constexpr int kHolderProbeLimit = 16;

enum class PrepareResult { Ready, Collision, Failed };
enum class ClaimResult { Claimed, Active, Gone, Failed };

void set_failure(UpdaterStorageDiagnostics *diagnostics, const std::wstring &reason, const std::string &category = "UpdaterStorageFailure")
{
	if (diagnostics) {
		diagnostics->failure = reason;
		diagnostics->failure_category = category;
	}
	wlog_warn(L"%s", reason.c_str());
}

void set_ancestor_warning(UpdaterStorageDiagnostics *diagnostics, const fs::path &dir, const TrustReport &trust)
{
	const std::wstring reason = L"Updater storage " + dir.wstring() + L" is reached through " + trust.ancestor.wstring() + L", which " + trust.ancestor_why;
	if (diagnostics && diagnostics->ancestor_warning.empty())
		diagnostics->ancestor_warning = reason;
	wlog_warn(L"%s; continuing in preview mode", reason.c_str());
}

bool updater_acl_is_valid(const fs::path &dir, std::wstring &why)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	PSID owner = nullptr;
	PACL dacl = nullptr;
	const DWORD read = GetNamedSecurityInfoW(dir.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl,
						 nullptr, &descriptor);
	if (read != ERROR_SUCCESS) {
		why = L"has an unreadable updater security descriptor: " + format_hex32(read);
		return false;
	}

	SECURITY_DESCRIPTOR_CONTROL control = 0;
	DWORD revision = 0;
	if (!owner || !IsWellKnownSid(owner, WinBuiltinAdministratorsSid)) {
		why = L"is not owned by Administrators";
	} else if (!GetSecurityDescriptorControl(descriptor, &control, &revision) || (control & SE_DACL_PROTECTED) == 0) {
		why = L"has a DACL that inherits from its parent";
	} else if (!dacl) {
		why = L"has no updater DACL";
	} else {
		bool administrators = false;
		bool system = false;
		const BYTE expected_flags = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;

		for (WORD i = 0; i < dacl->AceCount && why.empty(); i++) {
			ACCESS_ALLOWED_ACE *ace = nullptr;
			if (!GetAce(dacl, i, reinterpret_cast<void **>(&ace))) {
				why = L"has an unreadable updater ACE at index " + format_hex32(i);
				break;
			}
			if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE || ace->Header.AceFlags != expected_flags || ace->Mask != FILE_ALL_ACCESS) {
				why = L"has an unexpected updater ACE at index " + format_hex32(i);
				break;
			}

			PSID grantee = reinterpret_cast<PSID>(&ace->SidStart);
			if (IsWellKnownSid(grantee, WinBuiltinAdministratorsSid) && !administrators) {
				administrators = true;
			} else if (IsWellKnownSid(grantee, WinLocalSystemSid) && !system) {
				system = true;
			} else {
				why = L"has an unexpected updater trustee at ACE index " + format_hex32(i);
			}
		}

		if (why.empty() && (!administrators || !system || dacl->AceCount != 2))
			why = L"does not grant exactly Administrators and SYSTEM inheritable full control";
	}

	LocalFree(descriptor);
	return why.empty();
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

	std::wstring acl_why;
	if (!updater_acl_is_valid(dir, acl_why)) {
		set_failure(diagnostics, L"Refusing updater directory " + dir.wstring() + L": it " + acl_why);
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
		set_failure(diagnostics, L"Failed to build updater directory descriptor: " + format_hex32(GetLastError()));
		return PrepareResult::Failed;
	}

	const bool created = CreateDirectoryW(dir.c_str(), &attributes) != 0;
	const DWORD error = created ? ERROR_SUCCESS : GetLastError();
	LocalFree(attributes.lpSecurityDescriptor);

	if (!created) {
		if (error == ERROR_ALREADY_EXISTS || error == ERROR_FILE_EXISTS)
			return PrepareResult::Collision;
		set_failure(diagnostics, L"Failed to create updater directory " + dir.wstring() + L": " + format_hex32(error));
		return PrepareResult::Failed;
	}

	if (diagnostics)
		diagnostics->created = true;

	if (!trusted_directory(dir, enforce_ancestors, diagnostics)) {
		if (!RemoveDirectoryW(dir.c_str())) {
			wlog_warn(L"Failed to remove rejected updater directory %s: %lu", dir.c_str(), GetLastError());
		} else if (diagnostics) {
			diagnostics->created = false;
		}
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
		set_failure(diagnostics, L"Could not inspect updater directory " + dir.wstring() + L": " + format_hex32(lookup_error));
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

bool prune_leaf(const fs::path &path)
{
	const std::wstring name = path.filename().wstring();
	if (name.size() != 39 || name.rfind(L".prune-", 0) != 0)
		return false;

	for (size_t i = 7; i < name.size(); i++) {
		if (!iswxdigit(name[i]))
			return false;
	}
	return true;
}

/* Not fs::exists: that follows a link, and neither a squatted directory nor a
 * reparse point may read as a finished run. */
bool run_is_complete(const fs::path &run)
{
	const DWORD attributes = GetFileAttributesW((run / kRunCompleteName).c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
		return false;

	return (attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) == 0;
}

bool quarantine_leaf(const fs::path &root, const fs::path &path)
{
	const std::wstring prefix = root.filename().wstring() + L".quarantine-";
	const std::wstring name = path.filename().wstring();
	if (name.size() != prefix.size() + 32 || name.rfind(prefix, 0) != 0)
		return false;

	for (size_t i = prefix.size(); i < name.size(); i++) {
		if (!iswxdigit(name[i]))
			return false;
	}
	return true;
}

bool remove_quarantine_leaf(const fs::path &aside)
{
	/* The quarantined tree is attacker-controlled. Only remove a file, reparse
	 * point, or empty directory; never traverse it while elevated. */
	const DWORD attributes = GetFileAttributesW(aside.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES) {
		const DWORD error = GetLastError();
		if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
			return true;
		return false;
	}

	return (attributes & FILE_ATTRIBUTE_DIRECTORY) ? RemoveDirectoryW(aside.c_str()) != 0 : DeleteFileW(aside.c_str()) != 0;
}

void sweep_updater_root_quarantines(const fs::path &root, UpdaterStorageDiagnostics *diagnostics)
{
	std::error_code iteration_error;
	std::vector<fs::path> candidates;
	for (const fs::directory_entry &entry : fs::directory_iterator(root.parent_path(), fs::directory_options::skip_permission_denied, iteration_error)) {
		if (quarantine_leaf(root, entry.path()))
			candidates.push_back(entry.path());
	}
	if (iteration_error && diagnostics && diagnostics->cleanup_warning.empty()) {
		diagnostics->cleanup_warning =
			L"Failed to enumerate updater root quarantines beside " + root.wstring() + L": " + format_hex32(iteration_error.value());
		wlog_warn(L"%s", diagnostics->cleanup_warning.c_str());
	}

	for (const fs::path &candidate : candidates) {
		if (remove_quarantine_leaf(candidate))
			wlog_info(L"Removed updater root quarantine %s", candidate.c_str());
	}
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
			if (remove_quarantine_leaf(aside)) {
				wlog_warn(L"Moved and removed untrusted updater root %s", root.c_str());
			} else if (MoveFileExW(aside.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT)) {
				wlog_warn(L"Moved untrusted updater root %s to %s; it is queued for deletion at reboot", root.c_str(), aside.c_str());
			} else {
				wlog_warn(L"Could not queue updater root quarantine %s for deletion: %s", aside.c_str(), format_hex32(GetLastError()).c_str());
			}
			return true;
		}

		const DWORD error = GetLastError();
		if (error != ERROR_ALREADY_EXISTS && error != ERROR_FILE_EXISTS) {
			const bool blocked = error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION;
			set_failure(diagnostics, L"Could not move untrusted updater root " + root.wstring() + L" aside: " + format_hex32(error),
				    blocked ? "UpdaterStorageQuarantineBlocked" : "UpdaterStorageFailure");
			return false;
		}
	}

	set_failure(diagnostics, L"Could not find a unique updater root quarantine name");
	return false;
}

ClaimResult claim_updater_run(const fs::path &run, fs::path &claimed, std::wstring &why)
{
	for (int attempt = 0; attempt < 8; attempt++) {
		const std::wstring suffix = security_random_hex(4);
		if (suffix.empty()) {
			why = L"Could not name a claimed updater run: no randomness available";
			return ClaimResult::Failed;
		}

		claimed = run.parent_path() / (L".prune-" + suffix);
		if (MoveFileExW(run.c_str(), claimed.c_str(), 0))
			return ClaimResult::Claimed;

		const DWORD move_error = GetLastError();
		if (move_error == ERROR_FILE_NOT_FOUND || move_error == ERROR_PATH_NOT_FOUND)
			return ClaimResult::Gone;
		if (move_error == ERROR_ACCESS_DENIED || move_error == ERROR_SHARING_VIOLATION || move_error == ERROR_LOCK_VIOLATION)
			return ClaimResult::Active;
		if (move_error != ERROR_ALREADY_EXISTS && move_error != ERROR_FILE_EXISTS) {
			why = L"Could not rename claimed updater run " + run.wstring() + L": " + format_hex32(move_error);
			return ClaimResult::Failed;
		}
	}

	why = L"Could not find a unique claimed updater run name";
	return ClaimResult::Failed;
}

/* Failure path only: RmGetList is far too slow to run on a cleanup that worked.
 * A directory is probed through its first few files, since the Restart Manager
 * registers files rather than directories. */
std::vector<blocker_info> child_holders(const fs::path &child, bool is_directory)
{
	blockers_map_t blockers;

	if (!is_directory) {
		fs::path file = child;
		get_blockers_list(file, blockers);
		return get_blocker_details(blockers);
	}

	std::error_code ec;
	int probed = 0;
	fs::recursive_directory_iterator iter(child, fs::directory_options::skip_permission_denied, ec);
	const fs::recursive_directory_iterator end;
	while (!ec && iter != end && probed < kHolderProbeLimit) {
		std::error_code type_error;
		if (iter->is_regular_file(type_error) && !type_error) {
			fs::path file = iter->path();
			get_blockers_list(file, blockers);
			probed++;
		}
		iter.increment(ec);
	}

	return get_blocker_details(blockers);
}

std::wstring describe_holders(const std::vector<blocker_info> &holders)
{
	std::wstring text;
	for (const blocker_info &holder : holders) {
		if (!text.empty())
			text += L", ";
		text += holder.app_name + L" (" + std::to_wstring(holder.pid) + L")";
	}
	return text;
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
	if (prune_leaf(dir)) {
		set_failure(diagnostics, L"Refusing reserved updater prune directory " + dir.wstring());
		return false;
	}
	return prepare_directory(dir, allow_existing, true, diagnostics) == PrepareResult::Ready;
}

bool acquire_updater_run_lock(const fs::path &dir, void **lock_handle, UpdaterStorageDiagnostics *diagnostics)
{
	if (!lock_handle) {
		set_failure(diagnostics, L"Could not retain an updater run lock handle");
		return false;
	}
	*lock_handle = nullptr;

	const fs::path lock_path = dir / kRunLockName;
	/* Zero sharing makes the atomic stale-run rename fail while this updater is
	 * active anywhere below the run directory. */
	HANDLE lock = CreateFileW(lock_path.c_str(), GENERIC_READ, 0, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (lock == INVALID_HANDLE_VALUE) {
		set_failure(diagnostics, L"Could not acquire updater run lock " + lock_path.wstring() + L": " + format_hex32(GetLastError()));
		return false;
	}
	const bool lock_created = GetLastError() != ERROR_ALREADY_EXISTS;

	FILE_ATTRIBUTE_TAG_INFO tag = {};
	const bool readable = GetFileInformationByHandleEx(lock, FileAttributeTagInfo, &tag, sizeof(tag)) != 0;
	const DWORD error = readable ? ERROR_SUCCESS : GetLastError();
	if (!readable || (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		CloseHandle(lock);
		if (lock_created)
			DeleteFileW(lock_path.c_str());
		set_failure(diagnostics,
			    L"Refusing unexpected updater run lock " + lock_path.wstring() + (error == ERROR_SUCCESS ? L"" : L": " + format_hex32(error)));
		return false;
	}

	*lock_handle = lock;
	return true;
}

void release_updater_run_lock(void *lock_handle)
{
	if (lock_handle && lock_handle != INVALID_HANDLE_VALUE)
		CloseHandle(lock_handle);
}

bool remove_updater_run_lock(const fs::path &dir, UpdaterStorageDiagnostics *diagnostics)
{
	const fs::path lock_path = dir / kRunLockName;
	if (DeleteFileW(lock_path.c_str()))
		return true;

	const DWORD error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		return true;
	if (error == ERROR_SHARING_VIOLATION || error == ERROR_LOCK_VIOLATION) {
		wlog_info(L"Updater run lock %s is now held by another updater", lock_path.c_str());
		return true;
	}

	set_failure(diagnostics, L"Could not remove updater run lock " + lock_path.wstring() + L": " + format_hex32(error));
	return false;
}

/* Never reports through UpdaterStorageDiagnostics: the update has already
 * succeeded by the time this runs, and a missing marker only costs retention. */
bool mark_updater_run_complete(const fs::path &dir)
{
	const fs::path marker = dir / kRunCompleteName;
	HANDLE handle = CreateFileW(marker.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_HIDDEN | FILE_FLAG_OPEN_REPARSE_POINT, nullptr);
	if (handle == INVALID_HANDLE_VALUE) {
		const std::wstring reason = L"Could not write updater run marker " + marker.wstring() + L": " + format_hex32(GetLastError());
		wlog_warn(L"%s", reason.c_str());
		return false;
	}

	FILE_ATTRIBUTE_TAG_INFO tag = {};
	const bool readable = GetFileInformationByHandleEx(handle, FileAttributeTagInfo, &tag, sizeof(tag)) != 0;
	const DWORD error = readable ? ERROR_SUCCESS : GetLastError();
	if (!readable || (tag.FileAttributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT)) != 0) {
		CloseHandle(handle);
		const std::wstring reason =
			L"Refusing unexpected updater run marker " + marker.wstring() + (error == ERROR_SUCCESS ? L"" : L": " + format_hex32(error));
		wlog_warn(L"%s", reason.c_str());
		return false;
	}

	CloseHandle(handle);
	return true;
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
		if (diagnostics)
			diagnostics->root_replaced_reason = check.failure;
	}

	const PrepareResult created = prepare_directory(root, false, false, diagnostics);
	if (created == PrepareResult::Collision) {
		set_failure(diagnostics, L"Updater root " + root.wstring() + L" was recreated while it was being secured");
		return false;
	}
	return created == PrepareResult::Ready;
}

void prune_updater_runs(const fs::path &root, bool enforce_ancestors, UpdaterStorageDiagnostics *diagnostics)
{
	std::error_code iteration_error;
	const auto now = fs::file_time_type::clock::now();
	std::vector<fs::path> stale_runs;
	std::vector<fs::path> claimed_runs;
	for (const fs::directory_entry &entry : fs::directory_iterator(root, fs::directory_options::skip_permission_denied, iteration_error)) {
		std::error_code type_error;
		if (!entry.is_directory(type_error) || type_error)
			continue;
		type_error.clear();
		if (entry.is_symlink(type_error) || type_error)
			continue;
		const bool previously_claimed = prune_leaf(entry.path());
		if (!previously_claimed && !run_leaf(entry.path()))
			continue;

		UpdaterStorageDiagnostics validation;
		if (!trusted_directory(entry.path(), enforce_ancestors, &validation)) {
			if (diagnostics && diagnostics->cleanup_warning.empty())
				diagnostics->cleanup_warning = validation.failure;
			continue;
		}
		if (previously_claimed) {
			claimed_runs.push_back(entry.path());
			continue;
		}

		std::error_code modified_error;
		const auto modified = entry.last_write_time(modified_error);
		if (modified_error)
			continue;

		std::error_code backup_error;
		const bool has_backup = fs::exists(entry.path() / L"old-files", backup_error);
		if (backup_error)
			continue;

		/* A backup is only a rollback source until the run that made it
		 * finishes; after that it is worth no more than no backup at all. */
		const bool completed = run_is_complete(entry.path());
		const bool rollback_source = has_backup && !completed;

		const auto retention = rollback_source ? kRecoveryRunAge : kAbandonedRunAge;
		if (now - modified < retention)
			continue;

		stale_runs.push_back(entry.path());
	}
	if (iteration_error && diagnostics && diagnostics->cleanup_warning.empty()) {
		diagnostics->cleanup_warning = L"Failed to enumerate updater runs below " + root.wstring() + L": " + format_hex32(iteration_error.value());
		wlog_warn(L"%s", diagnostics->cleanup_warning.c_str());
	}

	for (const fs::path &run : claimed_runs) {
		UpdaterStorageDiagnostics cleanup;
		if (cleanup_updater_temp_dir(run, enforce_ancestors, &cleanup)) {
			wlog_info(L"Pruned previously claimed updater run %s", run.c_str());
		} else if (diagnostics && diagnostics->cleanup_warning.empty()) {
			diagnostics->cleanup_warning = cleanup.failure;
		}
	}

	for (const fs::path &run : stale_runs) {
		fs::path claimed;
		std::wstring claim_why;
		const ClaimResult claim = claim_updater_run(run, claimed, claim_why);
		if (claim == ClaimResult::Active) {
			wlog_info(L"Keeping active updater run %s", run.c_str());
			continue;
		}
		if (claim == ClaimResult::Gone)
			continue;
		if (claim == ClaimResult::Failed) {
			if (diagnostics && diagnostics->cleanup_warning.empty())
				diagnostics->cleanup_warning = claim_why;
			wlog_warn(L"%s", claim_why.c_str());
			continue;
		}

		UpdaterStorageDiagnostics cleanup;
		if (cleanup_updater_temp_dir(claimed, enforce_ancestors, &cleanup)) {
			wlog_info(L"Pruned abandoned updater run %s", run.c_str());
		} else if (diagnostics && diagnostics->cleanup_warning.empty()) {
			diagnostics->cleanup_warning = cleanup.failure;
		}
	}

	sweep_updater_root_quarantines(root, diagnostics);
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

	prune_updater_runs(root, false, diagnostics);

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
			if (diagnostics) {
				diagnostics->failure = run_diagnostics.failure;
				diagnostics->failure_category = run_diagnostics.failure_category;
			}
			return {};
		}
	}

	set_failure(diagnostics, L"Failed to create a unique updater directory after eight name collisions");
	return {};
}

bool cleanup_updater_temp_dir(const fs::path &dir, bool enforce_ancestors, UpdaterStorageDiagnostics *diagnostics)
{
	const auto missing = [&dir]() {
		if (GetFileAttributesW(dir.c_str()) != INVALID_FILE_ATTRIBUTES)
			return false;
		const DWORD error = GetLastError();
		return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
	};

	if (missing())
		return true;
	if (!trusted_directory(dir, enforce_ancestors, diagnostics)) {
		/* Another pruner can remove the same stale run between enumeration and
		 * this validation. A vanished path is already the desired result. */
		if (missing())
			return true;
		return false;
	}

	const fs::path log = dir / kUpdaterLogName;
	const fs::path complete = dir / kRunCompleteName;
	std::vector<fs::path> children;
	std::error_code ec;
	fs::directory_iterator iter(dir, ec);
	const fs::directory_iterator end;
	while (!ec && iter != end) {
		/* The marker outlives a failed cleanup on purpose: removing it while
		 * the backup survives would put the run back on the seven-day rule. */
		const fs::directory_entry &entry = *iter;
		const fs::path name = entry.path().filename();
		if (name != kUpdaterLogName && name != kRunCompleteName)
			children.push_back(entry.path());
		iter.increment(ec);
	}
	if (ec) {
		if (missing())
			return true;
		set_failure(diagnostics, L"Failed to enumerate updater run " + dir.wstring() + L": " + format_hex32(ec.value()));
		return false;
	}

	fs::path stuck;
	bool stuck_is_directory = false;
	int stuck_error = 0;
	size_t stuck_count = 0;
	for (const fs::path &child : children) {
		ec.clear();
		fs::remove_all(child, ec);
		if (!ec)
			continue;

		/* Keep going: one held child must not strand its siblings, or a stuck
		 * new-files leaves the backup behind with it. */
		if (stuck_count++ == 0) {
			std::error_code type_error;
			stuck = child;
			stuck_is_directory = fs::is_directory(child, type_error) && !type_error;
			stuck_error = ec.value();
		}
	}
	if (stuck_count != 0) {
		std::wstring reason = L"Failed to clean updater run " + dir.wstring() + L": " + (stuck_is_directory ? L"directory " : L"file ") +
				      stuck.wstring() + L" could not be removed: " + format_hex32(stuck_error);
		if (stuck_count > 1)
			reason += L" (" + std::to_wstring(stuck_count) + L" children failed)";

		const std::vector<blocker_info> holders = child_holders(stuck, stuck_is_directory);
		log_blockers("Updater run child is held open by", holders);
		if (!holders.empty())
			reason += L"; held by " + describe_holders(holders);
		if (GetFileAttributesW(log.c_str()) != INVALID_FILE_ATTRIBUTES)
			reason += L"; updater log retained at " + log.wstring();
		set_failure(diagnostics, reason);
		return false;
	}

	if (RemoveDirectoryW(dir.c_str()))
		return true;

	DWORD error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		return true;
	if (error != ERROR_DIR_NOT_EMPTY) {
		std::wstring reason = L"Failed to remove cleaned updater run " + dir.wstring() + L": " + format_hex32(error);
		if (GetFileAttributesW(log.c_str()) != INVALID_FILE_ATTRIBUTES)
			reason += L"; updater log retained at " + log.wstring();
		set_failure(diagnostics, reason);
		return false;
	}

	DeleteFileW(complete.c_str());

	if (!DeleteFileW(log.c_str())) {
		error = GetLastError();
		if (error != ERROR_FILE_NOT_FOUND && error != ERROR_PATH_NOT_FOUND) {
			set_failure(diagnostics, L"Failed to remove updater log " + log.wstring() + L": " + format_hex32(error) +
							 L"; updater log retained at " + log.wstring());
			return false;
		}
	}

	if (RemoveDirectoryW(dir.c_str()))
		return true;

	error = GetLastError();
	if (error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND)
		return true;
	std::wstring reason = L"Failed to remove cleaned updater run " + dir.wstring() + L": " + format_hex32(error);
	if (GetFileAttributesW(log.c_str()) != INVALID_FILE_ATTRIBUTES)
		reason += L"; updater log retained at " + log.wstring();
	else
		reason += L"; updater log was removed before final directory cleanup";
	set_failure(diagnostics, reason);
	return false;
}
