#include "hook-permissions.hpp"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstdint>
#include <string>
#include <system_error>
#include <vector>

#include "logger/log.h"

namespace {

/* SYSTEM and Administrators get full control, everyone else read and execute.
 * PAI blocks inheritance, which is what stops the CREATOR OWNER entry on
 * %ProgramData% handing full control to whoever creates the directory first.
 * AC and S-1-15-2-2 (ALL [RESTRICTED] APPLICATION PACKAGES) are what let an
 * AppContainer capture target load the hook. */
const wchar_t *const kHookDirSddl = L"O:BA"
				    L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;AC)(A;OICI;FRFX;;;S-1-15-2-2)";

const wchar_t *const kAdministratorsSid = L"S-1-5-32-544";

const wchar_t *const kImplicitLayers = L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers";

/* The hook and the vulkan manifest that points at it move together. */
struct HookPair {
	const wchar_t *dll;
	const wchar_t *manifest;
};

const HookPair kHookPairs[] = {
	{L"graphics-hook32.dll", L"obs-vulkan32.json"},
	{L"graphics-hook64.dll", L"obs-vulkan64.json"},
};

const wchar_t *const kTrustedSids[] = {
	L"S-1-5-18",                                                       /* LOCAL SYSTEM */
	kAdministratorsSid,                                                /* BUILTIN\Administrators */
	L"S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464", /* TrustedInstaller */
};

constexpr DWORD kWriteAccess = FILE_WRITE_DATA | FILE_APPEND_DATA | FILE_WRITE_EA | FILE_WRITE_ATTRIBUTES | FILE_DELETE_CHILD | DELETE | WRITE_DAC |
			       WRITE_OWNER | GENERIC_WRITE | GENERIC_ALL;

/* Above the object itself, only rights that let someone swap the child out
 * matter. Creating entries alongside it does not, and must not be checked for:
 * every drive root grants exactly that to Authenticated Users. */
constexpr DWORD kAncestorWriteAccess = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

enum class InstallResult {
	Failed,
	Installed,
	/* Staged: the bytes on disk are still the old ones until reboot. */
	Pending,
};

/* Declared up front so the contracts sit in one place. Each of these has a way
 * of looking over-cautious at its call site; the notes are what goes wrong if
 * it is simplified. */

bool sid_is_trusted(PSID sid);

/* Owned by an administrative account, with nobody else holding write_mask.
 * Mirrors hook_object_is_trusted() in obs-studio's shared/obs-hook-config, kept
 * in step by hand since the two repositories share no header. */
bool object_is_trusted(const fs::path &path, DWORD write_mask);

bool path_is_trusted(const fs::path &path);

/* path_is_trusted plus every directory above it. Locking a file down means
 * nothing if a standard user can rename one of its parents and present a
 * different tree under the same path. */
bool path_chain_is_trusted(const fs::path &path);

/* PE file version as one comparable value, 0 when it cannot be read. */
uint64_t file_version(const fs::path &path);

bool enable_privilege(const wchar_t *name);

fs::path programdata_hook_dir();

/* Renames dir aside rather than repairing it where it stands: an ACL change
 * does not revoke handles opened before it, so whoever created dir could rename
 * the hardened one away afterwards and put their own back at the same path.
 * Deletes only the names we own, since walking the tree would follow whatever
 * junctions were left in it. */
bool quarantine_hook_dir(const fs::path &dir);

/* Creates dir with the descriptor already attached, so it is never briefly
 * writable. ERROR_ALREADY_EXISTS is a failure and not a success: it means
 * somebody won the name after quarantine, and hardening their directory in
 * place would leave the handles they already opened alive. */
bool create_hook_dir(const fs::path &dir);

/* Ownership first and separately from the DACL: a directory left behind by an
 * earlier release can be owned by a standard user, and only the owner may
 * rewrite the DACL. Both have to land - either alone leaves them in control. */
bool apply_hook_dir_security(const fs::path &dir);

/* Only ever for a file we just wrote. On one we merely found, this would hand
 * somebody else's file to the administrators group and make it pass the
 * consumer's trust check. */
bool reset_file_acl(const fs::path &file);

void delete_layer_value(HKEY root, DWORD wow_flag, const std::wstring &value);

/* An implicit layer entry outlives the directory it points at, and the loader
 * hands that directory to every vulkan process on the machine. */
void remove_vulkan_layer_registry();

/* Deletes dst, then copies without overwrite. An entry planted at dst while the
 * directory was writable may be a hard link, and writing through it would put
 * our bytes into the link target - an arbitrary write, since we run elevated.
 *
 * TODO: Authenticode-verify src, and where publish_hooks() keeps an existing
 * file rather than replacing it. Permissions establish who could have written a
 * file, not what is in it. The open question is which publisher to accept: the
 * hooks are signed as "OBS Project, LLC" rather than as us. */
bool copy_over(const fs::path &src, const fs::path &dst);

/* copy_over, falling back to staging beside dst and swapping on reboot when the
 * target is locked - the vulkan layer pulls the hook into anything that
 * renders. The swap stays link-safe: MoveFileEx replaces the directory entry
 * rather than writing through it. */
InstallResult install_hook_file(const fs::path &src, const fs::path &dst);

/* Where the app keeps its copy of the hook, or empty when app_dir does not lead
 * anywhere usable. */
fs::path hook_source_dir(const fs::path &app_dir);

/* Best effort, and deliberately separate from the permission work above it:
 * this is the only part that knows the app's layout, and the only part allowed
 * to be skipped. pair_was_trusted[] must be the state read before the directory
 * was hardened. */
void publish_hooks(const fs::path &dir, const fs::path &source, const bool *pair_was_trusted);

bool sid_is_trusted(PSID sid)
{
	if (!sid || !IsValidSid(sid))
		return false;

	for (const wchar_t *candidate : kTrustedSids) {
		PSID compare = nullptr;
		BOOL equal = false;

		if (ConvertStringSidToSidW(candidate, &compare)) {
			equal = EqualSid(sid, compare);
			LocalFree(compare);
		}
		if (equal)
			return true;
	}

	return false;
}

bool object_is_trusted(const fs::path &path, DWORD write_mask)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_REPARSE_POINT))
		return false;

	PSECURITY_DESCRIPTOR descriptor = nullptr;
	PSID owner = nullptr;
	PACL dacl = nullptr;
	bool trusted = false;

	if (GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl, nullptr,
				  &descriptor) != ERROR_SUCCESS) {
		return false;
	}

	/* the owner can always rewrite the DACL, and a NULL DACL grants
	 * everything to everyone */
	if (sid_is_trusted(owner) && dacl) {
		trusted = true;

		for (WORD i = 0; i < dacl->AceCount; i++) {
			ACCESS_ALLOWED_ACE *ace = nullptr;

			if (!GetAce(dacl, i, reinterpret_cast<void **>(&ace))) {
				trusted = false;
				break;
			}
			if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
				continue;
			if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
				trusted = false;
				break;
			}
			/* inherit-only, such as the CREATOR OWNER entry on
			 * %ProgramData%, grants nothing on this object */
			if (ace->Header.AceFlags & INHERIT_ONLY_ACE)
				continue;
			if ((ace->Mask & write_mask) == 0)
				continue;
			if (!sid_is_trusted(reinterpret_cast<PSID>(&ace->SidStart))) {
				trusted = false;
				break;
			}
		}
	}

	LocalFree(descriptor);
	return trusted;
}

bool path_is_trusted(const fs::path &path)
{
	return object_is_trusted(path, kWriteAccess);
}

bool path_chain_is_trusted(const fs::path &path)
{
	if (!path_is_trusted(path))
		return false;

	for (fs::path current = path.parent_path();; current = current.parent_path()) {
		if (!object_is_trusted(current, kAncestorWriteAccess))
			return false;

		/* the root is its own parent, so stop once we reach it */
		if (!current.has_relative_path())
			return true;
	}
}

uint64_t file_version(const fs::path &path)
{
	DWORD handle = 0;
	const DWORD size = GetFileVersionInfoSizeW(path.c_str(), &handle);
	if (size == 0)
		return 0;

	std::vector<BYTE> buffer(size);
	if (!GetFileVersionInfoW(path.c_str(), 0, size, buffer.data()))
		return 0;

	VS_FIXEDFILEINFO *info = nullptr;
	UINT info_size = 0;
	if (!VerQueryValueW(buffer.data(), L"\\", reinterpret_cast<void **>(&info), &info_size) || !info)
		return 0;

	return (static_cast<uint64_t>(info->dwFileVersionMS) << 32) | info->dwFileVersionLS;
}

bool enable_privilege(const wchar_t *name)
{
	HANDLE token = nullptr;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &token))
		return false;

	TOKEN_PRIVILEGES privileges = {};
	bool success = false;

	if (LookupPrivilegeValueW(nullptr, name, &privileges.Privileges[0].Luid)) {
		privileges.PrivilegeCount = 1;
		privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
		success = AdjustTokenPrivileges(token, false, &privileges, sizeof(privileges), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
	}

	CloseHandle(token);
	return success;
}

fs::path programdata_hook_dir()
{
	wchar_t path[MAX_PATH] = {};
	if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path)))
		return {};

	return fs::path(path) / L"obs-studio-hook";
}

bool quarantine_hook_dir(const fs::path &dir)
{
	fs::path aside;
	bool moved = false;

	for (wchar_t suffix = L'0'; suffix <= L'9' && !moved; suffix++) {
		aside = dir;
		aside += L".quarantine";
		aside += suffix;
		moved = MoveFileExW(dir.c_str(), aside.c_str(), 0) != 0;
	}

	if (!moved) {
		wlog_warn(L"Could not move %s aside: %lu", dir.c_str(), GetLastError());
		return false;
	}

	for (const HookPair &pair : kHookPairs) {
		for (const wchar_t *name : {pair.dll, pair.manifest}) {
			fs::path leftover = aside / name;
			MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
			leftover += L".new";
			MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
		}
	}
	MoveFileExW(aside.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);

	wlog_info(L"Moved the untrusted hook directory to %s; it goes away on the next reboot", aside.c_str());
	return true;
}

bool create_hook_dir(const fs::path &dir)
{
	SECURITY_ATTRIBUTES attributes = {sizeof(attributes), nullptr, false};

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kHookDirSddl, SDDL_REVISION_1, &attributes.lpSecurityDescriptor, nullptr)) {
		log_warn("Failed to build hook directory descriptor: %lu", GetLastError());
		return false;
	}

	const bool success = CreateDirectoryW(dir.c_str(), &attributes) != 0;
	if (!success) {
		const DWORD error = GetLastError();
		if (error == ERROR_ALREADY_EXISTS)
			log_warn("The hook directory was recreated while it was being repaired; refusing it");
		else
			log_warn("Failed to create hook directory: %lu", error);
	}

	LocalFree(attributes.lpSecurityDescriptor);
	return success;
}

bool apply_hook_dir_security(const fs::path &dir)
{
	PSECURITY_DESCRIPTOR descriptor = nullptr;
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kHookDirSddl, SDDL_REVISION_1, &descriptor, nullptr)) {
		log_warn("Failed to build hook directory descriptor: %lu", GetLastError());
		return false;
	}

	PSID owner = nullptr;
	PACL dacl = nullptr;
	BOOL dacl_present = false;
	BOOL defaulted = false;
	bool success = false;
	std::wstring path = dir.wstring();

	if (GetSecurityDescriptorOwner(descriptor, &owner, &defaulted) && GetSecurityDescriptorDacl(descriptor, &dacl_present, &dacl, &defaulted) &&
	    dacl_present) {
		DWORD result = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, owner, nullptr, nullptr, nullptr);
		if (result != ERROR_SUCCESS) {
			log_warn("Failed to take ownership of the hook directory: %lu", result);
		} else {
			result = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr,
						       nullptr, dacl, nullptr);
			if (result == ERROR_SUCCESS)
				success = true;
			else
				log_warn("Failed to secure the hook directory: %lu", result);
		}
	}

	LocalFree(descriptor);
	return success;
}

bool reset_file_acl(const fs::path &file)
{
	ACL empty_dacl;
	if (!InitializeAcl(&empty_dacl, sizeof(empty_dacl), ACL_REVISION))
		return false;

	PSID owner = nullptr;
	if (!ConvertStringSidToSidW(kAdministratorsSid, &owner))
		return false;

	std::wstring path = file.wstring();
	DWORD result = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
					     OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, owner, nullptr,
					     &empty_dacl, nullptr);
	if (result != ERROR_SUCCESS)
		wlog_warn(L"Failed to reset permissions on %s: %lu", path.c_str(), result);

	LocalFree(owner);
	return result == ERROR_SUCCESS;
}

void delete_layer_value(HKEY root, DWORD wow_flag, const std::wstring &value)
{
	HKEY key = nullptr;
	if (RegOpenKeyExW(root, kImplicitLayers, 0, KEY_WRITE | wow_flag, &key) != ERROR_SUCCESS)
		return;

	RegDeleteValueW(key, value.c_str());
	RegCloseKey(key);
}

void remove_vulkan_layer_registry()
{
	const fs::path dir = programdata_hook_dir();

	for (const HookPair &pair : kHookPairs) {
		const std::wstring value = (dir / pair.manifest).wstring();

		for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
			delete_layer_value(root, KEY_WOW64_64KEY, value);
			delete_layer_value(root, KEY_WOW64_32KEY, value);
		}
	}
}

bool copy_over(const fs::path &src, const fs::path &dst)
{
	const DWORD attributes = GetFileAttributesW(dst.c_str());

	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (attributes & FILE_ATTRIBUTE_READONLY)
			SetFileAttributesW(dst.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY));

		if (!DeleteFileW(dst.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND)
			return false;
	}

	return CopyFileW(src.c_str(), dst.c_str(), true);
}

InstallResult install_hook_file(const fs::path &src, const fs::path &dst)
{
	if (copy_over(src, dst))
		return InstallResult::Installed;

	const DWORD copy_error = GetLastError();

	fs::path staged = dst;
	staged += L".new";

	if (!copy_over(src, staged)) {
		wlog_warn(L"Failed to install %s: %lu, and staging it failed: %lu", dst.c_str(), copy_error, GetLastError());
		return InstallResult::Failed;
	}

	reset_file_acl(staged);

	if (!MoveFileExW(staged.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)) {
		wlog_warn(L"Failed to schedule replacement of %s: %lu", dst.c_str(), GetLastError());
		DeleteFileW(staged.c_str());
		return InstallResult::Failed;
	}

	wlog_info(L"%s is in use, replacement scheduled for the next reboot", dst.c_str());
	return InstallResult::Pending;
}

fs::path hook_source_dir(const fs::path &app_dir)
{
	std::error_code ec;

	if (app_dir.empty())
		return {};

	const fs::path source =
		app_dir / L"resources" / L"app.asar.unpacked" / L"node_modules" / L"obs-studio-node" / L"data" / L"obs-plugins" / L"win-capture";

	if (!fs::is_directory(source, ec)) {
		wlog_info(L"No hook payload at %s; leaving the files to the app", source.c_str());
		return {};
	}

	/* --app-dir comes off our own command line, and the user picks the
	 * install directory at setup time - it is not necessarily %ProgramFiles%. */
	if (!path_chain_is_trusted(source)) {
		wlog_warn(L"Hook payload %s is modifiable by non-administrators; not publishing it", source.c_str());
		return {};
	}

	return source;
}

void publish_hooks(const fs::path &dir, const fs::path &source, const bool *pair_was_trusted)
{
	std::error_code ec;

	for (size_t i = 0; i < std::size(kHookPairs); i++) {
		const fs::path src_dll = source / kHookPairs[i].dll;
		const fs::path src_manifest = source / kHookPairs[i].manifest;
		const fs::path dst_dll = dir / kHookPairs[i].dll;
		const fs::path dst_manifest = dir / kHookPairs[i].manifest;

		if (!fs::exists(src_dll, ec) || !fs::exists(src_manifest, ec)) {
			wlog_warn(L"Hook payload %s is missing; cannot publish %s", src_dll.c_str(), dst_dll.c_str());
			continue;
		}

		/* A sound directory does not make them sound: either can carry
		 * entries of its own. */
		if (!path_is_trusted(src_dll) || !path_is_trusted(src_manifest)) {
			wlog_warn(L"Hook payload %s is modifiable by non-administrators; not publishing it", src_dll.c_str());
			continue;
		}

		/* Newest wins, since the directory is shared with every other OBS
		 * derived application on the machine. Gated on pair_was_trusted:
		 * otherwise the version resource says whatever whoever wrote the
		 * file wanted it to say. */
		if (pair_was_trusted[i] && file_version(dst_dll) >= file_version(src_dll) && file_version(dst_dll) != 0) {
			wlog_info(L"Leaving %s in place; it is at least as new as ours", dst_dll.c_str());
			continue;
		}

		/* reset_file_acl only for a file we actually wrote; see there. */
		if (install_hook_file(src_manifest, dst_manifest) == InstallResult::Installed)
			reset_file_acl(dst_manifest);

		if (install_hook_file(src_dll, dst_dll) == InstallResult::Installed)
			reset_file_acl(dst_dll);
	}
}

} // namespace

void repair_hook_directory(const fs::path &app_dir)
{
	const fs::path dir = programdata_hook_dir();
	if (dir.empty()) {
		log_warn("Could not resolve the hook directory, skipping permission repair");
		return;
	}

	/* non-fatal; logged only because it explains a later ownership failure */
	if (!enable_privilege(L"SeTakeOwnershipPrivilege"))
		log_warn("Could not enable SeTakeOwnershipPrivilege: %lu", GetLastError());
	if (!enable_privilege(L"SeRestorePrivilege"))
		log_warn("Could not enable SeRestorePrivilege: %lu", GetLastError());

	/* Read before we touch anything. Hardening propagates to children, so
	 * afterwards these would come back true whatever the starting state. */
	const bool dir_was_trusted = path_chain_is_trusted(dir);
	bool pair_was_trusted[std::size(kHookPairs)] = {};

	for (size_t i = 0; i < std::size(kHookPairs); i++)
		pair_was_trusted[i] = dir_was_trusted && path_is_trusted(dir / kHookPairs[i].dll) && path_is_trusted(dir / kHookPairs[i].manifest);

	/* RemoveDirectoryW unlinks a junction and leaves its target alone; every
	 * step below would otherwise operate on that target. */
	std::error_code ec;
	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		if (!RemoveDirectoryW(dir.c_str())) {
			wlog_warn(L"Hook directory %s is a reparse point and could not be unlinked: %lu", dir.c_str(), GetLastError());
			remove_vulkan_layer_registry();
			return;
		}
	}

	if (!dir_was_trusted && fs::exists(dir, ec) && !quarantine_hook_dir(dir)) {
		remove_vulkan_layer_registry();
		return;
	}

	/* A trusted directory is left as it is, contents and all. Anything else
	 * has to be one we created, with the descriptor already attached. */
	if ((!dir_was_trusted && !create_hook_dir(dir)) || !apply_hook_dir_security(dir)) {
		remove_vulkan_layer_registry();
		return;
	}

	/* Permissions are settled. Nothing below this line may abort the repair:
	 * the directory is already locked down, and the worst case from here is
	 * that we leave the vulkan layer unregistered for the app to sort out. */

	/* Anything we cannot vouch for has to go. Deleting is the only option -
	 * resetting the ACL instead would relabel somebody else's file as
	 * administrator-installed, which is exactly what the app reads to decide
	 * what it will inject into other processes. */
	for (const HookPair &pair : kHookPairs) {
		for (const wchar_t *name : {pair.dll, pair.manifest}) {
			const fs::path file = dir / name;

			if (!fs::exists(file, ec) || path_is_trusted(file))
				continue;

			if (DeleteFileW(file.c_str()))
				wlog_warn(L"Deleted %s: it was modifiable by non-administrators", file.c_str());
			else
				wlog_warn(L"Could not delete untrusted %s: %lu", file.c_str(), GetLastError());
		}
	}

	const fs::path source = hook_source_dir(app_dir);
	if (!source.empty())
		publish_hooks(dir, source, pair_was_trusted);

	bool complete = path_chain_is_trusted(dir);
	for (const HookPair &pair : kHookPairs)
		complete = complete && path_is_trusted(dir / pair.dll) && path_is_trusted(dir / pair.manifest);

	if (!complete) {
		/* The directory is sound but does not hold a full set of hooks we
		 * would stand behind, and the loader hands it to every vulkan
		 * process on the machine. The app re-registers the layer on its
		 * next elevated run, once it has put the files back. */
		remove_vulkan_layer_registry();
		log_info("Hook directory secured; the vulkan layer was unregistered until the hook is reinstalled");
		return;
	}

	log_info("Hook directory permissions verified");
}
