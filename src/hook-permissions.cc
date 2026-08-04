#include "hook-permissions.hpp"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <string>
#include <system_error>

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

/* Everything the directory is allowed to hold. Names only - this step never
 * writes any of them, it only decides whether what is there can stay. */
const wchar_t *const kHookFiles[] = {
	L"graphics-hook32.dll",
	L"graphics-hook64.dll",
	L"obs-vulkan32.json",
	L"obs-vulkan64.json",
};

const wchar_t *const kVulkanManifests[] = {L"obs-vulkan32.json", L"obs-vulkan64.json"};

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

void delete_layer_value(HKEY root, DWORD wow_flag, const std::wstring &value);

/* An implicit layer entry outlives the directory it points at, and the loader
 * hands that directory to every vulkan process on the machine. */
void remove_vulkan_layer_registry();

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

	for (const wchar_t *name : kHookFiles) {
		fs::path leftover = aside / name;
		MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
		leftover += L".new";
		MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
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

	for (const wchar_t *manifest : kVulkanManifests) {
		const std::wstring value = (dir / manifest).wstring();

		for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
			delete_layer_value(root, KEY_WOW64_64KEY, value);
			delete_layer_value(root, KEY_WOW64_32KEY, value);
		}
	}
}

} // namespace

void repair_hook_directory()
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
	 * afterwards this would come back true whatever the starting state. */
	const bool dir_was_trusted = path_chain_is_trusted(dir);

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

	/* The files are not ours to install - that is the app's job, and it has
	 * the version arbitration to decide whose hook wins. All we can do is
	 * refuse to leave one behind that we cannot vouch for. Deleting is the
	 * only option: resetting its ACL instead would relabel somebody else's
	 * file as administrator-installed, which is exactly what the app reads
	 * to decide what it will inject into other processes. */
	bool complete = true;
	for (const wchar_t *name : kHookFiles) {
		const fs::path file = dir / name;

		if (!fs::exists(file, ec)) {
			complete = false;
			continue;
		}

		if (!path_is_trusted(file)) {
			if (DeleteFileW(file.c_str()))
				wlog_warn(L"Deleted %s: it was modifiable by non-administrators", file.c_str());
			else
				wlog_warn(L"Could not delete untrusted %s: %lu", file.c_str(), GetLastError());
			complete = false;
		}
	}

	/* everything above reports intent; this is what is actually on disk */
	if (complete && !path_chain_is_trusted(dir))
		complete = false;

	if (!complete) {
		/* The directory is sound but does not hold a full set of hooks we
		 * would stand behind, and the loader hands it to every vulkan
		 * process on the machine. The app re-registers the layer on its
		 * next elevated run, once it has put the files back. */
		remove_vulkan_layer_registry();
		log_info("Hook directory secured; the vulkan layer was unregistered until the app reinstalls the hook");
		return;
	}

	log_info("Hook directory permissions verified");
}
