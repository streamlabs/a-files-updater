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
 * "PAI" blocks inheritance: the CREATOR OWNER entry on %ProgramData% would
 * otherwise hand full control to whichever account creates the directory
 * first. AC (ALL APPLICATION PACKAGES) is required so that AppContainer
 * processes can load the hook. */
const wchar_t *const kHookDirSddl = L"O:BA"
				    L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;AC)";

const wchar_t *const kAdministratorsSid = L"S-1-5-32-544";

const wchar_t *const kImplicitLayers = L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers";

const wchar_t *const kHookFiles[] = {L"graphics-hook32.dll", L"graphics-hook64.dll", L"obs-vulkan32.json", L"obs-vulkan64.json"};

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

bool create_hook_dir(const fs::path &dir)
{
	SECURITY_ATTRIBUTES attributes = {sizeof(attributes), nullptr, false};

	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kHookDirSddl, SDDL_REVISION_1, &attributes.lpSecurityDescriptor, nullptr)) {
		log_warn("Failed to build hook directory descriptor: %lu", GetLastError());
		return false;
	}

	bool success = CreateDirectoryW(dir.c_str(), &attributes) || GetLastError() == ERROR_ALREADY_EXISTS;
	if (!success)
		log_warn("Failed to create hook directory: %lu", GetLastError());

	LocalFree(attributes.lpSecurityDescriptor);
	return success;
}

/* Ownership is taken first and separately: a directory left behind by an
 * earlier release can be owned by a standard user, and only the owner may
 * rewrite the DACL. */
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
		if (result != ERROR_SUCCESS)
			log_warn("Failed to take ownership of the hook directory: %lu", result);

		result = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION, nullptr, nullptr,
					       dacl, nullptr);
		if (result == ERROR_SUCCESS)
			success = true;
		else
			log_warn("Failed to secure the hook directory: %lu", result);
	}

	LocalFree(descriptor);
	return success;
}

/* Drops explicit entries a file picked up while the directory was writable, so
 * that it inherits the descriptor applied above instead. */
void reset_file_acl(const fs::path &file)
{
	ACL empty_dacl;
	if (!InitializeAcl(&empty_dacl, sizeof(empty_dacl), ACL_REVISION))
		return;

	PSID owner = nullptr;
	if (!ConvertStringSidToSidW(kAdministratorsSid, &owner))
		return;

	std::wstring path = file.wstring();
	DWORD result = SetNamedSecurityInfoW(path.data(), SE_FILE_OBJECT,
					     OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION, owner, nullptr,
					     &empty_dacl, nullptr);
	if (result != ERROR_SUCCESS)
		wlog_warn(L"Failed to reset permissions on %s: %lu", path.c_str(), result);

	LocalFree(owner);
}

void delete_layer_value(HKEY root, DWORD wow_flag, const std::wstring &value)
{
	HKEY key = nullptr;
	if (RegOpenKeyExW(root, kImplicitLayers, 0, KEY_WRITE | wow_flag, &key) != ERROR_SUCCESS)
		return;

	RegDeleteValueW(key, value.c_str());
	RegCloseKey(key);
}

/* An implicit layer entry outlives the directory it points at, and the loader
 * hands that directory to every vulkan process on the machine. */
void remove_vulkan_layer_registry()
{
	const fs::path dir = programdata_hook_dir();
	const wchar_t *const manifests[] = {L"obs-vulkan32.json", L"obs-vulkan64.json"};

	for (const wchar_t *manifest : manifests) {
		const std::wstring value = (dir / manifest).wstring();

		for (HKEY root : {HKEY_LOCAL_MACHINE, HKEY_CURRENT_USER}) {
			delete_layer_value(root, KEY_WOW64_64KEY, value);
			delete_layer_value(root, KEY_WOW64_32KEY, value);
		}
	}
}

enum class InstallResult {
	Failed,
	Installed,
	/* Staged: the bytes on disk are still the old ones until reboot. */
	Pending,
};

InstallResult install_hook_file(const fs::path &src, const fs::path &dst)
{
	if (CopyFileW(src.c_str(), dst.c_str(), false))
		return InstallResult::Installed;

	const DWORD copy_error = GetLastError();

	/* The hook is loaded by whatever we are capturing, so the target can be
	 * locked. Stage the replacement next to it and swap on reboot. */
	fs::path staged = dst;
	staged += L".new";

	if (!CopyFileW(src.c_str(), staged.c_str(), false)) {
		wlog_warn(L"Failed to install %s: %lu", dst.c_str(), copy_error);
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

} // namespace

void repair_hook_directory(const fs::path &app_dir)
{
	const fs::path dir = programdata_hook_dir();
	if (dir.empty()) {
		log_warn("Could not resolve the hook directory, skipping permission repair");
		return;
	}

	std::error_code ec;
	const fs::path source =
		app_dir / L"resources" / L"app.asar.unpacked" / L"node_modules" / L"obs-studio-node" / L"data" / L"obs-plugins" / L"win-capture";

	if (!fs::is_directory(source, ec)) {
		wlog_warn(L"Hook source directory %s is missing, skipping permission repair", source.c_str());
		return;
	}

	enable_privilege(L"SeTakeOwnershipPrivilege");
	enable_privilege(L"SeRestorePrivilege");

	/* Creating the directory even when it is absent is deliberate: any user
	 * can create a subdirectory under %ProgramData% and would own whatever
	 * they create there. */
	if (!fs::exists(dir, ec)) {
		if (!create_hook_dir(dir)) {
			remove_vulkan_layer_registry();
			return;
		}
	} else if (!apply_hook_dir_security(dir)) {
		remove_vulkan_layer_registry();
		return;
	}

	/* The files themselves are always reinstalled: a hook planted while the
	 * directory was writable is indistinguishable from ours, and its
	 * version resource is whatever the attacker wrote there. */
	bool verified = true;
	for (const wchar_t *name : kHookFiles) {
		const fs::path src = source / name;
		const fs::path dst = dir / name;

		if (!fs::exists(src, ec))
			continue;

		const InstallResult result = install_hook_file(src, dst);
		if (result == InstallResult::Installed)
			reset_file_acl(dst);
		else
			verified = false;
	}

	if (!verified) {
		/* Either a file could not be replaced at all, or it was only
		 * staged and the bytes on disk stay as they are until reboot —
		 * on a machine that was already compromised, those are the
		 * planted bytes. The directory is locked down now, so nobody
		 * can refresh the plant, but we still must not point the vulkan
		 * loader at it: it hands this directory to every vulkan process
		 * on the machine. The app re-registers the layer once it sees a
		 * directory it trusts. */
		remove_vulkan_layer_registry();
		log_warn("Hook files are not fully verified (locked or unreplaceable); the vulkan layer was unregistered");
		return;
	}

	log_info("Hook directory permissions verified");
}
