#define _CRT_RAND_S

#include "hook-permissions.hpp"

#include <windows.h>
#include <aclapi.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstdint>
#include <cstdlib>
#include <string>
#include <system_error>
#include <vector>

#include "logger/log.h"

namespace {

const wchar_t *const kHookDirSddl = L"O:BA"
				    L"D:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;FRFX;;;BU)(A;OICI;FRFX;;;AC)(A;OICI;FRFX;;;S-1-15-2-2)";

const wchar_t *const kAdministratorsSid = L"S-1-5-32-544";

const wchar_t *const kImplicitLayers = L"SOFTWARE\\Khronos\\Vulkan\\ImplicitLayers";

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

constexpr DWORD kAncestorWriteAccess = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

enum class InstallResult { Failed, Installed, StagedForReboot };

bool is_reparse_point(const fs::path &path)
{
	const DWORD attributes = GetFileAttributesW(path.c_str());
	return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0;
}

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

	/* the owner can always rewrite the DACL, and a NULL DACL grants everyone
	 * everything */
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
			/* inherit-only grants nothing on this object */
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

fs::path quarantine_name(const fs::path &dir)
{
	static const wchar_t digits[] = L"0123456789abcdef";
	unsigned int word = 0;

	/* zeroed on failure, which would leave us a fixed name */
	if (rand_s(&word) != 0) {
		log_warn("Could not name a quarantine directory: no randomness available");
		return {};
	}

	fs::path name = dir;
	name += L".quarantine";

	for (int shift = 28; shift >= 0; shift -= 4)
		name += digits[(word >> shift) & 0xF];

	return name;
}

bool quarantine_hook_dir(const fs::path &dir)
{
	/* random, and tried once - see the header */
	const fs::path aside = quarantine_name(dir);
	if (aside.empty())
		return false;

	if (!MoveFileExW(dir.c_str(), aside.c_str(), 0)) {
		wlog_warn(L"Could not move %s aside: %lu", dir.c_str(), GetLastError());
		return false;
	}

	/* A junction survives the rename, and a child path below one resolves
	 * through it - we would be scheduling deletions in whatever it points
	 * at, carried out at reboot as SYSTEM. Tested after the move and not
	 * before it, where it would only describe what the path used to be. */
	if (!is_reparse_point(aside)) {
		/* only the names we own - walking the tree would follow
		 * whatever junctions were left in it */
		for (const HookPair &pair : kHookPairs) {
			for (const wchar_t *name : {pair.dll, pair.manifest}) {
				fs::path leftover = aside / name;
				MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
				leftover += L".new";
				MoveFileExW(leftover.c_str(), nullptr, MOVEFILE_DELAY_UNTIL_REBOOT);
			}
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

	const bool created = CreateDirectoryW(dir.c_str(), &attributes) != 0;
	if (!created) {
		const DWORD error = GetLastError();
		if (error == ERROR_ALREADY_EXISTS)
			log_warn("The hook directory was recreated while it was being repaired; refusing it");
		else
			log_warn("Failed to create hook directory: %lu", error);
	}

	LocalFree(attributes.lpSecurityDescriptor);
	return created;
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
		/* ownership first: only the owner may rewrite the DACL */
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

bool reset_acl_of_file_we_wrote(const fs::path &file)
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

bool delete_then_copy(const fs::path &src, const fs::path &dst)
{
	/* never write through an existing entry: it may be a hard link, and our
	 * bytes would land in its target instead */
	const DWORD attributes = GetFileAttributesW(dst.c_str());

	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (attributes & FILE_ATTRIBUTE_READONLY)
			SetFileAttributesW(dst.c_str(), attributes & ~static_cast<DWORD>(FILE_ATTRIBUTE_READONLY));

		if (!DeleteFileW(dst.c_str()) && GetLastError() != ERROR_FILE_NOT_FOUND)
			return false;
	}

	return CopyFileW(src.c_str(), dst.c_str(), true);
}

/* A .new an earlier run queued is still queued, and at reboot it would put that
 * older copy back over whatever is there now. Deleting the file is enough to
 * cancel it: a pending rename whose source has gone is skipped. */
void discard_staged(const fs::path &dst)
{
	fs::path staged = dst;
	staged += L".new";

	if (DeleteFileW(staged.c_str()))
		wlog_info(L"Discarded %s, which was queued to replace a newer file at the next reboot", staged.c_str());
}

InstallResult install_hook_file(const fs::path &src, const fs::path &dst)
{
	if (delete_then_copy(src, dst)) {
		discard_staged(dst);
		return InstallResult::Installed;
	}

	const DWORD copy_error = GetLastError();

	fs::path staged = dst;
	staged += L".new";

	if (!delete_then_copy(src, staged)) {
		wlog_warn(L"Failed to install %s: %lu, and staging it failed: %lu", dst.c_str(), copy_error, GetLastError());
		return InstallResult::Failed;
	}

	reset_acl_of_file_we_wrote(staged);

	if (!MoveFileExW(staged.c_str(), dst.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_DELAY_UNTIL_REBOOT)) {
		wlog_warn(L"Failed to schedule replacement of %s: %lu", dst.c_str(), GetLastError());
		DeleteFileW(staged.c_str());
		return InstallResult::Failed;
	}

	wlog_info(L"%s is in use, replacement scheduled for the next reboot", dst.c_str());
	return InstallResult::StagedForReboot;
}

fs::path trusted_hook_payload(const fs::path &app_dir)
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

		if (!path_is_trusted(src_dll) || !path_is_trusted(src_manifest)) {
			wlog_warn(L"Hook payload %s is modifiable by non-administrators; not publishing it", src_dll.c_str());
			continue;
		}

		/* newest wins, across every OBS derived application on the box */
		if (pair_was_trusted[i] && file_version(dst_dll) >= file_version(src_dll) && file_version(dst_dll) != 0) {
			wlog_info(L"Leaving %s in place; it is at least as new as ours", dst_dll.c_str());
			/* ours is the older of the two, so a staged copy of it
			 * would undo this at the next reboot */
			discard_staged(dst_dll);
			discard_staged(dst_manifest);
			continue;
		}

		if (install_hook_file(src_manifest, dst_manifest) == InstallResult::Installed)
			reset_acl_of_file_we_wrote(dst_manifest);

		if (install_hook_file(src_dll, dst_dll) == InstallResult::Installed)
			reset_acl_of_file_we_wrote(dst_dll);
	}
}

} // namespace

bool repair_hook_directory(const fs::path &app_dir)
{
	const fs::path dir = programdata_hook_dir();
	if (dir.empty()) {
		log_warn("Could not resolve the hook directory, skipping permission repair");
		return false;
	}

	/* non-fatal; logged only because it explains a later ownership failure */
	if (!enable_privilege(L"SeTakeOwnershipPrivilege"))
		log_warn("Could not enable SeTakeOwnershipPrivilege: %lu", GetLastError());
	if (!enable_privilege(L"SeRestorePrivilege"))
		log_warn("Could not enable SeRestorePrivilege: %lu", GetLastError());

	/* Every trust question about what is already here is answered now, before
	 * the descriptor goes on. Applying it propagates to the children, and a
	 * file that was writable only through an inherited ACE reads as
	 * administrator-installed afterwards. */
	const bool dir_was_trusted = path_chain_is_trusted(dir);
	bool file_was_trusted[std::size(kHookPairs)][2] = {};
	bool pair_was_trusted[std::size(kHookPairs)] = {};

	for (size_t i = 0; i < std::size(kHookPairs); i++) {
		file_was_trusted[i][0] = dir_was_trusted && path_is_trusted(dir / kHookPairs[i].dll);
		file_was_trusted[i][1] = dir_was_trusted && path_is_trusted(dir / kHookPairs[i].manifest);
		pair_was_trusted[i] = file_was_trusted[i][0] && file_was_trusted[i][1];
	}

	/* unlink a junction rather than working through it to its target */
	std::error_code ec;
	if (is_reparse_point(dir)) {
		if (!RemoveDirectoryW(dir.c_str())) {
			wlog_warn(L"Hook directory %s is a reparse point and could not be unlinked: %lu", dir.c_str(), GetLastError());
			remove_vulkan_layer_registry();
			return false;
		}
	}

	if (!dir_was_trusted && fs::exists(dir, ec) && !quarantine_hook_dir(dir)) {
		remove_vulkan_layer_registry();
		return false;
	}

	if ((!dir_was_trusted && !create_hook_dir(dir)) || !apply_hook_dir_security(dir)) {
		remove_vulkan_layer_registry();
		return false;
	}

	/* Permissions are settled; nothing below here may abort the repair. */

	for (size_t i = 0; i < std::size(kHookPairs); i++) {
		const wchar_t *const names[] = {kHookPairs[i].dll, kHookPairs[i].manifest};

		for (size_t j = 0; j < std::size(names); j++) {
			const fs::path file = dir / names[j];

			/* the sample, not a fresh check: this runs after the
			 * hardening it would otherwise be reading back */
			if (file_was_trusted[i][j] || !fs::exists(file, ec))
				continue;

			if (DeleteFileW(file.c_str()))
				wlog_warn(L"Deleted %s: it was modifiable by non-administrators", file.c_str());
			else
				wlog_warn(L"Could not delete untrusted %s: %lu", file.c_str(), GetLastError());
		}
	}

	const fs::path source = trusted_hook_payload(app_dir);
	if (!source.empty())
		publish_hooks(dir, source, pair_was_trusted);

	const bool dir_is_trusted = path_chain_is_trusted(dir);
	bool complete = dir_is_trusted;

	for (const HookPair &pair : kHookPairs)
		complete = complete && path_is_trusted(dir / pair.dll) && path_is_trusted(dir / pair.manifest);

	if (!complete) {
		remove_vulkan_layer_registry();

		/* only the payload being short is a success; the directory not
		 * being ours is the failure this reports */
		if (dir_is_trusted)
			log_info("Hook directory secured; the vulkan layer was unregistered until the hook is reinstalled");
		else
			log_warn("Hook directory is still modifiable by non-administrators; the vulkan layer was unregistered");

		return dir_is_trusted;
	}

	log_info("Hook directory permissions verified");
	return true;
}
