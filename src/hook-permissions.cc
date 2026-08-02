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
 * "PAI" blocks inheritance: the CREATOR OWNER entry on %ProgramData% would
 * otherwise hand full control to whichever account creates the directory
 * first.
 *
 * AC (ALL APPLICATION PACKAGES) and S-1-15-2-2 (ALL RESTRICTED APPLICATION
 * PACKAGES) are both required for AppContainer capture targets to load the
 * hook: %ProgramFiles% grants both, so the copy we ship is reachable from a
 * less privileged AppContainer and the shared copy has to be as well. */
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

/* For a directory somewhere above what we care about, the only rights that
 * matter are the ones that let someone replace the child out from under us.
 * Being able to create other entries alongside it is not interesting - which
 * is just as well, since every drive root grants exactly that. */
constexpr DWORD kAncestorWriteAccess = FILE_DELETE_CHILD | DELETE | WRITE_DAC | WRITE_OWNER | GENERIC_ALL;

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

/* Mirrors hook_object_is_trusted() in obs-studio's shared/obs-hook-config:
 * owned by an administrative account, not a reparse point, and nobody else
 * holding any of write_mask. Kept in step by hand, since the two repositories
 * share no header. */
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
			/* inherit-only entries grant nothing on this object */
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

/* The object plus every directory above it. Locking down a file means nothing
 * if a standard user can rename one of its parents and present a different
 * tree under the same path. */
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

/* PE file version as one comparable value, 0 when it cannot be read. */
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

/* Renames an untrusted directory out of the way rather than repairing it where
 * it stands.
 *
 * Rewriting a DACL does not revoke handles that are already open. Whoever
 * created the directory can hold one with delete access, let us harden and
 * verify it, and rename it away afterwards - then put their own back at the
 * same path. The app would reject what it finds there, but the vulkan loader
 * does not repeat our checks. A directory that did not exist when they opened
 * their handle is not reachable that way. */
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

	/* Only the names we know. Walking the tree would mean walking whatever
	 * links were left in it, and a delete that follows a junction deletes
	 * what is on the other side. Anything else in there keeps the directory
	 * alive, which is untidy but harmless - it is out of the way. */
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
		/* Both have to land. Taking ownership and then failing to
		 * rewrite the DACL leaves the old one in force; rewriting the
		 * DACL while the directory still belongs to someone else leaves
		 * them able to rewrite it straight back. */
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

/* Drops explicit entries a file picked up while the directory was writable, so
 * that it inherits the descriptor applied above instead.
 *
 * Only ever call this on a file we just wrote. Applied to a file we merely
 * found, it would hand an unknown file to the administrators group and make it
 * pass the consumer's trust check. */
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

/* Replaces dst without ever writing through an existing entry.
 *
 * A hard link planted at dst while the directory was writable shares its data
 * with the file it was linked to, so copying onto it would put our bytes into
 * that file - an arbitrary write, since we run elevated. Deleting removes the
 * directory entry and not the link target, and refusing to overwrite means a
 * re-created entry fails the copy instead of being followed. */
bool copy_over(const fs::path &src, const fs::path &dst)
{
	/* TODO: Authenticode-verify src here, and where repair_hook_directory()
	 * decides to keep an existing file rather than replace it. Permissions
	 * establish who could have written a file, not what is in it. The open
	 * question is which publisher to accept: the hooks ship validly signed,
	 * but as "OBS Project, LLC" rather than as us. */
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

	/* The hook is loaded by whatever we are capturing, so the target can be
	 * locked. Stage the replacement next to it and swap on reboot. The swap
	 * itself is link-safe: MoveFileEx replaces the directory entry rather
	 * than writing through it. */
	fs::path staged = dst;
	staged += L".new";

	if (!copy_over(src, staged)) {
		/* both errors: the first says why we had to stage, the second
		 * why staging did not work either */
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
		wlog_warn(L"Hook source directory %s is missing; unregistering the vulkan layer", source.c_str());
		remove_vulkan_layer_registry();
		return;
	}

	/* --app-dir comes off our own command line and the install directory is
	 * not necessarily %ProgramFiles% - the installer lets the user pick.
	 * Publishing bytes from a directory a standard user can rewrite, out of
	 * a process running as administrator, would just move the problem. */
	if (!path_chain_is_trusted(source)) {
		wlog_warn(L"Hook source directory %s is modifiable by non-administrators; unregistering the vulkan layer", source.c_str());
		remove_vulkan_layer_registry();
		return;
	}

	/* Non-fatal: we may already have the access we need. Worth knowing about
	 * when a later ownership or DACL call fails on someone's machine. */
	if (!enable_privilege(L"SeTakeOwnershipPrivilege"))
		log_warn("Could not enable SeTakeOwnershipPrivilege: %lu", GetLastError());
	if (!enable_privilege(L"SeRestorePrivilege"))
		log_warn("Could not enable SeRestorePrivilege: %lu", GetLastError());

	/* Read the trust state before touching anything: whether the files were
	 * already out of reach of standard users decides whether their version
	 * resource means anything later on. Hardening the directory propagates
	 * to its children, so afterwards the answer would always be yes. */
	const bool dir_was_trusted = path_is_trusted(dir);
	bool pair_was_trusted[std::size(kHookPairs)] = {};

	for (size_t i = 0; i < std::size(kHookPairs); i++) {
		pair_was_trusted[i] = dir_was_trusted && path_is_trusted(dir / kHookPairs[i].dll) && path_is_trusted(dir / kHookPairs[i].manifest);
	}

	/* A junction left behind by whoever owned the directory before us would
	 * send every later step - the descriptor, the copies - to its target
	 * instead. RemoveDirectoryW unlinks the junction itself and leaves
	 * whatever it pointed at alone. */
	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
		if (!RemoveDirectoryW(dir.c_str())) {
			wlog_warn(L"Hook directory %s is a reparse point and could not be unlinked: %lu", dir.c_str(), GetLastError());
			remove_vulkan_layer_registry();
			return;
		}
	}

	/* An untrusted directory is replaced, not repaired: see
	 * quarantine_hook_dir(). Everything in it goes with it, so there is
	 * nothing left to arbitrate against below - pair_was_trusted is already
	 * false throughout in this case, since it is derived from the directory
	 * being trusted. */
	if (!dir_was_trusted && fs::exists(dir, ec) && !quarantine_hook_dir(dir)) {
		remove_vulkan_layer_registry();
		return;
	}

	/* Creating the directory even when it is absent is deliberate: any user
	 * can create a subdirectory under %ProgramData% and would own whatever
	 * they create there.
	 *
	 * The descriptor is then applied unconditionally rather than only on
	 * the "it already existed" branch: CreateDirectoryW reporting
	 * ERROR_ALREADY_EXISTS is exactly what someone racing us to create it
	 * would produce, and that path must not skip the hardening. */
	if (!create_hook_dir(dir) || !apply_hook_dir_security(dir)) {
		remove_vulkan_layer_registry();
		return;
	}

	bool verified = true;
	for (size_t i = 0; i < std::size(kHookPairs); i++) {
		const fs::path src_dll = source / kHookPairs[i].dll;
		const fs::path src_manifest = source / kHookPairs[i].manifest;
		const fs::path dst_dll = dir / kHookPairs[i].dll;
		const fs::path dst_manifest = dir / kHookPairs[i].manifest;

		if (!fs::exists(src_dll, ec) || !fs::exists(src_manifest, ec)) {
			/* We are a remediation step, so a source we cannot
			 * reinstall from means whatever sits at dst stays
			 * there, and we have no idea who put it there. */
			wlog_warn(L"Hook source %s is missing; cannot reinstall %s", src_dll.c_str(), dst_dll.c_str());
			verified = false;
			continue;
		}

		/* The directory above them being sound does not make them so:
		 * either could carry its own entries, and the manifest decides
		 * what the vulkan loader ends up loading. */
		if (!path_is_trusted(src_dll) || !path_is_trusted(src_manifest)) {
			wlog_warn(L"Hook source %s is modifiable by non-administrators; not publishing it", src_dll.c_str());
			verified = false;
			continue;
		}

		/* This directory is shared with every other OBS derived
		 * application on the machine, and the hook version is the
		 * protocol they agree on: newest wins. A version we read out of
		 * a file only standard users could not write is one an
		 * administrator installed, so it is worth honouring - do not
		 * replace a newer hook that another one of them provisioned.
		 * Where that does not hold, the version resource says whatever
		 * whoever wrote the file wanted it to say, and nothing there
		 * survives. */
		if (pair_was_trusted[i] && file_version(dst_dll) >= file_version(src_dll) && file_version(dst_dll) != 0) {
			wlog_info(L"Leaving %s in place; it is at least as new as ours", dst_dll.c_str());
			continue;
		}

		const InstallResult dll_result = install_hook_file(src_dll, dst_dll);
		const InstallResult manifest_result = install_hook_file(src_manifest, dst_manifest);

		/* Ownership is handed over only for a file we actually wrote.
		 * Doing it for one we merely found would make somebody else's
		 * file look administrator-installed to the consumer. */
		if (dll_result != InstallResult::Installed || !reset_file_acl(dst_dll))
			verified = false;

		if (manifest_result != InstallResult::Installed || !reset_file_acl(dst_manifest))
			verified = false;
	}

	/* Everything above reports what it intended to do; this is what is
	 * actually on disk now. */
	if (verified && !path_is_trusted(dir))
		verified = false;

	for (const HookPair &pair : kHookPairs) {
		if (!verified)
			break;
		if (!path_is_trusted(dir / pair.dll) || !path_is_trusted(dir / pair.manifest))
			verified = false;
	}

	if (!verified) {
		/* A file could not be replaced, was only staged and stays as it
		 * is until reboot, or does not come out of this in a state we
		 * would accept. On a machine that was already compromised those
		 * are the planted bytes. The directory is locked down now so
		 * nobody can refresh the plant, but we still must not point the
		 * vulkan loader at it: the loader hands this directory to every
		 * vulkan process on the machine. The app re-registers the layer
		 * once it sees a directory it trusts. */
		remove_vulkan_layer_registry();
		log_warn("Hook files are not fully verified; the vulkan layer was unregistered");
		return;
	}

	log_info("Hook directory permissions verified");
}
