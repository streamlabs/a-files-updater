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

#include "crash-reporter.hpp"
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

/* manual: stream number formatting is not locale-safe on the worker thread */
std::wstring hex32(uint32_t value)
{
	static const wchar_t digits[] = L"0123456789ABCDEF";
	std::wstring text = L"0x";

	for (int shift = 28; shift >= 0; shift -= 4)
		text += digits[(value >> shift) & 0xF];

	return text;
}

std::wstring sid_string(PSID sid)
{
	wchar_t *text = nullptr;
	if (!sid || !IsValidSid(sid) || !ConvertSidToStringSidW(sid, &text))
		return L"an unreadable SID";

	std::wstring result = text;
	LocalFree(text);
	return result;
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

/* On false, why is filled with a phrase that reads after the path: "<path> is
 * owned by S-1-5-21-...". Deducing that from a bare bool cost a Sentry round
 * trip once already. */
bool object_is_trusted(const fs::path &path, DWORD write_mask, std::wstring *why)
{
	const auto refuse = [why](std::wstring reason) {
		if (why)
			*why = std::move(reason);
		return false;
	};

	const DWORD attributes = GetFileAttributesW(path.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES)
		return refuse(L"cannot be read: " + hex32(GetLastError()));
	if (attributes & FILE_ATTRIBUTE_REPARSE_POINT)
		return refuse(L"is a reparse point");

	PSECURITY_DESCRIPTOR descriptor = nullptr;
	PSID owner = nullptr;
	PACL dacl = nullptr;

	const DWORD read = GetNamedSecurityInfoW(path.c_str(), SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION, &owner, nullptr, &dacl,
						 nullptr, &descriptor);
	if (read != ERROR_SUCCESS)
		return refuse(L"has an unreadable security descriptor: " + hex32(read));

	std::wstring reason;

	/* the owner can always rewrite the DACL, and a NULL DACL grants everyone
	 * everything */
	if (!sid_is_trusted(owner)) {
		reason = L"is owned by " + sid_string(owner);
	} else if (!dacl) {
		reason = L"has no DACL, which grants everyone everything";
	} else {
		for (WORD i = 0; i < dacl->AceCount; i++) {
			ACCESS_ALLOWED_ACE *ace = nullptr;

			if (!GetAce(dacl, i, reinterpret_cast<void **>(&ace))) {
				reason = L"has an unreadable ACE at index " + hex32(i);
				break;
			}
			if (ace->Header.AceType == ACCESS_DENIED_ACE_TYPE)
				continue;
			if (ace->Header.AceType != ACCESS_ALLOWED_ACE_TYPE) {
				reason = L"has an ACE at index " + hex32(i) + L" of unhandled type " + hex32(ace->Header.AceType);
				break;
			}
			/* inherit-only grants nothing on this object */
			if (ace->Header.AceFlags & INHERIT_ONLY_ACE)
				continue;
			if ((ace->Mask & write_mask) == 0)
				continue;

			PSID grantee = reinterpret_cast<PSID>(&ace->SidStart);
			if (!sid_is_trusted(grantee)) {
				reason = L"grants " + sid_string(grantee) + L" write access " + hex32(ace->Mask & write_mask) + L", out of " + hex32(ace->Mask);
				break;
			}
		}
	}

	LocalFree(descriptor);

	if (reason.empty())
		return true;

	return refuse(std::move(reason));
}

bool path_is_trusted(const fs::path &path)
{
	return object_is_trusted(path, kWriteAccess, nullptr);
}

/* path_is_trusted, but it says why it refused. The refusal is not always a
 * write grant - an unreadable descriptor or a reparse point lands here too - so
 * a caller that phrases it as one is guessing. */
bool file_is_trusted(const wchar_t *lead, const fs::path &path)
{
	std::wstring why;

	if (object_is_trusted(path, kWriteAccess, &why))
		return true;

	wlog_warn(L"%s %s %s", lead, path.c_str(), why.c_str());
	return false;
}

/* The object and the path to it are answered separately, because only the
 * object is acted on: it is the one that says who wrote what is there, and the
 * one an elevated writer can repair. An untrusted ancestor is reported and
 * nothing else - see the header.
 *
 * Deliberately no bool that folds the two back together. One of those is what
 * had the repair quarantining a sound directory over a drive root. */
struct TrustReport {
	bool object = false;
	bool ancestors = false;
	std::wstring object_why;
	fs::path ancestor; /* the component ancestor_why describes */
	std::wstring ancestor_why;
};

TrustReport chain_trust(const fs::path &path)
{
	TrustReport report;

	report.object = object_is_trusted(path, kWriteAccess, &report.object_why);
	report.ancestors = true;

	for (fs::path current = path.parent_path();; current = current.parent_path()) {
		if (!object_is_trusted(current, kAncestorWriteAccess, &report.ancestor_why)) {
			report.ancestors = false;
			report.ancestor = current;
			break;
		}

		/* the root is its own parent, so stop once we reach it */
		if (!current.has_relative_path())
			break;
	}

	return report;
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

	/* The directory holding it, not the path to it: a standard user who can
	 * rename a parent of %ProgramFiles% can replace the application itself,
	 * so refusing over one would cost capture and deny them nothing. */
	const TrustReport trust = chain_trust(source);

	if (!trust.object) {
		wlog_warn(L"Hook payload %s %s; not publishing it", source.c_str(), trust.object_why.c_str());
		return {};
	}
	if (!trust.ancestors)
		wlog_warn(L"Hook payload %s is reached through %s, which %s; publishing it anyway", source.c_str(), trust.ancestor.c_str(),
			  trust.ancestor_why.c_str());

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

		if (!file_is_trusted(L"Not publishing hook payload", src_dll) || !file_is_trusted(L"Not publishing hook payload", src_manifest))
			continue;

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

HookRepair repair_hook_directory(const fs::path &app_dir)
{
	const fs::path dir = programdata_hook_dir();
	if (dir.empty()) {
		log_warn("Could not resolve the hook directory, skipping permission repair");
		return HookRepair::Failed;
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
	const TrustReport before = chain_trust(dir);
	const bool dir_was_trusted = before.object;
	bool file_was_trusted[std::size(kHookPairs)][2] = {};
	bool pair_was_trusted[std::size(kHookPairs)] = {};

	/* Nothing an elevated writer can repair, and no reason to distrust the
	 * hooks: whoever wrote them is a separate question from whether the way
	 * to them can be swapped. Logged here so it survives a later failure. */
	if (!before.ancestors)
		wlog_warn(L"The hook directory is reached through %s, which %s", before.ancestor.c_str(), before.ancestor_why.c_str());

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
			return HookRepair::Failed;
		}
	}

	if (!dir_was_trusted && fs::exists(dir, ec)) {
		wlog_warn(L"Hook directory %s %s; replacing it", dir.c_str(), before.object_why.c_str());

		if (!quarantine_hook_dir(dir)) {
			remove_vulkan_layer_registry();
			return HookRepair::Failed;
		}
	}

	if ((!dir_was_trusted && !create_hook_dir(dir)) || !apply_hook_dir_security(dir)) {
		remove_vulkan_layer_registry();
		return HookRepair::Failed;
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

	const TrustReport after = chain_trust(dir);
	bool hooks_trusted = true;

	for (const HookPair &pair : kHookPairs)
		hooks_trusted = hooks_trusted && path_is_trusted(dir / pair.dll) && path_is_trusted(dir / pair.manifest);

	/* The layer is kept by a directory that is ours holding a full set of
	 * trusted hooks. The path above it is reported and nothing else - see
	 * the header. */
	if (!after.object || !hooks_trusted)
		remove_vulkan_layer_registry();

	if (!after.object) {
		wlog_warn(L"The repair did not take - hook directory %s %s; the vulkan layer was unregistered", dir.c_str(), after.object_why.c_str());
		return HookRepair::Failed;
	}

	if (!hooks_trusted)
		log_info("Hook directory secured; the vulkan layer was unregistered until the hook is reinstalled");
	else
		log_info("Hook directory permissions verified");

	if (!after.ancestors) {
		wlog_warn(L"Hook directory %s is administrator-only, but it is reached through %s, which %s; left in use", dir.c_str(), after.ancestor.c_str(),
			  after.ancestor_why.c_str());
		return HookRepair::AncestorUntrusted;
	}

	return HookRepair::Secured;
}

void report_hook_repair(HookRepair result)
{
	switch (result) {
	case HookRepair::Secured:
		break;
	case HookRepair::AncestorUntrusted:
		/* not necessarily a write grant - a reparse point or an
		 * unreadable descriptor lands here too, and the log has the
		 * one that did */
		report_handled_error("HookDirAncestorUntrusted", "A directory above the graphics hook directory could not be trusted");
		break;
	case HookRepair::Failed:
		report_handled_error("HookRepairFailure", "Could not secure the graphics hook directory");
		break;
	}
}
