#define _CRT_RAND_S

#include "updater-storage.hpp"

#include <windows.h>
#include <sddl.h>
#include <shlobj.h>

#include <cstdlib>
#include <string>

#include "hook-permissions.hpp"
#include "logger/log.h"

namespace {

const wchar_t *const kUpdaterDirSddl = L"O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)";

void log_untrusted(const fs::path &dir, const TrustReport &trust)
{
	if (!trust.object)
		wlog_warn(L"Refusing updater directory %s: it %s", dir.c_str(), trust.object_why.c_str());
	if (!trust.ancestors)
		wlog_warn(L"Refusing updater directory %s: ancestor %s %s", dir.c_str(), trust.ancestor.c_str(), trust.ancestor_why.c_str());
}

bool trusted_directory(const fs::path &dir)
{
	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes == INVALID_FILE_ATTRIBUTES || (attributes & FILE_ATTRIBUTE_DIRECTORY) == 0) {
		wlog_warn(L"Refusing updater directory %s: it is not a directory", dir.c_str());
		return false;
	}

	const TrustReport trust = chain_trust(dir);
	if (!trust.object || !trust.ancestors) {
		log_untrusted(dir, trust);
		return false;
	}

	return true;
}

bool create_secure_directory(const fs::path &dir)
{
	SECURITY_ATTRIBUTES attributes = {sizeof(attributes), nullptr, false};
	if (!ConvertStringSecurityDescriptorToSecurityDescriptorW(kUpdaterDirSddl, SDDL_REVISION_1, &attributes.lpSecurityDescriptor, nullptr)) {
		log_warn("Failed to build updater directory descriptor: %lu", GetLastError());
		return false;
	}

	const bool created = CreateDirectoryW(dir.c_str(), &attributes) != 0;
	const DWORD error = created ? ERROR_SUCCESS : GetLastError();
	LocalFree(attributes.lpSecurityDescriptor);

	if (!created) {
		wlog_warn(L"Failed to create updater directory %s: %lu", dir.c_str(), error);
		return false;
	}

	if (!trusted_directory(dir)) {
		wlog_warn(L"Updater directory %s did not retain its secure descriptor", dir.c_str());
		return false;
	}

	return true;
}

std::wstring random_leaf()
{
	static const wchar_t digits[] = L"0123456789abcdef";
	std::wstring leaf = L"run-";

	for (int word_index = 0; word_index < 4; word_index++) {
		unsigned int word = 0;
		if (rand_s(&word) != 0)
			return {};

		for (int shift = 28; shift >= 0; shift -= 4)
			leaf += digits[(word >> shift) & 0xF];
	}

	return leaf;
}

} // namespace

fs::path programdata_updater_root()
{
	wchar_t path[MAX_PATH] = {};
	if (FAILED(SHGetFolderPathW(nullptr, CSIDL_COMMON_APPDATA, nullptr, SHGFP_TYPE_CURRENT, path)))
		return {};

	return fs::path(path) / L"slobs-updater";
}

bool prepare_updater_temp_dir(const fs::path &dir, bool allow_existing)
{
	if (dir.empty() || !dir.is_absolute() || !dir.has_relative_path()) {
		wlog_warn(L"Refusing invalid updater directory %s", dir.c_str());
		return false;
	}
	for (const fs::path &component : dir.relative_path()) {
		if (component == L"." || component == L"..") {
			wlog_warn(L"Refusing non-normal updater directory %s", dir.c_str());
			return false;
		}
	}

	const DWORD attributes = GetFileAttributesW(dir.c_str());
	if (attributes != INVALID_FILE_ATTRIBUTES) {
		if (!allow_existing) {
			wlog_warn(L"Refusing existing updater directory %s", dir.c_str());
			return false;
		}

		return trusted_directory(dir);
	}

	const DWORD lookup_error = GetLastError();
	if (lookup_error != ERROR_FILE_NOT_FOUND && lookup_error != ERROR_PATH_NOT_FOUND) {
		wlog_warn(L"Could not inspect updater directory %s: %lu", dir.c_str(), lookup_error);
		return false;
	}

	/* The standard ProgramData DACL lets Users create sibling directories,
	 * but not rename or delete existing ones. That is safe here: creation
	 * applies the final protected DACL atomically, and ERROR_ALREADY_EXISTS
	 * is refused rather than adopted. Judge the parent as an ancestor, where
	 * create-child is therefore not a replacement capability. */
	const TrustReport destination = chain_trust(dir);
	if (!destination.ancestors) {
		wlog_warn(L"Refusing to create updater directory %s: ancestor %s %s", dir.c_str(), destination.ancestor.c_str(),
			  destination.ancestor_why.c_str());
		return false;
	}

	return create_secure_directory(dir);
}

fs::path create_default_updater_temp_dir()
{
	const fs::path root = programdata_updater_root();
	if (root.empty()) {
		log_warn("Failed to resolve the system ProgramData directory");
		return {};
	}

	if (!prepare_updater_temp_dir(root, true))
		return {};

	for (int attempt = 0; attempt < 8; attempt++) {
		const std::wstring leaf = random_leaf();
		if (leaf.empty()) {
			log_warn("Failed to generate a random updater directory name");
			return {};
		}

		const fs::path run_dir = root / leaf;
		if (prepare_updater_temp_dir(run_dir, false))
			return run_dir;
	}

	log_warn("Failed to create a unique updater directory");
	return {};
}
