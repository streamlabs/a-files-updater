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

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwctype>
#include <string>
#include <vector>

#include "hook-permissions.hpp"
#include "update-blockers.hpp"
#include "stub-reporter.hpp"

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

void write_file(const fs::path &path, const char *contents)
{
	FILE *file = nullptr;
	if (_wfopen_s(&file, path.c_str(), L"wb") == 0 && file) {
		fwrite(contents, 1, strlen(contents), file);
		fclose(file);
	}
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
