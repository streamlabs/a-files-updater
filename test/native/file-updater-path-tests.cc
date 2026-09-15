#include <Windows.h>

#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>

#include "file-updater-paths.hpp"

namespace fs = std::filesystem;

namespace {

int failures = 0;

void check(bool ok, const char *expression, int line)
{
	if (ok)
		return;

	failures++;
	printf("FAIL line %d: %s\n", line, expression);
}

#define CHECK(cond) check((cond), #cond, __LINE__)

void write_file(const fs::path &path)
{
	fs::create_directories(path.parent_path());
	std::ofstream(path) << "test";
}

void missing_destination_is_accepted(const fs::path &root)
{
	std::error_code ec = std::make_error_code(std::errc::permission_denied);
	CHECK(remove_revert_destination(root / L"missing", ec));
	CHECK(!ec);
}

void file_destination_is_removed(const fs::path &root)
{
	const fs::path file = root / L"file";
	write_file(file);

	std::error_code ec;
	CHECK(remove_revert_destination(file, ec));
	CHECK(!ec);
	CHECK(!fs::exists(file));
}

void directory_destination_is_removed_recursively(const fs::path &root)
{
	const fs::path directory = root / L"directory";
	write_file(directory / L"nested" / L"payload.dll");

	std::error_code ec;
	CHECK(remove_revert_destination(directory, ec));
	CHECK(!ec);
	CHECK(!fs::exists(directory));
}

void directory_symlink_is_removed_as_a_leaf(const fs::path &root)
{
	const fs::path target = root / L"target";
	const fs::path link = root / L"link";
	write_file(target / L"keep.txt");

	if (!CreateSymbolicLinkW(link.c_str(), target.c_str(), SYMBOLIC_LINK_FLAG_DIRECTORY | SYMBOLIC_LINK_FLAG_ALLOW_UNPRIVILEGED_CREATE)) {
		printf("SKIP directory symlink case: CreateSymbolicLinkW failed with 0x%08lx\n", GetLastError());
		return;
	}

	std::error_code ec;
	CHECK(remove_revert_destination(link, ec));
	CHECK(!ec);
	CHECK(!fs::exists(fs::symlink_status(link)));
	CHECK(fs::exists(target / L"keep.txt"));
}

} // namespace

int main()
{
	const fs::path root = fs::temp_directory_path() / (L"slobs-file-updater-path-tests-" + std::to_wstring(GetCurrentProcessId()));
	std::error_code ec;
	fs::remove_all(root, ec);
	fs::create_directories(root, ec);
	CHECK(!ec);

	missing_destination_is_accepted(root);
	file_destination_is_removed(root);
	directory_destination_is_removed_recursively(root);
	directory_symlink_is_removed_as_a_leaf(root);

	fs::remove_all(root, ec);
	printf("file updater path tests: %d failed\n", failures);
	return failures == 0 ? 0 : 1;
}
