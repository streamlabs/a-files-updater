#include <cstdio>
#include <string>
#include <vector>

#include "manifest-parser.hpp"

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

std::string line(char hash, const std::string &path, const std::string &ending = "\n")
{
	return std::string(64, hash) + " " + path + ending;
}

bool parses(const std::string &content)
{
	manifest_map_t manifest;
	std::string error;
	return parse_update_manifest(content, manifest, error);
}

void valid_manifest_is_normalized()
{
	manifest_map_t manifest;
	std::string error;
	const std::string content = std::string("\xef\xbb\xbf", 3) + line('A', "Resources/App.Asar", "\r\n") + line('b', "dir\\file 1.txt", "");

	CHECK(parse_update_manifest(content, manifest, error));
	CHECK(error.empty());
	CHECK(manifest.size() == 2);
	CHECK(manifest.count("resources\\app.asar") == 1);
	CHECK(manifest.find("RESOURCES\\APP.ASAR") != manifest.end());
	CHECK(manifest.count("dir\\file 1.txt") == 1);
	CHECK(manifest.at("resources\\app.asar").hash_sum == std::string(64, 'a'));
}

void redundant_separators_are_canonicalized()
{
	manifest_map_t manifest;
	std::string error;

	CHECK(parse_update_manifest(line('a', "dir\\\\nested//file.txt"), manifest, error));
	CHECK(manifest.size() == 1);
	CHECK(manifest.count("dir\\nested\\file.txt") == 1);
}

void unsafe_paths_are_rejected()
{
	const std::vector<std::string> paths = {
		"C:\\Windows\\payload.dll",
		"\\Windows\\payload.dll",
		"/Windows/payload.dll",
		"\\\\server\\share\\payload.dll",
		"..\\payload.dll",
		"dir\\..\\payload.dll",
		"dir\\.\\payload.dll",
		"file.txt:stream",
		"dir\\",
		"NUL.txt",
		"dir\\COM1",
		"CON .txt",
		"COM1 .dll",
		"CONIN$",
		"CONOUT$.txt",
		"LPT\xc2\xb9.log",
		"dir\\trailing.\\file",
	};

	for (const std::string &path : paths)
		CHECK(!parses(line('a', path)));
}

void malformed_manifests_are_rejected()
{
	CHECK(!parses(""));
	CHECK(!parses(std::string(63, 'a') + " file.txt\n"));
	CHECK(!parses(std::string(64, 'g') + " file.txt\n"));
	CHECK(!parses(std::string(64, 'a') + "\tfile.txt\n"));
	CHECK(!parses(std::string(64, 'a') + " \n"));
	CHECK(!parses("\n"));
	CHECK(!parses(std::string("\xef\xbb\xbf", 3)));
	CHECK(!parses(line('a', "file.txt") + "broken\n"));
	CHECK(!parses(line('a', "File.txt") + line('b', "file.txt")));
	CHECK(!parses(line('a', "dir/file.txt") + line('b', "dir\\file.txt")));
	CHECK(!parses(line('a', "dir\\file.txt") + line('b', "dir\\\\file.txt")));
	CHECK(!parses(line('a', "foo") + line('b', "foo\\bar.dll")));
	CHECK(!parses(line('a', "Dir") + line('b', "dir\\bar.dll")));
}

void failure_does_not_publish_a_partial_manifest()
{
	manifest_map_t manifest;
	std::string original_hash(64, 'c');
	manifest.emplace("existing.txt", manifest_entry_t(original_hash));
	std::string error;

	CHECK(!parse_update_manifest(line('a', "valid.txt") + "broken\n", manifest, error));
	CHECK(!error.empty());
	CHECK(manifest.size() == 1);
	CHECK(manifest.count("existing.txt") == 1);
}

} // namespace

int main()
{
	valid_manifest_is_normalized();
	redundant_separators_are_canonicalized();
	unsafe_paths_are_rejected();
	malformed_manifests_are_rejected();
	failure_does_not_publish_a_partial_manifest();

	printf("manifest tests: %d failed\n", failures);
	return failures == 0 ? 0 : 1;
}
