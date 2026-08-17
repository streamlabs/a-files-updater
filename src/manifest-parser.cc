#include "manifest-parser.hpp"

#include <algorithm>
#include <cctype>
#include <cwchar>
#include <cwctype>
#include <utility>
#include <vector>

namespace {

bool reserved_device_name(const std::wstring &component)
{
	const size_t extension = component.find(L'.');
	std::wstring base = component.substr(0, extension);
	while (!base.empty() && (base.back() == L' ' || base.back() == L'.'))
		base.pop_back();
	std::transform(base.begin(), base.end(), base.begin(), [](wchar_t c) { return static_cast<wchar_t>(towupper(c)); });

	if (base == L"CON" || base == L"PRN" || base == L"AUX" || base == L"NUL" || base == L"CONIN$" || base == L"CONOUT$")
		return true;
	if (base.size() == 4 && (base.rfind(L"COM", 0) == 0 || base.rfind(L"LPT", 0) == 0)) {
		const wchar_t suffix = base[3];
		return (suffix >= L'1' && suffix <= L'9') || suffix == L'\u00b9' || suffix == L'\u00b2' || suffix == L'\u00b3';
	}

	return false;
}

bool valid_component(const fs::path &component, std::string &error)
{
	const std::wstring value = component.native();
	if (value.empty() || value == L"." || value == L"..") {
		error = "path contains an empty, dot, or parent component";
		return false;
	}
	if (value.front() == L' ' || value.back() == L' ' || value.back() == L'.') {
		error = "path component starts or ends with a space or dot";
		return false;
	}
	for (wchar_t c : value) {
		if (c < 32 || wcschr(L"<>:\"|?*", c)) {
			error = "path component contains a reserved Windows character";
			return false;
		}
	}
	if (reserved_device_name(value)) {
		error = "path component is a reserved Windows device name";
		return false;
	}

	return true;
}

int compare_windows_paths(const fs::path &left, const fs::path &right)
{
	return CompareStringOrdinal(left.c_str(), -1, right.c_str(), -1, TRUE);
}

} // namespace

bool normalize_manifest_path(std::string_view input, std::string &normalized, std::string &error)
{
	normalized.clear();
	error.clear();
	if (input.empty() || input.find('\0') != std::string_view::npos) {
		error = "path is empty or contains a NUL byte";
		return false;
	}

	std::string windows_path(input);
	std::replace(windows_path.begin(), windows_path.end(), '/', '\\');

	try {
		fs::path path = fs::u8path(windows_path);
		path.make_preferred();
		if (path.empty() || path.is_absolute() || path.has_root_name() || path.has_root_directory() || !path.has_filename()) {
			error = "path is rooted, absolute, or does not name a file";
			return false;
		}
		fs::path canonical;
		for (const fs::path &component : path) {
			if (!valid_component(component, error))
				return false;
			canonical /= component;
		}

		normalized = canonical.u8string();
		return true;
	} catch (const std::exception &) {
		error = "path is not valid UTF-8";
		return false;
	}
}

bool parse_update_manifest(const std::string &content, manifest_map_t &output, std::string &error)
{
	manifest_map_t parsed;
	std::vector<std::pair<fs::path, size_t>> parsed_paths;
	error.clear();

	std::string_view document(content);
	constexpr std::string_view utf8_bom("\xef\xbb\xbf", 3);
	if (document.substr(0, utf8_bom.size()) == utf8_bom)
		document.remove_prefix(utf8_bom.size());

	if (document.empty()) {
		error = "manifest is empty";
		return false;
	}

	size_t offset = 0;
	size_t line_number = 1;
	while (offset < document.size()) {
		const size_t newline = document.find('\n', offset);
		size_t line_end = newline == std::string_view::npos ? document.size() : newline;
		if (line_end > offset && document[line_end - 1] == '\r')
			line_end--;
		const std::string_view line(document.data() + offset, line_end - offset);
		if (line.size() < 66 || line[64] != ' ') {
			error = "line " + std::to_string(line_number) + " does not contain a SHA-256 hash and path";
			return false;
		}

		std::string checksum(line.substr(0, 64));
		if (!std::all_of(checksum.begin(), checksum.end(), [](unsigned char c) { return std::isxdigit(c) != 0; })) {
			error = "line " + std::to_string(line_number) + " contains an invalid SHA-256 hash";
			return false;
		}
		std::transform(checksum.begin(), checksum.end(), checksum.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

		std::string normalized;
		std::string path_error;
		if (!normalize_manifest_path(line.substr(65), normalized, path_error)) {
			error = "line " + std::to_string(line_number) + " has an invalid path: " + path_error;
			return false;
		}

		manifest_entry_t entry(checksum);
		parsed.emplace(normalized, std::move(entry));
		parsed_paths.emplace_back(fs::u8path(normalized), line_number);
		offset = newline == std::string_view::npos ? document.size() : newline + 1;
		line_number++;
	}

	std::sort(parsed_paths.begin(), parsed_paths.end(),
		  [](const auto &left, const auto &right) { return compare_windows_paths(left.first, right.first) == CSTR_LESS_THAN; });
	for (size_t i = 1; i < parsed_paths.size(); i++) {
		if (compare_windows_paths(parsed_paths[i - 1].first, parsed_paths[i].first) == CSTR_EQUAL) {
			error = "line " + std::to_string(parsed_paths[i].second) + " duplicates another Windows path";
			return false;
		}
	}
	for (const auto &entry : parsed_paths) {
		for (fs::path parent = entry.first.parent_path(); !parent.empty(); parent = parent.parent_path()) {
			if (parsed.find(parent.u8string()) != parsed.end()) {
				error = "line " + std::to_string(entry.second) + " has a parent path that is also a manifest file";
				return false;
			}
		}
	}

	output = std::move(parsed);
	return true;
}
