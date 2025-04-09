#include "utils.hpp"

#include <shellapi.h>
#include <fstream>
#include <iostream>
#include <sstream>

#include <boost/exception/all.hpp>

#include "logger/log.h"
#include "checksum-filters.hpp"
#include <boost/algorithm/string/replace.hpp>
#include <boost/locale.hpp>
#include <filesystem>

namespace fs = std::filesystem;

MultiByteCommandLine::MultiByteCommandLine(bool skip_load) {}

MultiByteCommandLine::MultiByteCommandLine()
{
	LPWSTR lpCommandLine = GetCommandLineW();
	LPWSTR *wargv = CommandLineToArgvW(lpCommandLine, &m_argc);
	m_argv = new LPSTR[m_argc];

	/* The glory of using an unreliably sized byte
	 * type to hold a 2-byte codepoint that practically
	 * no one in the universe wants to actaully use.
	 * If there's one thing I'd like Microsoft to
	 * change, it's their shitty integration with
	 * UTF-16LE (or UCS-2 as they call it).
	 * Anyways... this converts each UTF-16LE string
	 * to UTF-8 (or something it understands). */
	for (int i = 0; i < m_argc; ++i) {
		DWORD size = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, NULL, 0, NULL, NULL);

		m_argv[i] = new CHAR[size];

		size = WideCharToMultiByte(CP_UTF8, 0, wargv[i], -1, m_argv[i], size, NULL, NULL);
	}

	LocalFree(wargv);
}

MultiByteCommandLine::~MultiByteCommandLine()
{
	for (int i = 0; i < m_argc; ++i) {
		delete[] m_argv[i];
	}
	if (m_argv)
		delete[] m_argv;
}

std::string ConvertToUtf8(std::wstring from)
{
	int to_size = WideCharToMultiByte(CP_UTF8, 0, from.c_str(), -1, NULL, 0, NULL, NULL);

	std::string ret;
	ret.resize(to_size);

	int size = WideCharToMultiByte(CP_UTF8, 0, from.c_str(), -1, ret.data(), to_size, NULL, NULL);

	if (size == 0) {
		LogLastError(L"WideCharToMultiByte");
		return "";
	}
	ret.resize(strlen(ret.c_str())); //important to end string at 0
	return ret;
}

std::wstring ConvertToUtf16WS(std::string from)
{
	int to_size = MultiByteToWideChar(CP_UTF8, 0, from.c_str(), -1, NULL, 0);

	std::wstring ret;
	ret.resize(to_size);

	int size = MultiByteToWideChar(CP_UTF8, 0, from.c_str(), -1, ret.data(), to_size);

	if (size == 0) {
		LogLastError(L"MultiByteToWideChar");
		return L"";
	}

	return ret;
}

LPWSTR ConvertToUtf16LP(const char *from, int *from_size)
{
	int to_size = MultiByteToWideChar(CP_UTF8, 0, from, *from_size, NULL, 0);

	auto to = new WCHAR[to_size];

	int size = MultiByteToWideChar(CP_UTF8, 0, from, *from_size, to, to_size);

	if (size == 0) {
		*from_size = 0;
		LogLastError(L"MultiByteToWideChar");
		return NULL;
	}

	*from_size = to_size;

	return to;
}

bool is_system_folder(const fs::path &path)
{
	DWORD fileAttributes = GetFileAttributes(path.c_str());
	if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
		return false;
	}
	return fileAttributes & FILE_ATTRIBUTE_SYSTEM;
}

void LogLastError(LPCWSTR lpFunctionName)
{
	DWORD dwError = GetLastError();
	DWORD szMsgBuf = 1024;
	LPTSTR strMsgBuf = new wchar_t[szMsgBuf];

	FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS, NULL, dwError, 0, strMsgBuf, szMsgBuf, NULL);

	wlog_debug(L"%s: %.*s", lpFunctionName, szMsgBuf, strMsgBuf);

	delete[] strMsgBuf;
}

BOOL StartApplication(LPWSTR lpCommandLine, LPCWSTR lpWorkingDirectory)
{
	BOOL bSuccess;
	DWORD dwShellProcId;
	HANDLE hShellProc;
	HANDLE hShellToken;
	HANDLE hNewToken;
	STARTUPINFO xStartupInfo = {0};
	PROCESS_INFORMATION xProcInfo = {0};
	HWND hwndShell = GetShellWindow();

	if (hwndShell == NULL)
		return FALSE;

	GetWindowThreadProcessId(hwndShell, &dwShellProcId);

	hShellProc = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, dwShellProcId);

	if (hShellProc == NULL) {
		LogLastError(L"OpenProcess");
		return FALSE;
	}

	bSuccess = OpenProcessToken(hShellProc, TOKEN_DUPLICATE, &hShellToken);

	if (bSuccess == 0) {
		LogLastError(L"OpenProcessToken");
		return FALSE;
	}

	bSuccess = DuplicateTokenEx(hShellToken, TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL,
				    SecurityImpersonation, TokenPrimary, &hNewToken);

	if (bSuccess == 0) {
		LogLastError(L"DuplicateTokenEx");
		return FALSE;
	}

	bSuccess = CreateProcessWithTokenW(hNewToken, 0, NULL, lpCommandLine, 0, NULL, lpWorkingDirectory, &xStartupInfo, &xProcInfo);

	if (bSuccess == 0) {
		LogLastError(L"CreateProcessWithTokenW");
		return FALSE;
	}

	return TRUE;
}

BOOL StartApplication(const char *lpCommandLine, const char *lpWorkingDir)
{
	/* Convert UTF-8 command line back to UTF-16 */
	int dwCLSize = -1;
	LPWSTR lpWideCommandLine = ConvertToUtf16LP(lpCommandLine, &dwCLSize);
	LPWSTR lpWideWorkingDir;
	BOOL bSuccess = false;

	dwCLSize = -1;

	lpWideWorkingDir = ConvertToUtf16LP(lpWorkingDir, &dwCLSize);

	bSuccess = StartApplication(lpWideCommandLine, lpWideWorkingDir);

	if (!bSuccess) {
		HINSTANCE exec_result = ShellExecute(NULL, L"runas", lpWideCommandLine, nullptr, NULL, SW_SHOWNORMAL);

		int exec_result_code = static_cast<int>(reinterpret_cast<uintptr_t>(exec_result));

		if (exec_result_code >= 32) {
			bSuccess = true;
		} else {
			LogLastError(L"ShellExecute");
		}
	}

	delete lpWideCommandLine;
	delete lpWideWorkingDir;

	return bSuccess;
}

fs::path prepare_file_path(const fs::path &base, const std::string &target)
{
	fs::path file_path = "";
	try {
		file_path = base;

		std::string un_urled_path = unfixup_uri(target);
		file_path /= fs::u8path(un_urled_path.c_str());

		file_path.make_preferred();
		file_path.replace_extension();

		fs::create_directories(file_path.parent_path());

		fs::remove(file_path);
	} catch (fs::filesystem_error const &ex) {
		log_error("Creating a file path failed. Error %s", ex.what());
		log_error("Info: %s and %s", base.string().c_str(), target.c_str());
		file_path = "";
	} catch (...) {
		log_error("Creating a file path failed for %s", target.c_str());
		file_path = "";
	}

	return file_path;
}

std::string encimpl(std::string::value_type v)
{
	if (isascii(v))
		return std::string() + v;

	std::ostringstream enc;
	enc << '%' << std::setw(2) << std::setfill('0') << std::hex << std::uppercase << int(static_cast<unsigned char>(v));
	return enc.str();
}

std::string urlencode(const std::string &url)
{
	const std::string::const_iterator start = url.begin();

	std::vector<std::string> qstrs;

	std::transform(start, url.end(), std::back_inserter(qstrs), encimpl);

	std::ostringstream ostream;

	for (auto const &i : qstrs) {
		ostream << i;
	}

	return ostream.str();
}

std::string fixup_uri(const std::string &source)
{
	std::string result(source);

	const std::map<char, std::string> urlEncodeMap = {{' ', "%20"}, {'"', "%22"}, {'#', "%23"}, {'&', "%26"}, {'\'', "%27"}, {'(', "%28"},
							  {')', "%29"}, {'*', "%2A"}, {'+', "%2B"}, {',', "%2C"}, {':', "%3A"},  {';', "%3B"},
							  {'<', "%3C"}, {'=', "%3E"}, {'?', "%3F"}, {'@', "%40"}, {'[', "%5B"},  {']', "%5D"},
							  {'^', "%5E"}, {'`', "%60"}, {'{', "%7B"}, {'|', "%7C"}, {'}', "%7D"},  {'~', "%7E"}};
	boost::algorithm::replace_all(result, "\\", "/");
	boost::algorithm::replace_all(result, "%", "%25");
	for (const auto &pair : urlEncodeMap) {
		boost::algorithm::replace_all(result, std::string(1, pair.first), pair.second);
	}

	return result;
}

std::string unfixup_uri(const std::string &source)
{
	std::string result(source);

	// Map of URL-encoded strings to their character equivalents
	const std::map<std::string, char> urlDecodeMap = {{"%20", ' '}, {"%22", '"'}, {"%23", '#'}, {"%26", '&'}, {"%27", '\''}, {"%28", '('}, {"%29", ')'},
							  {"%2A", '*'}, {"%2B", '+'}, {"%2C", ','}, {"%3A", ':'}, {"%3B", ';'},  {"%3C", '<'}, {"%3E", '='},
							  {"%3F", '?'}, {"%40", '@'}, {"%5B", '['}, {"%5D", ']'}, {"%5E", '^'},  {"%60", '`'}, {"%7B", '{'},
							  {"%7C", '|'}, {"%7D", '}'}, {"%7E", '~'}, {"%25", '%'}};

	// Iterating over each encoded sequence in the map
	for (const auto &pair : urlDecodeMap) {
		boost::algorithm::replace_all(result, pair.first, std::string(1, pair.second));
	}

	// Replacing encoded backslash
	boost::algorithm::replace_all(result, "/", "\\");

	return result;
}

std::string calculate_files_checksum_safe(const fs::path &path)
{
	std::string checksum = "";
	try {
		checksum = calculate_files_checksum(path);
	} catch (const boost::exception &e) {
		log_warn("Failed to calculate checksum of local file. Exception: %s", boost::diagnostic_information(e).c_str());
	} catch (const std::exception &e) {
		log_warn("Failed to calculate checksum of local file. std::exception: %s", e.what());
	} catch (...) {
		wlog_warn(L"Failed to calculate checksum of local file. file: %s", path.c_str());
	}
	return checksum;
}

std::string calculate_files_checksum(const fs::path &path)
{
	std::ostringstream hex_digest;
	unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

	std::ifstream file(path, std::ios::in | std::ios::binary);
	if (file.is_open()) {
		SHA256_CTX sha256;
		SHA256_Init(&sha256);

		unsigned char buffer[4096];
		while (true) {
			file.read((char *)buffer, 4096);
			std::streamsize read_byte = file.gcount();
			if (read_byte != 0) {
				SHA256_Update(&sha256, buffer, read_byte);
			}
			if (!file.good()) {
				break;
			}
		}

		SHA256_Final(hash, &sha256);

		file.close();

		hex_digest << std::nouppercase << std::setfill('0') << std::hex;

		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
			hex_digest << std::setw(2) << static_cast<unsigned int>(hash[i]);
		}
	}

	return hex_digest.str();
}

std::vector<char> get_messages_callback(std::string const &file_name, std::string const &encoding)
{
	static std::unordered_map<std::string, int> locales_resources(
		{{"/ar_SA/LC_MESSAGES/messages.mo", 101}, {"/cs_CZ/LC_MESSAGES/messages.mo", 102}, {"/da_DK/LC_MESSAGES/messages.mo", 103},
		 {"/de_DE/LC_MESSAGES/messages.mo", 104}, {"/en_US/LC_MESSAGES/messages.mo", 105}, {"/es_ES/LC_MESSAGES/messages.mo", 106},
		 {"/fr_FR/LC_MESSAGES/messages.mo", 107}, {"/hu_HU/LC_MESSAGES/messages.mo", 108}, {"/id_ID/LC_MESSAGES/messages.mo", 109},
		 {"/it_IT/LC_MESSAGES/messages.mo", 110}, {"/ja_JP/LC_MESSAGES/messages.mo", 111}, {"/ko_KR/LC_MESSAGES/messages.mo", 112},
		 {"/mk_MK/LC_MESSAGES/messages.mo", 113}, {"/nl_NL/LC_MESSAGES/messages.mo", 114}, {"/pl_PL/LC_MESSAGES/messages.mo", 115},
		 {"/pt_BR/LC_MESSAGES/messages.mo", 116}, {"/pt_PT/LC_MESSAGES/messages.mo", 117}, {"/ru_RU/LC_MESSAGES/messages.mo", 118},
		 {"/sk_SK/LC_MESSAGES/messages.mo", 119}, {"/sl_SI/LC_MESSAGES/messages.mo", 120}, {"/sv_SE/LC_MESSAGES/messages.mo", 121},
		 {"/th_TH/LC_MESSAGES/messages.mo", 122}, {"/tr_TR/LC_MESSAGES/messages.mo", 123}, {"/vi_VN/LC_MESSAGES/messages.mo", 124},
		 {"/zh_CN/LC_MESSAGES/messages.mo", 125}, {"/zh_TW/LC_MESSAGES/messages.mo", 126}});
	std::vector<char> localization;

	HMODULE hmodule = GetModuleHandle(NULL);
	if (hmodule) {
		HRSRC res;
		auto res_id = locales_resources.at(file_name);
		res = FindResource(hmodule, MAKEINTRESOURCEW(res_id), L"BINARY");
		if (res) {
			HGLOBAL res_load;
			res_load = LoadResource(hmodule, res);
			if (res_load) {
				LPVOID res_memory;
				res_memory = LockResource(res_load);
				if (res_memory) {
					size_t file_size = SizeofResource(hmodule, res);
					localization.resize(file_size);
					memcpy(localization.data(), res_memory, file_size);
				}
			}
			FreeResource(res_load);
		}
	}

	return localization;
}

void setup_locale()
{
	const char *current_locale = std::setlocale(LC_ALL, nullptr);
	if (current_locale == nullptr || std::strlen(current_locale) == 0) {
		std::setlocale(LC_ALL, "en_US.UTF-8");
	}

	namespace blg = boost::locale::gnu_gettext;
	blg::messages_info info;

	info.paths.push_back("");
	info.domains.push_back(blg::messages_info::domain("messages"));
	info.callback = get_messages_callback;

	boost::locale::generator gen;
	std::locale base_locale = gen("");

	boost::locale::info const &properties = std::use_facet<boost::locale::info>(base_locale);
	info.language = properties.language();
	info.country = properties.country();
	info.encoding = properties.encoding();
	info.variant = properties.variant();

	std::locale real_locale(base_locale, blg::create_messages_facet<char>(info));
	std::locale::global(real_locale);
}
