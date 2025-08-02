
#include <iostream>
#include <fstream>
#include <iomanip>
#include <boost/bind/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl/error.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/asio/ssl.hpp>
#include <tlhelp32.h>
#include <psapi.h>
#include "utils.hpp"

#include <memory>

#include "crash-reporter.hpp"
#include "update-parameters.hpp"

using boost::asio::ip::tcp;

#ifdef SENTRY_HOST_NAME
const std::string host = SENTRY_HOST_NAME;
const std::string protocol = "https";
#else
const std::string host = "sentry.io";
const std::string protocol = "https";
std::string last_error_type = "";
//const std::string protocol = "1443";
//const std::string host = "127.0.0.1";
#endif

#if !defined(SENTRY_PROJECT_KEY) || !defined(SENTRY_PROJECT_ID)
#error "sentry project info not provided"
#endif
const std::string api_path_minidump = "/api/" SENTRY_PROJECT_ID "/minidump/";
const std::string api_path_store = "/api/" SENTRY_PROJECT_ID "/store/";

const bool send_manual_backtrace = false;
std::wstring minidump_filenamew = L"MiniDump.dmp";
std::string minidump_filename = "MiniDump.dmp";

extern bool update_completed;
extern struct update_parameters params;

bool report_unsuccessful = false;

std::time_t app_start_timestamp;

std::string get_uuid() noexcept;
std::string get_timestamp() noexcept;
std::string get_logs_json() noexcept;

double get_time_from_start() noexcept;

std::string prepare_crash_report(struct _EXCEPTION_POINTERS *ExceptionInfo, std::string minidump_result) noexcept;
int send_crash_to_sentry_sync(const std::string &report_json, bool send_minidump) noexcept;

void save_start_timestamp();
std::string get_command_line() noexcept;
std::string get_current_dir() noexcept;
std::string get_parent_process_path(bool only_first_parent) noexcept;

void handle_exit() noexcept;
void handle_crash(struct _EXCEPTION_POINTERS *ExceptionInfo, bool callAbort = true) noexcept;

void print_stacktrace_sym(CONTEXT *ctx, std::ostringstream &report_stream) noexcept; //Prints stack trace based on context record

std::string create_mini_dump(EXCEPTION_POINTERS *pep) noexcept;

std::string escapeJsonString(const std::string &input) noexcept;
std::string get_version();
std::string GetWindowsVersionString();

#include "dbghelp.h"
#pragma comment(lib, "Dbghelp.lib")

std::string prepare_crash_report(struct _EXCEPTION_POINTERS *ExceptionInfo, std::string minidump_result) noexcept
{
	std::ostringstream json_report;

	json_report << "{";
	json_report << "	\"event_id\": \"" << get_uuid() << "\", ";
	json_report << "	\"release\": \"" << get_version() << "\", ";
	json_report << "	\"timestamp\": \"" << get_timestamp() << "\", ";
	if (send_manual_backtrace) {
		json_report << "	\"exception\": {\"values\":[{";
		if (ExceptionInfo) {
			json_report << "		\"type\": \"" << ExceptionInfo->ExceptionRecord->ExceptionCode << "\", ";
		}
		json_report << "		\"thread_id\": \"" << std::this_thread::get_id() << "\", ";

		if (ExceptionInfo) {
			std::string method;
			json_report << "		\"stacktrace\": { \"frames\" : [";
			print_stacktrace_sym(ExceptionInfo->ContextRecord, json_report);
			json_report << "		] } ";
		}
		json_report << "	}]}, ";
	} else if (!ExceptionInfo && minidump_result.size() == 0) {
		json_report << "	\"exception\": [{";
		json_report << "		\"type\": \"" << last_error_type << "\", ";
		json_report << "		\"value\": \"" << last_error_type << "\" ";
		json_report << "	}], ";
	}
	json_report << "	\"tags\": { ";
	json_report << "		\"app_build_timestamp\": \"" << __DATE__ << " " << __TIME__ << "\", ";
	if (!minidump_result.size())
		json_report << "		\"report_type\": \""
			    << "catched_error"
			    << "\", ";
	json_report << "		\"updater_version\": \"" << get_version() << "\", ";
	json_report << "		\"os_version\": \"" << GetWindowsVersionString() << "\" ";
	json_report << "	}, ";
	json_report << "	\"extra\": { ";
	json_report << "		\"app_run_time\": \"" << get_time_from_start() << "\", ";
	json_report << "		\"app_logs_listing\": " << get_logs_json() << " , ";
	if (minidump_result.size())
		json_report << "		\"minidump_result\": \"" << minidump_result << "\", ";
	json_report << "		\"console_args\": \"" << get_command_line() << "\", ";
	json_report << "		\"current_dir\": \"" << get_current_dir() << "\", ";
	json_report << "		\"parent_process\": \"" << get_parent_process_path(false) << "\" ";
	json_report << "	}, ";
	json_report << "	\"user\": { ";
	json_report << "		\"ip_address\": \"{{auto}}\" ";
	json_report << "	} ";
	json_report << "}";

	return json_report.str();
}

std::string get_current_dir() noexcept
{
	WCHAR path_buffer[MAX_PATH];
	DWORD lenght = GetCurrentDirectoryW(MAX_PATH, &path_buffer[0]);
	if (lenght == 0)
		return "";
	std::string ret = ConvertToUtf8(std::wstring(path_buffer, lenght));
	ret = escapeJsonString(ret);
	return ret;
}

bool is_launched_by_explorer()
{
	std::string parent_path = get_parent_process_path(true);

	const std::string explorer_exe = "explorer.exe";
	if (parent_path.size() >= explorer_exe.size())
		return std::equal(explorer_exe.rbegin(), explorer_exe.rend(), parent_path.rbegin(), [](char a, char b) { return tolower(a) == tolower(b); });

	return false;
}

std::string get_version()
{
	std::string version = "0.0.0-dev";
#ifdef RELEASE_VERSION
	version = std::string(RELEASE_VERSION);
#endif
	return version;
}

std::string GetWindowsVersionString()
{
	DWORD dwHandle;
	VS_FIXEDFILEINFO *pFixedFileInfo;
	UINT uLen;
	std::ostringstream oss;

	DWORD dwSize = GetFileVersionInfoSize(TEXT("kernel32.dll"), &dwHandle);
	BYTE *pBuffer = new BYTE[dwSize];

	if (GetFileVersionInfo(TEXT("kernel32.dll"), dwHandle, dwSize, pBuffer)) {
		if (VerQueryValue(pBuffer, TEXT("\\"), (LPVOID *)&pFixedFileInfo, &uLen)) {
			DWORD dwFileVersionMS = pFixedFileInfo->dwFileVersionMS;
			DWORD dwFileVersionLS = pFixedFileInfo->dwFileVersionLS;

			DWORD dwMajorVersion = HIWORD(dwFileVersionMS);
			DWORD dwMinorVersion = LOWORD(dwFileVersionMS);
			DWORD dwBuildNumber = HIWORD(dwFileVersionLS);
			DWORD dwRevisionNumber = LOWORD(dwFileVersionLS);

			oss << "Windows:" << dwMajorVersion << "." << dwMinorVersion << " (build " << dwBuildNumber << "." << dwRevisionNumber << ")";
		} else {
			oss << "Windows:unknown";
		}

	} else {
		oss << "Windows:unknown";
	}

	delete[] pBuffer;

	return oss.str();
}

std::string get_parent_process_path(bool only_first_parent) noexcept
{
	std::wstring parent_path;
	HANDLE hSnapshot;
	PROCESSENTRY32 pe32;
	DWORD pid = GetCurrentProcessId();
	std::vector<DWORD> parents_pids;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

	if (hSnapshot != INVALID_HANDLE_VALUE) {
		DWORD last_ppid = pid;
		bool found = false;
		do {
			found = false;
			ZeroMemory(&pe32, sizeof(pe32));
			pe32.dwSize = sizeof(pe32);
			if (Process32First(hSnapshot, &pe32)) {
				do {
					if (pe32.th32ProcessID == last_ppid) {
						last_ppid = pe32.th32ParentProcessID;
						found = true;
						parents_pids.push_back(last_ppid);
						break;
					}
				} while (Process32Next(hSnapshot, &pe32));
			} else
				break;
		} while (found && !only_first_parent);
		CloseHandle(hSnapshot);
	}

	if (parents_pids.size() > 0) {
		for (DWORD ppid : parents_pids) {
			HANDLE parent_handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, ppid);
			if (parent_handle) {
				WCHAR path_buffer[MAX_PATH];
				DWORD lenght = GetModuleFileNameEx(parent_handle, 0, path_buffer, MAX_PATH);
				if (lenght) {
					parent_path += std::wstring(path_buffer, lenght);
				} else {
					parent_path += std::to_wstring(ppid);
				}
				CloseHandle(parent_handle);
			} else {
				parent_path += std::to_wstring(ppid);
			}

			if (only_first_parent)
				break;

			parent_path += L" => ";
		}
	} else
		parent_path = L"No parent pid found";
	std::string ret = ConvertToUtf8(parent_path);
	ret = escapeJsonString(ret);
	return ret;
}

std::string create_mini_dump(EXCEPTION_POINTERS *pep) noexcept
{
	std::string ret = "successfully";

	HANDLE hFile = CreateFile(minidump_filenamew.c_str(), GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);

	if ((hFile != NULL) && (hFile != INVALID_HANDLE_VALUE)) {
		MINIDUMP_EXCEPTION_INFORMATION mdei = {0};

		mdei.ThreadId = GetCurrentThreadId();
		mdei.ExceptionPointers = pep;
		mdei.ClientPointers = TRUE;

		const DWORD CD_Flags = MiniDumpWithDataSegs | MiniDumpWithHandleData | MiniDumpScanMemory | MiniDumpWithUnloadedModules |
				       MiniDumpWithIndirectlyReferencedMemory | MiniDumpWithPrivateReadWriteMemory | MiniDumpWithFullMemoryInfo |
				       MiniDumpWithThreadInfo | MiniDumpIgnoreInaccessibleMemory;

		BOOL rv = MiniDumpWriteDump(GetCurrentProcess(), GetCurrentProcessId(), hFile, (MINIDUMP_TYPE)CD_Flags, (pep != 0) ? &mdei : 0, 0, 0);
		if (!rv) {
			ret = "failed to generate minidump: " + std::to_string(GetLastError());
		}

		CloseHandle(hFile);
	} else {
		ret = "failed to create file: " + std::to_string(GetLastError());
	}
	return ret;
}

int send_crash_to_sentry_sync(const std::string &report_json, bool send_minidump = true) noexcept
{
	try {
		boost::asio::ssl::context context(boost::asio::ssl::context::tls_client);
		context.set_options(boost::asio::ssl::context::default_workarounds | boost::asio::ssl::context::no_sslv2 | boost::asio::ssl::context::no_sslv3 |
				    boost::asio::ssl::context::no_tlsv1 | boost::asio::ssl::context::no_tlsv1_1);
		context.set_default_verify_paths();

		boost::asio::io_service io_service;
		boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl_socket(io_service, context);

		tcp::resolver resolver(io_service);
		tcp::resolver::query query(host, protocol);
		tcp::resolver::iterator endpoint_iterator = resolver.resolve(query);
		tcp::resolver::iterator end;

		tcp::socket socket(io_service);
		boost::system::error_code error = boost::asio::error::host_not_found;
		while (error && endpoint_iterator != end) {
			ssl_socket.lowest_layer().close();
			boost::asio::connect(ssl_socket.lowest_layer(), endpoint_iterator, error);
			if (error) {
				++endpoint_iterator;
				continue;
			}

			if (SSL_set_tlsext_host_name(ssl_socket.native_handle(), host.c_str()) != 1) {
				error = boost::system::error_code(static_cast<int>(::ERR_get_error()), boost::asio::error::get_ssl_category());
				++endpoint_iterator;
				continue;
			}

			ssl_socket.set_verify_mode(boost::asio::ssl::verify_none);

			try {
				ssl_socket.handshake(boost::asio::ssl::stream_base::client);
			} catch (const boost::system::system_error &e) {
				error = e.code();
				++endpoint_iterator;
				continue;
			}

			error.clear();
			break;
		}
		if (error) {
			throw boost::system::system_error(error);
		}

		long long minidump_file_size = 0L;

		const std::string PREFIX = "--";
		const std::string BOUNDARY = get_uuid();
		const std::string NEWLINE = "\r\n";
		const size_t NEWLINE_LENGTH = NEWLINE.length();
		if (send_minidump) {
			try {
				minidump_file_size = fs::file_size(minidump_filename);
			} catch (...) {
				minidump_file_size = 0;
			}
			//Calculate length of entire HTTP request - goes into header
			long long lengthOfRequest = 0;
			lengthOfRequest += PREFIX.length() + BOUNDARY.length() + NEWLINE_LENGTH;
			lengthOfRequest += (std::string("Content-Disposition: form-data; name=\"upload_file_minidump\"; filename=\"") + minidump_filename +
					    std::string("\""))
						   .length();
			lengthOfRequest += NEWLINE_LENGTH + NEWLINE_LENGTH;
			lengthOfRequest += minidump_file_size;
			lengthOfRequest += NEWLINE_LENGTH + PREFIX.length() + BOUNDARY.length() + NEWLINE_LENGTH;

			lengthOfRequest += std::string("Content-Disposition: form-data; name=\"sentry\"").length();
			lengthOfRequest += NEWLINE_LENGTH + NEWLINE_LENGTH;
			lengthOfRequest += report_json.size();
			lengthOfRequest += NEWLINE_LENGTH + PREFIX.length() + BOUNDARY.length() + PREFIX.length() + NEWLINE_LENGTH; // + NEWLINE_LENGTH;

			boost::asio::streambuf request;
			std::ostream request_stream(&request);

			request_stream << "POST " << api_path_minidump << " HTTP/1.1" << NEWLINE;
			request_stream << "Host: " << host << NEWLINE;
			request_stream << "Accept: *" << NEWLINE;
			request_stream << "User-Agent: slobs_updater " << NEWLINE;
			request_stream << "Accept-encoding: 'br'" << NEWLINE;
			request_stream << "Accept-language: 'en-US,en;q=0.9,ru;q=0.8'" << NEWLINE;
			request_stream << "Connection: close" << NEWLINE;
			request_stream << "X-Sentry-Auth: Sentry sentry_version=5,sentry_client=slobs_updater/";
			request_stream << "1.0.0"
				       << ",sentry_timestamp=" << get_timestamp();
			request_stream << ",sentry_key=" << SENTRY_PROJECT_KEY;
			request_stream << ",sentry_secret="
				       << "654ed1db5d93495284f66f3d6d195790";
			request_stream << NEWLINE;

			request_stream << "Content-Length: " << lengthOfRequest << NEWLINE;
			request_stream << "Content-Type: multipart/form-data; boundary=" << BOUNDARY;
			request_stream << NEWLINE << NEWLINE;
			request_stream << PREFIX << BOUNDARY;
			request_stream << NEWLINE;
			request_stream << "Content-Disposition: form-data; name=\"upload_file_minidump\"; filename=\"" << minidump_filename << "\"";
			request_stream << NEWLINE << NEWLINE;
			boost::asio::write(ssl_socket, request);

			const long long minidump_buf_size = 1024 * 8;
			static char minidump_buf[minidump_buf_size];
			long long bytes_read = 0;
			long long total_bytes_sent = 0;

			try {
				std::ifstream is(minidump_filename.c_str(), std::ios::in | std::ios::binary);

				while ((bytes_read = is.read(minidump_buf, minidump_buf_size).gcount()) > 0) {
					boost::asio::write(ssl_socket, boost::asio::buffer(minidump_buf, bytes_read));
					total_bytes_sent += bytes_read;
				}
			} catch (...) {
			}

			if (total_bytes_sent < minidump_file_size) {
				memset(minidump_buf, 0x00, minidump_buf_size);
				size_t bytes_to_send = 0;
				while (bytes_to_send = std::min(minidump_buf_size, total_bytes_sent) > 0) {
					total_bytes_sent -= bytes_to_send;
					boost::asio::write(ssl_socket, boost::asio::buffer(minidump_buf, bytes_to_send));
				}
			}

			boost::asio::streambuf request_end;
			std::ostream request_stream_end(&request_end);
			request_stream_end << NEWLINE;
			request_stream_end << PREFIX << BOUNDARY;
			request_stream_end << NEWLINE;

			request_stream_end << "Content-Disposition: form-data; name=\"sentry\"";
			request_stream_end << NEWLINE << NEWLINE;
			request_stream_end << report_json;
			request_stream_end << NEWLINE;
			request_stream_end << PREFIX << BOUNDARY;
			request_stream_end << PREFIX;
			request_stream_end << NEWLINE;
			boost::asio::write(ssl_socket, request_end);
		} else {
			boost::asio::streambuf request;
			std::ostream request_stream(&request);

			request_stream << "POST " << api_path_store << " HTTP/1.1" << NEWLINE;
			request_stream << "Host: " << host << NEWLINE;
			request_stream << "Accept: *" << NEWLINE;
			request_stream << "Accept-encoding: 'br'" << NEWLINE;
			request_stream << "Accept-language: 'en-US,en;q=0.9,ru;q=0.8'" << NEWLINE;
			request_stream << "Connection: close" << NEWLINE;
			request_stream << "X-Sentry-Auth: Sentry sentry_version=5,sentry_client=slobs_updater/";
			request_stream << "1.0.0"
				       << ",sentry_timestamp=" << get_timestamp();
			request_stream << ",sentry_key=" << SENTRY_PROJECT_KEY;
			request_stream << ",sentry_secret="
				       << "654ed1db5d93495284f66f3d6d195790";
			request_stream << NEWLINE;
			request_stream << "Content-Type: application/json" << NEWLINE;
			request_stream << "Content-Length: " << report_json.length() << NEWLINE;
			request_stream << NEWLINE;
			request_stream << report_json;

			// Send the request.
			boost::asio::write(ssl_socket, request);
		}

		// Read the response status line.
		boost::asio::streambuf response;
		boost::asio::read_until(ssl_socket, response, "\r\n");

		// Check that response is OK.
		std::istream response_stream(&response);
		std::string http_version;
		response_stream >> http_version;
		unsigned int status_code;
		response_stream >> status_code;

		std::string status_message;
		std::getline(response_stream, status_message);

		if (!response_stream || http_version.substr(0, 5) != "HTTP/") {
		} else {
			// Read the response headers, which are terminated by a blank line.
			boost::asio::read_until(ssl_socket, response, "\r\n\r\n");

			// Process the response headers.
			// Not much we can do if sentry response with error.
			// Just read data to make connection finish correctly
			std::string header;
			while (std::getline(response_stream, header) && header != "\r\n") {
			}

			if (response.size() > 0) {
			}

			// Read until EOF, checking data as we go.
			while (boost::asio::read(ssl_socket, response, boost::asio::transfer_at_least(1), error)) {
			}

			if (error != boost::asio::error::eof) {
				throw boost::system::system_error(error);
			}
		}

	} catch (const std::exception &) {
		//have to ignore exceptions as programm is in reporting exception already
	}

	return 0;
}

void handle_crash(struct _EXCEPTION_POINTERS *ExceptionInfo, bool callAbort) noexcept
{
	static bool insideCrashMethod = false;
	if (insideCrashMethod) {
		abort();
	}
	insideCrashMethod = true;

	std::string minidump_result = create_mini_dump(ExceptionInfo);

	std::string report = prepare_crash_report(ExceptionInfo, minidump_result);

	send_crash_to_sentry_sync(report);

	DeleteFile(minidump_filenamew.c_str());

	if (callAbort) {
		abort();
	}

	insideCrashMethod = false;
}

void handle_exit() noexcept
{
	std::string report = prepare_crash_report(nullptr, "");

	send_crash_to_sentry_sync(report, false);
}

void save_exit_error(const std::string &error_type) noexcept
{
	last_error_type = error_type;
}

void print_stacktrace_sym(CONTEXT *ctx, std::ostringstream &report_stream) noexcept
{
	BOOL result;
	HANDLE process;
	HANDLE thread;
	HMODULE hModule;

	STACKFRAME64 stack;
	ULONG frame;
	DWORD64 displacement;

	DWORD disp;
	IMAGEHLP_LINE64 *line;
	const int MaxNameLen = 256;

	char buffer[sizeof(SYMBOL_INFO) + MAX_SYM_NAME * sizeof(TCHAR)];
	char module[MaxNameLen];
	PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)buffer;

	memset(&stack, 0, sizeof(STACKFRAME64));

	process = GetCurrentProcess();
	thread = GetCurrentThread();
	displacement = 0;
#if !defined(_M_AMD64)
	stack.AddrPC.Offset = (*ctx).Eip;
	stack.AddrPC.Mode = AddrModeFlat;
	stack.AddrStack.Offset = (*ctx).Esp;
	stack.AddrStack.Mode = AddrModeFlat;
	stack.AddrFrame.Offset = (*ctx).Ebp;
	stack.AddrFrame.Mode = AddrModeFlat;
#endif

	SymInitialize(process, NULL, TRUE);
	bool first_element = true;
	for (frame = 0;; frame++) {
		//get next call from stack
		result = StackWalk64(
#if defined(_M_AMD64)
			IMAGE_FILE_MACHINE_AMD64
#else
			IMAGE_FILE_MACHINE_I386
#endif
			,
			process, thread, &stack, ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL);

		if (!result)
			break;

		if (!first_element) {
			report_stream << ",";
		}
		report_stream << " { ";

		//get symbol name for address
		pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
		pSymbol->MaxNameLen = MAX_SYM_NAME;
		if (SymFromAddr(process, (ULONG64)stack.AddrPC.Offset, &displacement, pSymbol)) {
			line = (IMAGEHLP_LINE64 *)malloc(sizeof(IMAGEHLP_LINE64));
			line->SizeOfStruct = sizeof(IMAGEHLP_LINE64);

			report_stream << " 	\"function\": \"" << pSymbol->Name << "\", ";
			report_stream << " 	\"instruction_addr\": \""
				      << "0x" << std::uppercase << std::setfill('0') << std::setw(12) << std::hex << pSymbol->Address << "\", ";
			if (SymGetLineFromAddr64(process, stack.AddrPC.Offset, &disp, line)) {
				report_stream << " 	\"lineno\": \"" << line->LineNumber << "\", ";
				std::string file_name = line->FileName;
				file_name = escapeJsonString(file_name);
				report_stream << " 	\"filename\": \"" << file_name << "\", ";
			} else {
				//failed to get line number
			}
			free(line);
			line = NULL;
		} else {
			report_stream << " 	\"function\": \""
				      << "unknown"
				      << "\", ";
			report_stream << " 	\"instruction_addr\": \""
				      << "0x" << std::uppercase << std::setfill('0') << std::setw(12) << std::hex << (ULONG64)stack.AddrPC.Offset << "\", ";
		}

		hModule = NULL;
		lstrcpyA(module, "");
		if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCTSTR)(stack.AddrPC.Offset),
				      &hModule)) {
			if (hModule != NULL) {
				if (GetModuleFileNameA(hModule, module, MaxNameLen)) {
					std::string module_name = module;
					module_name = escapeJsonString(module_name);
					report_stream << " 	\"module\": \"" << module_name << "\" ";
				}
			}
		}

		first_element = false;
		report_stream << " } ";
	}
}

void save_start_timestamp()
{
	std::time(&app_start_timestamp);
}

double get_time_from_start() noexcept
{
	time_t current_time;
	time(&current_time);
	return difftime(current_time, app_start_timestamp);
}

std::string get_command_line() noexcept
{
	std::string ret = "empty";
	LPWSTR lpCommandLine = GetCommandLine();
	if (lpCommandLine != nullptr) {
		std::wstring ws_args = std::wstring(lpCommandLine);
		ret = escapeJsonString(ConvertToUtf8(ws_args));
	}
	return ret;
}

void setup_crash_reporting()
{
	save_start_timestamp();

	std::set_terminate([]() { handle_crash(nullptr); });

	SetUnhandledExceptionFilter([](struct _EXCEPTION_POINTERS *ExceptionInfo) {
		/* don't use if a debugger is present */
		if (IsDebuggerPresent()) {
			return LONG(EXCEPTION_CONTINUE_SEARCH);
		}

		handle_crash(ExceptionInfo);

		// Unreachable statement
		return LONG(EXCEPTION_CONTINUE_SEARCH);
	});
}

std::string get_logs_json() noexcept
{
	std::list<std::string> last_logs;
	try {
		std::ifstream logfile(params.log_file_path);

		std::string logline;
		while (std::getline(logfile, logline)) {
			last_logs.push_back(std::string("\"") + escapeJsonString(logline) + std::string("\""));
			if (last_logs.size() > 100) {
				last_logs.pop_front();
			}
		}

	} catch (...) {
		return std::string(" \"failed to read logs\" ");
	}

	std::ostringstream ss;
	bool first_line = true;

	ss << " [ ";
	for (auto const &logline : last_logs) {
		if (first_line) {
			first_line = false;
		} else {
			ss << ", \n";
		}

		ss << logline;
	}
	ss << " ] \n";

	return ss.str();
}

std::string get_timestamp() noexcept
{
	char buf[sizeof "xxxx-xx-xxTxx:xx:xxx\0"];
	std::time_t curent_time;

	std::time(&curent_time);
	std::strftime(buf, sizeof buf, "%Y-%m-%dT%H:%M:%SZ", std::gmtime(&curent_time));

	return std::string(buf);
}

std::string get_uuid() noexcept
{
	char result[33] = {'\0'}; //"fc6d8c0c43fc4630ad850ee518f1b9d0";
	std::srand(static_cast<unsigned int>(std::time(nullptr)));

	for (std::size_t i = 0; i < sizeof(result) - 1; ++i) {
		const auto r = static_cast<char>(std::rand() % 16);
		if (r < 10) {
			result[i] = '0' + r;
		} else {
			result[i] = 'a' + r - static_cast<char>(10);
		}
	}

	return std::string(result);
}

std::string escapeJsonString(const std::string &input) noexcept
{
	std::ostringstream ss;
	for (auto iter = input.cbegin(); iter != input.cend(); iter++) {
		switch (*iter) {
		case '\\':
			ss << "\\\\";
			break;
		case '"':
			ss << "\\\"";
			break;
		case '/':
			ss << "\\/";
			break;
		case '\b':
			ss << "\\b";
			break;
		case '\f':
			ss << "\\f";
			break;
		case '\n':
			ss << "\\n";
			break;
		case '\r':
			ss << "\\r";
			break;
		case '\t':
			ss << "\\t";
			break;
		default:
			ss << *iter;
			break;
		}
	}
	return ss.str();
}