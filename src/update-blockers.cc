#include "update-blockers.hpp"
#include "logger/log.h"

#include <algorithm>
#include <tlhelp32.h>
#include <unordered_map>

#pragma comment(lib, "Rstrtmgr.lib")
#pragma comment(lib, "Version.lib")

bool is_virtualcam_file(const fs::path &relative_path)
{
	std::wstring filename = relative_path.filename().wstring();
	std::transform(filename.begin(), filename.end(), filename.begin(), ::towlower);
	return filename == L"obs-virtualcam-module64.dll" ||
	       filename == L"obs-virtualcam-module32.dll";
}

bool get_blockers_list(fs::path &check_path, blockers_map_t &blockers)
{
	bool ret = false;

	DWORD dwSession = 0;
	WCHAR szSessionKey[CCH_RM_SESSION_KEY + 1] = {0};
	DWORD dwError;

	dwError = RmStartSession(&dwSession, 0, szSessionKey);

	if (dwError == ERROR_SUCCESS) {
		PCWSTR pszFile = check_path.native().c_str();
		dwError = RmRegisterResources(dwSession, 1, &pszFile, 0, NULL, 0, NULL);

		if (dwError == ERROR_SUCCESS) {
			DWORD dwReason = 0;
			UINT nProcInfoNeeded;
			UINT nProcInfo = 1;
			RM_PROCESS_INFO *rgpi = nullptr;

			dwError = ERROR_MORE_DATA;

			while (dwError != ERROR_SUCCESS) {
				if (rgpi != nullptr) {
					delete[] rgpi;
					rgpi = nullptr;
				}

				rgpi = new RM_PROCESS_INFO[nProcInfo];
				dwError = RmGetList(dwSession, &nProcInfoNeeded, &nProcInfo, rgpi, &dwReason);

				if (dwError != ERROR_MORE_DATA) {
					break;
				}
				nProcInfo = nProcInfoNeeded;
			}

			if (dwError == ERROR_SUCCESS) {
				for (unsigned int i = 0; i < nProcInfo; i++) {
					std::unique_lock<std::mutex> ulock(blockers.mtx);
					blockers.list.insert({rgpi[i].Process.dwProcessId, rgpi[i]});
				}

				ret = true;
			} else {
				if (dwError == 5) {
					RM_PROCESS_INFO unknown_locker_process;
					unknown_locker_process.Process.dwProcessId = 0;
					const WCHAR *unknown_name = L"Unknown Process\0";
					memcpy(unknown_locker_process.strAppName, unknown_name, 32);

					std::unique_lock<std::mutex> ulock(blockers.mtx);
					blockers.list.insert({unknown_locker_process.Process.dwProcessId, unknown_locker_process});
					ret = true;
				}
				log_debug("RmGetList for (%s) returned %d", check_path.u8string().c_str(), dwError);
			}

			if (rgpi != nullptr) {
				delete[] rgpi;
				rgpi = nullptr;
			}
		} else {
			log_debug("RmRegisterResources(%ls) returned %d", check_path.u8string().c_str(), dwError);
		}

		RmEndSession(dwSession);
	} else {
		log_error("RmStartSession returned %d", dwError);
	}

	return ret;
}

bool get_blockers_names(blockers_map_t &blockers)
{
	bool ret = true;
	/*
	//for each blockers 
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, rgpi[i].Process.dwProcessId);

	if (hProcess)
	{
		FILETIME ftCreate, ftExit, ftKernel, ftUser;
		if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser) && CompareFileTime(&rgpi[i].Process.ProcessStartTime, &ftCreate) == 0)
		{
			WCHAR sz[MAX_PATH];
			DWORD cch = MAX_PATH;
			if (QueryFullProcessImageNameW(hProcess, 0, sz, &cch) && cch <= MAX_PATH)
			{
				wprintf(L"%d.Process.Name = %ls\n", i, sz);
			}
		}
		CloseHandle(hProcess);
	}
	*/
	return ret;
}

struct find_window_data {
	DWORD pid;
	bool found;
};

static BOOL CALLBACK find_visible_window_cb(HWND hwnd, LPARAM lParam)
{
	auto *data = reinterpret_cast<find_window_data *>(lParam);
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);

	if (pid == data->pid && IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == NULL) {
		data->found = true;
		return FALSE;
	}
	return TRUE;
}

static std::wstring get_file_description(const std::wstring &exe_path)
{
	if (exe_path.empty())
		return {};

	DWORD dummy = 0;
	DWORD size = GetFileVersionInfoSizeW(exe_path.c_str(), &dummy);
	if (size == 0)
		return {};

	std::vector<BYTE> buffer(size);
	if (!GetFileVersionInfoW(exe_path.c_str(), 0, size, buffer.data()))
		return {};

	struct LANGANDCODEPAGE {
		WORD wLanguage;
		WORD wCodePage;
	} *translations = nullptr;
	UINT trans_size = 0;

	if (!VerQueryValueW(buffer.data(), L"\\VarFileInfo\\Translation", (LPVOID *)&translations, &trans_size) || trans_size < sizeof(*translations))
		return {};

	wchar_t sub_block[64];
	swprintf(sub_block, 64, L"\\StringFileInfo\\%04x%04x\\FileDescription", translations[0].wLanguage, translations[0].wCodePage);

	LPWSTR description = nullptr;
	UINT desc_len = 0;
	if (VerQueryValueW(buffer.data(), sub_block, (LPVOID *)&description, &desc_len) && desc_len > 0)
		return std::wstring(description);

	return {};
}

std::vector<blocker_info> get_blocker_details(blockers_map_t &blockers)
{
	std::vector<blocker_info> all_entries;
	std::unique_lock<std::mutex> ulock(blockers.mtx);

	for (auto &entry : blockers.list) {
		blocker_info info;
		info.pid = entry.first;
		info.app_name = entry.second.strAppName;
		info.has_window = false;

		if (info.pid != 0) {
			HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
			if (hProcess) {
				FILETIME ftCreate, ftExit, ftKernel, ftUser;
				if (GetProcessTimes(hProcess, &ftCreate, &ftExit, &ftKernel, &ftUser) &&
				    CompareFileTime(&entry.second.Process.ProcessStartTime, &ftCreate) == 0) {
					WCHAR sz[MAX_PATH];
					DWORD cch = MAX_PATH;
					if (QueryFullProcessImageNameW(hProcess, 0, sz, &cch) && cch <= MAX_PATH) {
						info.exe_path = sz;
					}
				}
				CloseHandle(hProcess);
			}

			find_window_data fwd = {info.pid, false};
			EnumWindows(find_visible_window_cb, (LPARAM)&fwd);
			info.has_window = fwd.found;
		}

		all_entries.push_back(std::move(info));
	}
	ulock.unlock();

	/* Deduplicate: group by exe_path (or app_name if exe_path is empty).
	 * Keep the entry with has_window=true when possible, so the "Bring up"
	 * button targets the interactive process. */
	std::unordered_map<std::wstring, size_t> seen;
	std::vector<blocker_info> result;

	for (auto &info : all_entries) {
		const std::wstring &key = info.exe_path.empty() ? info.app_name : info.exe_path;

		auto it = seen.find(key);
		if (it != seen.end()) {
			/* Prefer the entry with a visible window */
			if (info.has_window && !result[it->second].has_window) {
				result[it->second] = std::move(info);
			}
		} else {
			seen[key] = result.size();
			result.push_back(std::move(info));
		}
	}

	/* Check sibling processes for visible windows. The PIDs reported by
	 * the Restart Manager are often worker/child processes (e.g. Chrome
	 * GPU process) that don't own the main app window. */
	for (auto &info : result) {
		if (info.has_window || info.exe_path.empty())
			continue;

		HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		if (snap == INVALID_HANDLE_VALUE)
			continue;

		PROCESSENTRY32W pe = {sizeof(pe)};
		if (Process32FirstW(snap, &pe)) {
			do {
				HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
				if (hProc) {
					WCHAR sz[MAX_PATH];
					DWORD cch = MAX_PATH;
					if (QueryFullProcessImageNameW(hProc, 0, sz, &cch) && cch <= MAX_PATH) {
						if (_wcsicmp(sz, info.exe_path.c_str()) == 0) {
							find_window_data fwd = {pe.th32ProcessID, false};
							EnumWindows(find_visible_window_cb, (LPARAM)&fwd);
							if (fwd.found) {
								info.has_window = true;
							}
						}
					}
					CloseHandle(hProc);
				}
				if (info.has_window)
					break;
			} while (Process32NextW(snap, &pe));
		}
		CloseHandle(snap);
	}

	/* Disambiguate entries that share the same app_name but have different
	 * exe_path (e.g. Chrome vs Chrome Beta both report "Google Chrome").
	 * Use FileDescription from version info for a better display name. */
	std::unordered_map<std::wstring, int> name_counts;
	for (auto &info : result)
		name_counts[info.app_name]++;

	for (auto &info : result) {
		if (name_counts[info.app_name] <= 1)
			continue;

		std::wstring desc = get_file_description(info.exe_path);
		if (!desc.empty() && desc != info.app_name) {
			info.app_name = desc;
		} else if (!info.exe_path.empty()) {
			/* Fallback: use the product folder from the exe path
			 * e.g. "C:\...\Chrome Beta\Application\chrome.exe" -> "Chrome Beta" */
			fs::path exe(info.exe_path);
			fs::path parent = exe.parent_path();
			if (parent.has_parent_path()) {
				std::wstring folder = parent.parent_path().filename().wstring();
				if (!folder.empty()) {
					info.app_name += L" (" + folder + L")";
				}
			}
		}
	}

	return result;
}

bool check_file_updatable(fs::path &check_path, bool check_read, blockers_map_t &blockers)
{
	bool ret = true;
	const std::wstring path_str = check_path.generic_wstring();

	HANDLE hFile = CreateFile(path_str.c_str(), check_read ? GENERIC_READ : GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		DWORD errorCode = GetLastError();

		switch (errorCode) {
		case ERROR_SUCCESS:
		case ERROR_FILE_NOT_FOUND:
		case ERROR_PATH_NOT_FOUND:
			//its normal we can update file that not exist before
			break;
		case ERROR_SHARING_VIOLATION:
		case ERROR_LOCK_VIOLATION:
			if (get_blockers_list(check_path, blockers)) {
				ret = false;
			} else {
				//if fail to get blocking process info we go old way
				throw update_exception_blocked();
			}
			break;
		case ERROR_ACCESS_DENIED:
		case ERROR_WRITE_PROTECT:
		case ERROR_WRITE_FAULT:
		case ERROR_OPEN_FAILED:
		default:
			//its bad
			throw update_exception_failed();
		}
	} else {
		CloseHandle(hFile);
	}
	return ret;
}
