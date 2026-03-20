#include "update-blockers.hpp"
#include "logger/log.h"

#include <algorithm>

#pragma comment(lib, "Rstrtmgr.lib")

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
