/*
	QueryEventLog - proof of concept for detecting 'in-development/homerolled cheat modules' which have previously crashed our current application and are presently loaded

	AlSch092 @ github , August 2023
*/
#include <Windows.h>
#include <iostream>
#include <string>
#include <psapi.h>
#include <list>

using namespace std;

#define EVENTLOG_APPLICATION_CRITICAL_EXCEPTION 1000  //these are the "Red-grade icon" entries representing a program crash
#define EVENTLOG_APPLICATION_WER_APPCRASH 1001        //"white-grade icon" entries for APPCRASH

#define OUR_PROGRAM L"QueryEventLog.exe" //change to whatever your program is

list<wstring> crashed_modules_list = list<wstring>();

//converts an EVENTLOGRECORD (event log entry) to array of strings
wchar_t** record_to_strings(EVENTLOGRECORD *pBuf) //returned mem must be freed 2-dimensionally after finished
{
	//parse pBuf into array of wchar_t*	
	UINT64 stringsAddr = (UINT64)pBuf + pBuf->StringOffset;
	UINT64 current_offset = stringsAddr;

	wchar_t** record_strs = new wchar_t*[pBuf->NumStrings];

	for (int i = 0; i < pBuf->NumStrings; i++) //the EVENTLOGRECORD structure's string entries is an array of strings with 3 byte spacing between, thus we offset by the string's length each time
	{
		wchar_t* str = (wchar_t*)(current_offset);
		record_strs[i] = new wchar_t[wcslen(str) + 2];
		wcscpy(record_strs[i], str);

		wprintf(L"%s\n", record_strs[i]); //uncomment if you want to display the entry string
		current_offset += wcslen(str) * 2 + 2;
	}

	return record_strs;
}

bool is_dll_whitelisted(const wchar_t* dllName)
{
	bool whitelisted = false;

	if (wcscmp(dllName, L"KERNEL32.dll") == 0 || wcsstr(dllName, L"KERNEL32.dll") != NULL) //you can add in more modules here, and optionally encrypt the strings to make it harder to RE
		whitelisted = true;
	else if (wcscmp(dllName, L"USER32.dll") == 0 || wcsstr(dllName, L"USER32.dll") != NULL)
		whitelisted = true;
	else if (wcscmp(dllName, L"ntdll.dll") == 0 || wcsstr(dllName, L"ntdll.dll") != NULL)
		whitelisted = true;
	else if (wcscmp(dllName, L"KERNELBASE.dll") == 0 || wcsstr(dllName, L"KERNELBASE.dll") != NULL)
		whitelisted = true;
	else if (wcscmp(dllName, L"ucrtbase.dll") == 0 || wcsstr(dllName, L"ucrtbase.dll") != NULL)
		whitelisted = true;

	return whitelisted;
}

bool found_cheat_developer(wchar_t** record_strings, int nStrings) //checks array of strings from record_to_strings() for .dlls and current program name. if both are found, we can do further investigation
{
	bool isCrashLogOurProgram = false;
	bool foundDll = false;

	wstring program, dll;
	unsigned int Exception = 0;

	for (int i = 0; i < nStrings; i++)
	{
		if (wcscmp(record_strings[i], OUR_PROGRAM) == 0)
		{
			isCrashLogOurProgram = true;
			program = record_strings[i];
		}
		else if (wcsstr(record_strings[i], L".dll") != NULL) //don't forget to check for case sensitivity!
		{		
			if (!is_dll_whitelisted(dll.c_str()) && isCrashLogOurProgram) //in crash log entry, a .DLL plus a .exe present implies the .dll crashed the .exe. we can then check the current modulelist for loaded dlls
			{
				wprintf(L"Found DLL: %s\n", record_strings[i]);

				foundDll = true;
				dll = record_strings[i];

				crashed_modules_list.push_back(dll);
			}
		}
		else if (wcscmp(record_strings[i], L"c0000005") == 0 || wcscmp(record_strings[i], L"C0000005") == 0) //most common development crash error for usermode cheat tools
		{
			Exception = EXCEPTION_ACCESS_VIOLATION;
		}
	}

	if (isCrashLogOurProgram && foundDll && Exception == EXCEPTION_ACCESS_VIOLATION)
	{
		return true;
	}

	return false;
}

static bool scan_event_log_for_cheater(void) 
{
	bool found_cheater = false;
	DWORD BufSize;
	DWORD ReadBytes;
	DWORD NextSize;

	HANDLE hEventLog = NULL;
	EVENTLOGRECORD *pBuf = NULL;

	hEventLog = OpenEventLogW(NULL, L"Application");

	if (hEventLog == NULL) 
	{
		printf("failed to open event log: %d\n", GetLastError());
		return false;
	}

	bool looping = true;

	while (looping)
	{
		BufSize = 1;
		pBuf = (EVENTLOGRECORD *)GlobalAlloc(GMEM_FIXED, BufSize);

		BOOL bResult = ReadEventLogW(hEventLog,EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ, 0, pBuf, BufSize, &ReadBytes, &NextSize);

		if (!bResult && GetLastError() != ERROR_INSUFFICIENT_BUFFER)  //exit loop 
			break;

		GlobalFree(pBuf);
		pBuf = NULL;

		BufSize = NextSize;
		pBuf = (EVENTLOGRECORD *)GlobalAlloc(GMEM_FIXED, BufSize);

		bResult = ReadEventLogW(hEventLog,EVENTLOG_FORWARDS_READ | EVENTLOG_SEQUENTIAL_READ,0,pBuf,BufSize,&ReadBytes,&NextSize);

		if (!bResult) 
			break;

		if (pBuf->EventID == EVENTLOG_APPLICATION_CRITICAL_EXCEPTION)
		{
			wchar_t** record_strs = record_to_strings(pBuf);

			if (found_cheat_developer(record_strs, pBuf->NumStrings)) //parses one record entry
			{
				found_cheater = true; 			
			}

			for (int i = 0; i < pBuf->NumStrings; i++) //clean mem
			{
				delete[] record_strs[i];
			}

			delete record_strs;

			GlobalFree(pBuf);
			pBuf = NULL;
		}	
	}

	if (pBuf != NULL) 
		GlobalFree(pBuf);

	if (hEventLog != NULL) 
		CloseEventLog(hEventLog);

	return found_cheater;
}

bool is_faulting_module_loaded()
{
	HMODULE hMods[1024];
	HANDLE hProcess;
	DWORD cbNeeded;

	bool is_faulting_dll_loaded = false;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION |
		PROCESS_VM_READ,
		FALSE, GetCurrentProcessId());
	if (NULL == hProcess)
		return 1;

	if (EnumProcessModules(hProcess, hMods, sizeof(hMods), &cbNeeded))
	{
		for (int i = 0; i < (cbNeeded / sizeof(HMODULE)); i++)
		{
			TCHAR szModName[MAX_PATH];

			if (GetModuleFileNameEx(hProcess, hMods[i], szModName,
				sizeof(szModName) / sizeof(TCHAR)))
			{	
				wprintf(L"szModName: %s\n", szModName);

				for each(wstring dll in crashed_modules_list)
				{
					if (wcscmp(szModName, dll.c_str()) == 0 || wcsstr(szModName, dll.c_str()) != NULL)
					{
						wprintf(L"Module %s is presently loaded, and also in our event logs for crashing our program.\n", szModName);
						is_faulting_dll_loaded = true;
					}
				}
			}
		}
	}

	CloseHandle(hProcess);

	return is_faulting_dll_loaded;
}

int main(int argc, char** argv) 
{
	if (scan_event_log_for_cheater()) //gather .dlls which have crashed our application previously
	{
		if (is_faulting_module_loaded()) //loop through the current program's modules and see if the faulting modules found are present/loaded
		{
			printf("Potential cheat program was found!\n");
		}
	}
	else
	{
		printf("Did not find any event logs of modules crashing the current application.\n");
	}

	system("pause");
	return 0;
}
