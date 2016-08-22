#include "helper.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <regex>
#include <ntstatus.h>
#include <WbemCli.h>
#include <atlbase.h>


#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")


extern "C" BOOL cdtors(TORS_ROUTINE *p_ir, size_t ir_count) {
	size_t i;
	BOOL success = TRUE;
	BOOL tor_ret;

	if (!p_ir)
		return TRUE;

	// call all tors functions
	for (i = 0; i < ir_count && success; ++i) {
		if (!p_ir[i])
			success &= FALSE;
		tor_ret = !reinterpret_cast<BOOL>(p_ir[i](NULL));
		success &= tor_ret;
	}

	return success;
}

extern "C" BOOL send_all(SOCKET s, const char *buf, int len, int flags) {
	int bytes_sent_total = 0,
		bytes_sent;

	while ((bytes_sent = send(s, buf + bytes_sent_total, len - bytes_sent_total, flags)) != SOCKET_ERROR) {
		if (!bytes_sent)
			break;

		bytes_sent_total += bytes_sent;
	}
	
	return bytes_sent_total == len;
}

extern "C" BOOL recv_all(SOCKET s, char *buf, int len, int flags) {
	// FIXME: implement

	return TRUE;
}

extern "C" BOOL ctors(TORS_ROUTINE *p_ir, size_t ir_count) {
	return cdtors(p_ir, ir_count);
}

extern "C" BOOL dtors(TORS_ROUTINE *p_ir, size_t ir_count) {
	return cdtors(p_ir, ir_count);
}

extern "C" LPVOID ctors_wsa(LPVOID arg) {
	WORD wVersionRequested;
	WSADATA wsaData;
	int err;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData)) {
		return reinterpret_cast<LPVOID>(1);
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		return reinterpret_cast<LPVOID>(1);
	}

	return NULL;
}

extern "C" LPVOID dtors_wsa(LPVOID arg) {
	return reinterpret_cast<LPVOID>(WSACleanup());
}

extern "C" DWORD find_process_by_name(LPCSTR proc_name) {
	PROCESSENTRY32 entry;
	DWORD pid = INVALID_PID_VALUE;

	if (!proc_name)
		return pid;

	entry.dwSize = sizeof(PROCESSENTRY32);

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

	if (Process32First(snapshot, &entry) == FALSE) {
		goto clean;
	}

	while (Process32Next(snapshot, &entry) == TRUE)
		if (!_stricmp(entry.szExeFile, proc_name)) {
			pid = entry.th32ProcessID;
			goto clean;
		}

clean:
	CloseHandle(snapshot);

	return pid;
}

extern "C" HANDLE open_process_by_pid(DWORD pid, DWORD flags) {
	HANDLE hProcess;

	if (!(hProcess = OpenProcess(flags, FALSE, pid)))
		return INVALID_HANDLE_VALUE;

	return hProcess;
}

extern "C" HANDLE open_thread_by_tid(DWORD tid, DWORD flags) {
	HANDLE hThread;

	if (!(hThread = OpenThread(flags, FALSE, tid)))
		return INVALID_HANDLE_VALUE;

	return hThread;
}

extern "C" HANDLE open_process_by_name(LPCSTR proc_name, DWORD flags) {
	DWORD pid;
	
	pid = find_process_by_name(proc_name);
	if (pid == INVALID_PID_VALUE)
		return INVALID_HANDLE_VALUE;

	return open_process_by_pid(pid, flags);
}

extern "C" BOOL terminate_process(HANDLE proc) {
	if (proc == INVALID_HANDLE_VALUE)
		return FALSE;

	// FIXME: should be implemented
	return FALSE;
}

extern "C" BOOL check_if_path_exists(LPCSTR path, DWORD *err_code) {
	// TODO: implement
	HANDLE hFile;

	/*
	if (!(hFile = CreateFileA(
			path,
			READ_CONTROL,
			FILE_SHARE_READ | FILE_SHARE_WRITE
		))) {

		return FALSE;
	}
	*/

	return TRUE;
}

extern "C" BOOL check_current_parent_folder_w(const wchar_t *file_name) {
	if (!file_name)
		return FALSE;

	if (file_name[0] == '.')
		return file_name[1] == 0x00 || (file_name[1] == '.' && file_name[2] == 0x00);

	return FALSE;
}

/*
 * Responsible for enumerating recursively drive path
 */
extern "C" BOOL enumerate_directory_w(const wchar_t *path, SIZE_T max_rec_depth, SIZE_T rec_depth, FILE_ROUTINE proc_on_entry, PVOID proc_args, const std::list<file_name_w_t> &filenames) {
	HANDLE hFile;
	WIN32_FIND_DATAW f_find_data;
	wchar_t full_path[MAX_PATH + 1] = { 0 };
	wchar_t regexp[MAX_PATH * 2 + 1];
	wchar_t file_path[MAX_PATH + 1];
	BOOL found = FALSE;

	if (rec_depth > max_rec_depth)
		return FALSE;

	if (!PathCombineW(full_path, path, L"*.*"))
		return FALSE;

	hFile = FindFirstFileW(full_path, &f_find_data);
	if (hFile == INVALID_HANDLE_VALUE)
		return FALSE;

	do {
		if (check_current_parent_folder_w(f_find_data.cFileName))
			continue;

		if (f_find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
			if (!PathCombineW(full_path, path, f_find_data.cFileName))
				continue;

			// TODO: should we call proc_on_entry for directory ???
			if (enumerate_directory_w(full_path, max_rec_depth, rec_depth + 1, proc_on_entry, proc_args, filenames))
				break;
		}
		// TODO: should we check other attributes ???
		else {
			// check if file name matches at least one of the specified regexps
			pfi *ppfi = static_cast<pfi *>(proc_args);
			if (!ppfi)
				continue;

			found = FALSE;

			memset(file_path, 0, sizeof(file_path));
			if (!PathCombineW(file_path, path, f_find_data.cFileName))
				continue;

			for (auto &ri : filenames) {
				memset(regexp, 0, sizeof(regexp));
				if (!PathCombineW(regexp, path, ri.c_str()))
					continue;
				// std::string re(regexp), fp(file_path);
				// TODO: escape charactes from regexp
				/*
				if (match_regexp<char>(std::string(ri.c_str()), std::string(f_find_data.cFileName))) {
				found = TRUE;
				break;
				}
				*/
				if (std::wstring(f_find_data.cFileName) == ri) {
					found = TRUE;
					break;
				}
			}

			// no matching file found
			if (!found)
				continue;

			ppfi->matched = true;

			// check if we have any extra checks ?
			if (!proc_on_entry)
				break;

			ppfi->file_name = f_find_data.cFileName;	// TODO: do we need short path and long path ???
			proc_on_entry(proc_args);
			ppfi->file_name = NULL;
			if (ppfi->matched)
				break;
		}
	} while (FindNextFileW(hFile, &f_find_data));

	FindClose(hFile);
	return found;
}


extern "C" LPCVOID inject_data(HANDLE hProcess, const data_t *data, SIZE_T code_size, DWORD protect) {
	LPVOID mem_chunk;
	DWORD dwNumberOfBytesWritten;

	if (code_size < 0)
		return NULL;

	// allocate memory + write data
	mem_chunk = VirtualAllocEx(
		hProcess,
		NULL,
		code_size,
		MEM_COMMIT | MEM_RESERVE,
		protect
		);

	if (!mem_chunk)
		return NULL;

	if (WriteProcessMemory(
		hProcess,
		mem_chunk,
		data,
		code_size,
		&dwNumberOfBytesWritten
		) == FALSE)
		return NULL;

	if (code_size != dwNumberOfBytesWritten)
		return NULL;

	// code was injected successfully

	return mem_chunk;
}


extern "C" LPCVOID inject_code(HANDLE hProcess, const code_t *code, SIZE_T code_size) {
	LPCVOID code_chunk;

	code_chunk = inject_data(hProcess, code, code_size, PAGE_EXECUTE_READ);
	if (!code_chunk)
		return NULL;

	return code_chunk;
}


extern "C" BOOL execute_code(HANDLE hProcess, LPTHREAD_START_ROUTINE start_addr, LPVOID args, HANDLE *phThread) {
	HANDLE hThread;

	// just use stupid method ever CreateRemoteThread
	hThread = CreateRemoteThread(
		hProcess,
		NULL,
		0,
		start_addr,
		args,
		0,
		NULL
		);

	if (phThread)
		*phThread = hThread;

	return hThread != 0;
}

extern "C" BOOL thread_context_execute_code(HANDLE hThread, LPTHREAD_START_ROUTINE routine, LPVOID args, BOOL suspended) {
	HMODULE hModule;
	FARPROC fpZwGetContextThread,
		fpZwResumeThread,
		fpZwSetContextThread;
	CONTEXT threadContext;

	hModule = GetModuleHandleW(L"ntdll");
	if (!hModule)
		return FALSE;

	fpZwGetContextThread = GetProcAddress(hModule, "ZwGetContextThread");
	if (!fpZwGetContextThread)
		return FALSE;

	fpZwSetContextThread = GetProcAddress(hModule, "ZwSetContextThread");
	if (!fpZwSetContextThread)
		return FALSE;

	fpZwResumeThread = GetProcAddress(hModule, "ZwResumeThread");
	if (!fpZwResumeThread)
		return FALSE;

	ZeroMemory(&threadContext, sizeof(threadContext));

	threadContext.ContextFlags = CONTEXT_ALL;
	NTSTATUS s;
	const size_t max_retries = 10;
	size_t retries_count = 0;

	do {
		Sleep(10);
		s = reinterpret_cast<NTSTATUS (WINAPI *)(HANDLE, PCONTEXT)>(fpZwGetContextThread)(hThread, &threadContext);
	} while (s != STATUS_SUCCESS && s != STATUS_INVALID_PARAMETER && retries_count++ < max_retries);

	if (s != STATUS_SUCCESS)
		return FALSE;

	if (suspended)
		threadContext.Eax = reinterpret_cast<DWORD>(routine);
	else
		threadContext.Eip = reinterpret_cast<DWORD>(routine);

	if (reinterpret_cast<NTSTATUS (WINAPI *)(HANDLE, PCONTEXT)>(fpZwSetContextThread)(hThread, &threadContext) != STATUS_SUCCESS)
		return FALSE;

	if (reinterpret_cast<NTSTATUS (WINAPI *)(HANDLE, PULONG)>(fpZwResumeThread)(hThread, NULL) != STATUS_SUCCESS)
		return FALSE;

	return TRUE;
}


/*
 * Assembly check if function has a trampoline at the beggining
 * esp ---> ------------------------
 *			-pointer to code       -
 *			-pointer to code's size-
 *			------------------------
 * esi <--- contains pointer to code
 * ecx <--- contains pointer to code's size
 */


/*
 * Retrieve specified environment variable
 * Achieved data should be freed later in case function succeeded
 */
bool get_envvar(const char *env, char **out) {
	if (!env | !out)
		return FALSE;

	char *envvar = NULL;
	size_t buff_size = 0;

	if (getenv_s(&buff_size, NULL, 0, env))
		return FALSE;

	envvar = static_cast<char *>(calloc(buff_size + 1, sizeof(char)));
	if (!envvar)
		return FALSE;

	if (getenv_s(&buff_size, envvar, buff_size, env))
		return FALSE;

	*out = envvar;
	return TRUE;
}


/*
* Retrieve specified environment variable
* Achieved data should be freed later in case function succeeded
*/
bool get_envvar_w(const wchar_t *env, wchar_t **out) {
	if (!env | !out)
		return FALSE;

	wchar_t *envvar = NULL;
	size_t buff_size = 0;

	if (_wgetenv_s(&buff_size, NULL, 0, env))
		return FALSE;

	envvar = static_cast<wchar_t *>(calloc(buff_size + 1, sizeof(wchar_t)));
	if (!envvar)
		return FALSE;

	if (_wgetenv_s(&buff_size, envvar, buff_size, env))
		return FALSE;

	*out = envvar;
	return TRUE;
}


/*
* Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
*
* @APPLE_LICENSE_HEADER_START@
*
* The contents of this file constitute Original Code as defined in and
* are subject to the Apple Public Source License Version 1.1 (the
* "License").  You may not use this file except in compliance with the
* License.  Please obtain a copy of the License at
* http://www.apple.com/publicsource and read it before using this file.
*
* This Original Code and all software distributed under the License are
* distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
* EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
* INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
* License for the specific language governing rights and limitations
* under the License.
*
* @APPLE_LICENSE_HEADER_END@
*/
/*
* Copyright (c) 1990, 1993
*	The Regents of the University of California.  All rights reserved.
*
* This code is derived from software contributed to Berkeley by
* Chris Torek.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
* 1. Redistributions of source code must retain the above copyright
*    notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
*    notice, this list of conditions and the following disclaimer in the
*    documentation and/or other materials provided with the distribution.
* 3. All advertising materials mentioning features or use of this software
*    must display the following acknowledgement:
*	This product includes software developed by the University of
*	California, Berkeley and its contributors.
* 4. Neither the name of the University nor the names of its contributors
*    may be used to endorse or promote products derived from this software
*    without specific prior written permission.
*
* THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
* ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
* IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
* ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
* FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
* DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
* OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
* HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
* LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
* OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
* SUCH DAMAGE.
*/
void* __memchr(const void *s, unsigned char c, size_t n) {
	if (n != 0) {
		const unsigned char *p = reinterpret_cast<const unsigned char *>(s);

		do {
			if (*p++ == c)
				return ((void *)(p - 1));
		} while (--n != 0);
	}
	return NULL;
}

extern "C" unsigned char* __memmem(const unsigned char* haystack, size_t hlen, const unsigned char* needle, size_t nlen) {
	if (nlen > hlen) 
		return 0;

	size_t i = 0, j = 0;

	switch (nlen) { // we have a few specialized compares for certain needle sizes
	case 0: // no needle? just give the haystack
		return const_cast<unsigned char *>(haystack);
	case 1: // just use memchr for 1-byte needle
		return reinterpret_cast<unsigned char *>(__memchr(reinterpret_cast<const void *>(haystack), needle[0], hlen));
	case 2: // use 16-bit compares for 2-byte needles
		for (i = 0; i < hlen - nlen + 1; ++i) {
			if (*reinterpret_cast<const uint16_t *>(haystack + i) == *reinterpret_cast<const uint16_t *>(needle)) {
				return const_cast<unsigned char *>(haystack + i);
			}
		}
		break;
	case 4: // use 32-bit compares for 4-byte needles
		for (i = 0; i < hlen - nlen + 1; ++i) {
			if (*reinterpret_cast<const uint32_t *>(haystack + i) == *reinterpret_cast<const uint32_t *>(needle)) {
				return const_cast<unsigned char *>(haystack + i);
			}
		}
		break;
	default: // generic compare for any other needle size
			 // walk i through the haystack, matching j as long as needle[j] matches haystack[i]
		for (i = 0; i < hlen - nlen + 1; ++i) {
			if (haystack[i] == needle[j]) {
				if (j == nlen - 1) { // end of needle and it all matched?  win.
					return const_cast<unsigned char *>(haystack + i - j);
				}
				else { // keep advancing j (and i, implicitly)
					j++;
				}
			}
			else { // no match, rewind i the length of the failed match (j), and reset j
				i -= j;
				j = 0;
			}
		}
	}
	return NULL;
}


extern "C" DWORD align_down(DWORD val, DWORD align) {
	if (!align)
		return val;

	if (val % align == 0)
		return val;

	return (val / align) * align;
}


extern "C" DWORD align_up(DWORD val, DWORD align) {
	if (!align)
		return val;

	if (val % align == 0)
		return val;

	return ((val / align) + 1) * align;
}

/*
 * Retrieve Ipv4 connection table handling current structure state
 * Return pointer to MIB_TCPTABLE. If pointer value is not NULL, then it should be freed
 */
extern "C" LPCVOID get_tcp_table() {
	PMIB_TCPTABLE pTcpTable;
	PMIB_TCPTABLE pTcpTable_old;
	DWORD dwSize;

	dwSize = sizeof(MIB_TCPTABLE);
	pTcpTable = reinterpret_cast<MIB_TCPTABLE *>(calloc(1, dwSize));
	if (!pTcpTable)
		return NULL;

	// Make initial call in order to initialize Tcp Table

	if (GetTcpTable(pTcpTable, &dwSize, TRUE) == ERROR_INSUFFICIENT_BUFFER) {
		pTcpTable_old = pTcpTable;
		pTcpTable = reinterpret_cast<MIB_TCPTABLE *>(realloc(pTcpTable, dwSize));
		if (!pTcpTable) {
			free(pTcpTable);
			return NULL;
		}
	}

	// get structures all tcp connections
	if (GetTcpTable(pTcpTable, &dwSize, TRUE) != NO_ERROR) {
		free(pTcpTable);
		return NULL;
	}

	return pTcpTable;
}

extern "C" char* hexlify(const unsigned char *data, size_t data_size) {
	size_t i;
	char *hex_data = reinterpret_cast<char *>(calloc((data_size * 2) + 1, sizeof(char)));
	if (!hex_data)
		return NULL;

	for (i = 0; i < data_size; ++i) {
		_snprintf_s(hex_data + (i * 2), data_size * 2 + 1, 3, "%.02x", data[i]);
	}

	return hex_data;
}

void get_tcp_entries(const MIB_TCPTABLE *p_tcp_table, network_endpoints_t &net_endpoints, DWORD state) {
	size_t i;

	if (!p_tcp_table)
		return;

	for (i = 0; i < p_tcp_table->dwNumEntries; ++i) {
		if (p_tcp_table->table[i].dwState == state) {
			net_endpoints.push_back(network_endpoint_t(p_tcp_table->table[i].dwLocalAddr, p_tcp_table->table[i].dwLocalPort));
		}
	}

	return;
}

template <typename T>
bool match_regexp(const std::basic_string<T> &regexp, const std::basic_string<T> &str, std::vector<std::basic_string<T>> *matches) {
	std::basic_regex<T> re(regexp, std::regex::ECMAScript | std::regex::icase);
	std::match_results<std::basic_string<T>::const_iterator> sm;

	if (!std::regex_match(str, sm, re))
		return FALSE;

	if (matches) {
		for (size_t i = 1, e = sm.size(); i < e; ++i)
			matches->push_back(sm[i].str());
	}

	return TRUE;
}

bool run_self_susp(const wchar_t *app_params, PROCESS_INFORMATION *ppi) {
	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	GetStartupInfoW(&si);

	wchar_t cur_dir[MAX_PATH + 1] = {},
		app_name[MAX_PATH + 1] = {};

	if (!get_app_full_name(app_params, app_name, _countof(app_name), cur_dir, _countof(cur_dir)))
		return false;

	// create process with parametres
	return CreateProcessW(
		NULL,
		app_name,
		NULL,
		NULL,
		TRUE,
		CREATE_SUSPENDED,
		NULL,
		cur_dir,
		&si,
		ppi
		);
}

bool get_app_full_name(const wchar_t *app_params, wchar_t *app_name, size_t app_name_size, wchar_t *cur_dir, size_t cur_dir_size) {
	if (!GetCurrentDirectoryW(cur_dir_size, cur_dir))
		return false;

	if (!GetModuleFileNameW(NULL, app_name, app_name_size))
		return false;

	wcscat_s(app_name, app_name_size, L" ");
	if (app_params)
		wcscat_s(app_name, app_name_size, app_params);

	return true;
}

bool run_self_susp_wmi(const wchar_t *app_params, DWORD *ppid) {
	CComPtr<IWbemLocator> wbemLocator;
	CComPtr<IWbemServices> wbemServices;
	CComPtr<IWbemCallResult> callResult;
	CComPtr<IWbemClassObject> oWin32Process;
	CComPtr<IWbemClassObject> oWin32ProcessStartup;
	CComPtr<IWbemClassObject> oMethCreate, oMethCreateSignature;
	CComPtr<IWbemClassObject> instWin32Process;
	CComPtr<IWbemClassObject> instWin32ProcessStartup;
	CComVariant varCreateFlags(CREATE_SUSPENDED);
	CComPtr<IWbemClassObject> pOutParams;

	wchar_t	app_name[MAX_PATH + 1] = {},
		cur_dir[MAX_PATH + 1] = {};

	if (!get_app_full_name(app_params, app_name, _countof(app_name), cur_dir, _countof(cur_dir)))
		return false;

	CComVariant varCmdLine(app_name);
	CComVariant varCurDir(cur_dir);
	bool succ = false;

	do {
		CoInitializeEx(NULL, 0);

		if (!ppid)
			break;

		if (FAILED(CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL)))
			break;

		if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&wbemLocator)) || !wbemLocator)
			break;

		if (FAILED(wbemLocator->ConnectServer(CComBSTR("ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &wbemServices)) || !wbemServices)
			break;

		if (FAILED(CoSetProxyBlanket(wbemServices, RPC_C_AUTHN_WINNT, 0, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0)))
			break;

		if (FAILED(wbemServices->GetObject(CComBSTR("Win32_Process"), 0, NULL, &oWin32Process, &callResult)) || !oWin32Process)
			break;

		if (FAILED(wbemServices->GetObject(CComBSTR("Win32_ProcessStartup"), 0, NULL, &oWin32ProcessStartup, &callResult)) || !oWin32ProcessStartup)
			break;

		if (FAILED(oWin32Process->GetMethod(CComBSTR("Create"), 0, &oMethCreate, &oMethCreateSignature)) || !oMethCreate)
			break;

		if (FAILED(oMethCreate->SpawnInstance(0, &instWin32Process)) || !instWin32Process)
			break;

		if (FAILED(oWin32ProcessStartup->SpawnInstance(0, &instWin32ProcessStartup)) || !instWin32ProcessStartup)
			break;

		if (FAILED(instWin32ProcessStartup->Put(CComBSTR("CreateFlags"), 0, &varCreateFlags, 0)))
			break;

		if (FAILED(instWin32Process->Put(CComBSTR("CommandLine"), 0, &varCmdLine, 0)))
			break;

		if (FAILED(instWin32Process->Put(CComBSTR("CurrentDirectory"), 0, &varCurDir, 0)))
			break;

		CComVariant varStartupInfo(instWin32ProcessStartup);
		if (FAILED(instWin32Process->Put(CComBSTR("ProcessStartupInformation"), 0, &varStartupInfo, 0)))
			break;

		if (FAILED(wbemServices->ExecMethod(CComBSTR("Win32_Process"), CComBSTR("Create"), 0, NULL, instWin32Process, &pOutParams, &callResult)))
			break;

		CComVariant pid(0);
		CIMTYPE pid_type(CIM_UINT32);

		if (FAILED(pOutParams->Get(CComBSTR("ProcessId"), 0, &pid, &pid_type, NULL)))
			break;

		*ppid = reinterpret_cast<DWORD>(pid.puintVal);
		succ = true;

	} while (false);

	// TODO: implement cleanup

	// CoUninitialize();

	return succ;
}

bool get_all_tids_by_pid(DWORD pid, std::vector<DWORD> &tids) {
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	THREADENTRY32 te;
	te.dwSize = sizeof(te);

	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;
	
	if (!Thread32First(hSnapshot, &te)) {
		CloseHandle(hSnapshot);
		return false;
	}

	do {
		if (te.th32OwnerProcessID == pid)
			tids.push_back(te.th32ThreadID);

	} while (Thread32Next(hSnapshot, &te));

	CloseHandle(hSnapshot);
	return true;
}


/*
// TODO: does not work
template <typename T>
std::basic_string<T> escape_regexp(const std::basic_string<T> &str) {
	const T esc_a[] = { '[', '.', '^', '$', '|', '(', ')', '\\', '[', '\\', ']', '{', '}', '*', '+', '?', '\\', '\\', 0 };
	const T rep_a[] = { '\\', '\\', '&', 0 };
	std::basic_string<T> estr;
	// const std::basic_regex<T> esc(std::basic_string<T>("[.^$|()\\[\\]{}*+?\\\\]"));
	// const std::basic_string<T> rep(std::basic_string<T>("\\\\&"));
	const std::basic_regex<T> esc(esc_a);
	const std::basic_string<T> rep(rep_a);

	estr = std::regex_replace(str, esc, rep, std::regex_constants::match_default | std::regex_constants::format_sed);

	return estr;
}
*/
