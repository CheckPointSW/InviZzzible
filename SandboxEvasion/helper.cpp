#include "helper.h"
#include <TlHelp32.h>
#include <Shlwapi.h>
#include <regex>
#include <ntstatus.h>
#include <WbemCli.h>
#include <atlbase.h>
#include <comdef.h>
#include <taskschd.h>
#include <MSTask.h>
#include <Winreg.h>
#include <Iphlpapi.h>
#include <Ntsecapi.h>
#include "nt.h"


#pragma comment(lib, "Shlwapi")
#pragma comment(lib, "Iphlpapi")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "wbemuuid.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "Mstask.lib")

#include <iostream>
using std::cout;
using std::endl;


std::map<LogMessageLevel, std::string> log_msg_levels = {
	{ LogMessageLevel::DEBUG, std::string("DEBUG") },
	{ LogMessageLevel::INFO, std::string("INFO") },
	{ LogMessageLevel::WARNING, std::string("WARNING") },
	{ LogMessageLevel::ERR, std::string("ERROR") },
	{ LogMessageLevel::PANIC, std::string("PANIC") }
};

const std::map<std::string, HKEY> str2hkey = {
	{ "HKCR", HKEY_CLASSES_ROOT },
	{ "HKCC", HKEY_CURRENT_CONFIG },
	{ "HKCU", HKEY_CURRENT_USER },
	{ "HKLM", HKEY_LOCAL_MACHINE },
	{ "HKUS", HKEY_USERS }
};

bool g_verbose_mode = false;
bool g_is_wow64 = false;
RTL_OSVERSIONINFOW g_osver;

void enable_verbose_mode() {
	g_verbose_mode = true;
}

void enable_wow64() {
	g_is_wow64 = true;
}

bool is_wow64() {
	return g_is_wow64;
}

HKEY get_hkey(const std::string &key) {
	const std::map<std::string, HKEY>::const_iterator it = str2hkey.find(key);

	return it == str2hkey.end() ? reinterpret_cast<HKEY>(INVALID_HKEY) : it->second;
}

void log_message(LogMessageLevel msg_l, const std::string &module, const std::string &msg) {
	if (!g_verbose_mode)
		return;

	if (log_msg_levels.find(msg_l) == log_msg_levels.end())
		return;

	cout << "[" << log_msg_levels[msg_l] << "] " << module << ": " << msg << std::endl;
}

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

extern "C" BOOL ctors(TORS_ROUTINE *p_ir, size_t ir_count) {
	return cdtors(p_ir, ir_count);
}

extern "C" BOOL dtors(TORS_ROUTINE *p_ir, size_t ir_count) {
	return cdtors(p_ir, ir_count);
}

extern "C" LPVOID ctors_wsa(LPVOID arg) {
	WORD wVersionRequested;
	WSADATA wsaData;

	wVersionRequested = MAKEWORD(2, 2);

	if (WSAStartup(wVersionRequested, &wsaData)) {
		return (LPVOID)(1);
	}

	if (LOBYTE(wsaData.wVersion) != 2 || HIBYTE(wsaData.wVersion) != 2) {
		WSACleanup();
		return (LPVOID)(1);
	}

	return NULL;
}

extern "C" LPVOID ctors_check_wow64(LPVOID arg) {
	FARPROC fpIsWow64Process = NULL;
	BOOL isWoW64 = FALSE;

	fpIsWow64Process = GetProcAddress(GetModuleHandleW(L"kernel32"), "IsWow64Process");
	if (fpIsWow64Process && ((BOOL (WINAPI*)(HANDLE, PBOOL))fpIsWow64Process)(GetCurrentProcess(), &isWoW64) && isWoW64)
		enable_wow64();

	return (LPVOID)(0);
}

/*
 * Code taken from VMDE project: https://github.com/hfiref0x/VMDE
 */
extern "C" LPVOID ctors_get_os_ver(LPVOID arg) {
	NTSTATUS Status;

	RtlSecureZeroMemory(&g_osver, sizeof(g_osver));
	g_osver.dwOSVersionInfoSize = sizeof(g_osver);

	NTSTATUS(NTAPI *fnRtlGetVersion)(PRTL_OSVERSIONINFOW) = (NTSTATUS(NTAPI *)(PRTL_OSVERSIONINFOW))(GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlGetVersion"));
	if (!fnRtlGetVersion)
		return (LPVOID)(1);

	Status = fnRtlGetVersion(&g_osver);
	if (NT_SUCCESS(Status)) {
		if (g_osver.dwMajorVersion < 6) {
			enable_privilege(SE_DEBUG_PRIVILEGE, TRUE);
		}
		return (LPVOID)(0);
	}

	return (LPVOID)(1);
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


// https://sourceware.org/ml/libc-alpha/2007-12/msg00000.html
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

	if (!ppid)
		return false;

	if (!get_app_full_name(app_params, app_name, _countof(app_name), cur_dir, _countof(cur_dir)))
		return false;

	CComVariant varCmdLine(app_name);
	CComVariant varCurDir(cur_dir);
	bool succ = false;
	HRESULT hres;

	do {
		// Initialize COM
		if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
			break;

		//  Set general COM security levels
		hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (FAILED(hres) && hres != RPC_E_TOO_LATE)
			break;

		// create an instance of WbemLocator
		if (FAILED(CoCreateInstance(CLSID_WbemLocator, NULL, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&wbemLocator)) || !wbemLocator)
			break;

		// get services
		if (FAILED(wbemLocator->ConnectServer(CComBSTR("ROOT\\CIMV2"), NULL, NULL, NULL, 0, NULL, NULL, &wbemServices)) || !wbemServices)
			break;

		// set proxy blanket for services
		if (FAILED(CoSetProxyBlanket(wbemServices, RPC_C_AUTHN_WINNT, 0, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0)))
			break;

		// get Win32_Process object
		if (FAILED(wbemServices->GetObject(CComBSTR("Win32_Process"), 0, NULL, &oWin32Process, &callResult)) || !oWin32Process)
			break;

		// get Win32_ProcessStartup object
		if (FAILED(wbemServices->GetObject(CComBSTR("Win32_ProcessStartup"), 0, NULL, &oWin32ProcessStartup, &callResult)) || !oWin32ProcessStartup)
			break;

		if (FAILED(oWin32Process->GetMethod(CComBSTR("Create"), 0, &oMethCreate, &oMethCreateSignature)) || !oMethCreate)
			break;

		if (FAILED(oMethCreate->SpawnInstance(0, &instWin32Process)) || !instWin32Process)
			break;

		if (FAILED(oWin32ProcessStartup->SpawnInstance(0, &instWin32ProcessStartup)) || !instWin32ProcessStartup)
			break;

		// set startup information for process
		if (FAILED(instWin32ProcessStartup->Put(CComBSTR("CreateFlags"), 0, &varCreateFlags, 0)))
			break;

		if (FAILED(instWin32Process->Put(CComBSTR("CommandLine"), 0, &varCmdLine, 0)))
			break;

		if (FAILED(instWin32Process->Put(CComBSTR("CurrentDirectory"), 0, &varCurDir, 0)))
			break;

		CComVariant varStartupInfo(instWin32ProcessStartup);
		if (FAILED(instWin32Process->Put(CComBSTR("ProcessStartupInformation"), 0, &varStartupInfo, 0)))
			break;

		// start process
		if (FAILED(wbemServices->ExecMethod(CComBSTR("Win32_Process"), CComBSTR("Create"), 0, NULL, instWin32Process, &pOutParams, &callResult)))
			break;

		CComVariant pid(0);
		CIMTYPE pid_type(CIM_UINT32);

		// collect PID
		if (FAILED(pOutParams->Get(CComBSTR("ProcessId"), 0, &pid, &pid_type, NULL)))
			break;

		*ppid = reinterpret_cast<DWORD>(pid.puintVal);
		succ = true;

	} while (false);

	// TODO: implement cleanup

	// CoUninitialize();

	return succ;
}

bool run_self_tsched(const wchar_t *app_params, DWORD *ppid) {
	DWORD major_version;

	major_version = (DWORD)(LOBYTE(LOWORD(GetVersion())));

	if (major_version == 5) 
		return run_self_tsched_xp_down(app_params, ppid);
	else if (major_version > 5)
		return run_self_tsched_vista_up(app_params, ppid);

	return false;
}


bool run_self_tsched_vista_up(const wchar_t *app_params, DWORD *ppid) {
	ITaskService *pService = NULL;
	ITaskFolder *pTaskRootFolder = NULL;
	ITaskDefinition *pTask = NULL;
	IRegistrationInfo *pRegInfo = NULL;
	IPrincipal *pPrincipal = NULL;
	ITaskSettings *pSettings = NULL;
	ITriggerCollection *pTriggerCollection = NULL;
	ITrigger *pTrigger = NULL;
	IRegistrationTrigger *pRegistrationTrigger = NULL;
	IActionCollection *pActionCollection = NULL;
	IAction *pAction = NULL;
	IExecAction *pExecAction = NULL;
	IRegisteredTask *pRegisteredTask = NULL;

	bool succ = false;
	wchar_t task_name[] = L"sandbox evasion tsrv";

	wchar_t	app_name[MAX_PATH + 1] = {},
		cur_dir[MAX_PATH + 1] = {};
	HRESULT hres;

	if (!ppid)
		return false;

	if (!get_app_full_name(NULL, app_name, _countof(app_name), cur_dir, _countof(cur_dir)))
		return false;

	do {
		// Initialize COM
		if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
			break;

		//  Set general COM security levels
		hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (FAILED(hres) && hres != RPC_E_TOO_LATE)
			break;

		// create an instance of the Task Service
		if (FAILED(CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService)))
			break;

		// connect to task service
		if (FAILED(pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t())))
			break;

		// get task root folder
		if (FAILED(pService->GetFolder(_bstr_t(L"\\"), &pTaskRootFolder)))
			break;

		// delete task if already exists
		pTaskRootFolder->DeleteTask(_bstr_t(task_name), 0);

		// create task object
		if (FAILED(pService->NewTask(0, &pTask)))
			break;

		// get task registration info
		if (FAILED(pTask->get_RegistrationInfo(&pRegInfo)))
			break;

		// set info
		if (FAILED(pRegInfo->put_Author(L"Sandbox Evasion")))
			break;

		// create principal for the task
		if (FAILED(pTask->get_Principal(&pPrincipal)))
			break;

		// setup principal information
		pPrincipal->put_Id(_bstr_t(L"Principal Sandbox Evasion"));
		pPrincipal->put_LogonType(TASK_LOGON_INTERACTIVE_TOKEN);

		// run task with the least privileges
		if (FAILED(pPrincipal->put_RunLevel(TASK_RUNLEVEL_LUA)))
			break;

		// create settings for the task
		if (FAILED(pTask->get_Settings(&pSettings)))
			break;

		// set starting values for the task
		if (FAILED(pSettings->put_StartWhenAvailable(VARIANT_TRUE)))
			break;

		// get triggers collection
		if (FAILED(pTask->get_Triggers(&pTriggerCollection)))
			break;

		// add registration trigger to the task
		if (FAILED(pTriggerCollection->Create(TASK_TRIGGER_REGISTRATION, &pTrigger)))
			break;

		if (FAILED(pTrigger->QueryInterface(IID_IRegistrationTrigger, (void **)&pRegistrationTrigger)))
			break;

		pRegistrationTrigger->put_Id(_bstr_t(L"Trigger Sandbox Evasion"));

		if (FAILED(pRegistrationTrigger->put_Delay(_bstr_t(L"PT0S"))))
			break;

		// add action to created task
		if (FAILED(pTask->get_Actions(&pActionCollection)))
			break;

		if (FAILED(pActionCollection->Create(TASK_ACTION_EXEC, &pAction)))
			break;

		// get executable task pointer
		if (FAILED(pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction)))
			break;

		// set path & working directory for executable	
		if (FAILED(pExecAction->put_Path(_bstr_t(app_name))))
			break;

		if (FAILED(pExecAction->put_Arguments(_bstr_t(app_params))))
			break;

		if (FAILED(pExecAction->put_WorkingDirectory(_bstr_t(cur_dir))))
			break;

		// save task in task root folder
		if (FAILED(pTaskRootFolder->RegisterTaskDefinition(_bstr_t(task_name), pTask, TASK_CREATE_OR_UPDATE, _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(L""), &pRegisteredTask)))
			break;

		succ = true;

	} while (false);

	// Clean up
	if (pService) pService->Release();
	if (pTaskRootFolder) pTaskRootFolder->Release();
	if (pTask) pTask->Release();
	if (pRegInfo) pRegInfo->Release();
	if (pPrincipal) pPrincipal->Release();
	if (pSettings) pSettings->Release();
	if (pTriggerCollection) pTriggerCollection->Release();
	if (pTrigger) pTrigger->Release();
	if (pRegistrationTrigger) pRegistrationTrigger->Release();
	if (pActionCollection) pActionCollection->Release();
	if (pAction) pAction->Release();
	if (pExecAction) pExecAction->Release();
	if (pRegisteredTask) pRegisteredTask->Release();

	CoUninitialize();

	return succ;
}


bool run_self_tsched_xp_down(const wchar_t *app_params, DWORD *ppid) {
	ITaskScheduler *pTaskScheduler = NULL;
	ITask *pTask = NULL;
	IPersistFile *pPersistFile = NULL;
	ITrigger *pTrigger = NULL;
	ITaskTrigger *pTaskTrigger = NULL;
	WORD piNewTrigger;

	bool succ = false;
	wchar_t task_name[] = L"sandbox evasion tsched";

	wchar_t	app_name[MAX_PATH + 1] = {},
		cur_dir[MAX_PATH + 1] = {};
	HRESULT hres;

	if (!ppid)
		return false;

	if (!get_app_full_name(NULL, app_name, _countof(app_name), cur_dir, _countof(cur_dir)))
		return false;

	TASK_TRIGGER tt = {};

	tt.wBeginDay = 1;
	tt.wBeginMonth = 1;
	tt.wBeginYear = 1900;
	tt.cbTriggerSize = 0x30;
	tt.MinutesDuration = -1;
	tt.TriggerType = TASK_TIME_TRIGGER_ONCE;

	do {
		// Initialize COM
		if (FAILED(CoInitializeEx(NULL, COINIT_MULTITHREADED)))
			break;

		//  Set general COM security levels
		hres = CoInitializeSecurity(NULL, -1, NULL, NULL, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, 0, NULL);
		if (FAILED(hres) && hres != RPC_E_TOO_LATE)
			break;

		// create an instance of Task Scheduler
		if (FAILED(CoCreateInstance(CLSID_CTaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskScheduler, (void **)&pTaskScheduler)))
			break;

		// delete previous task
		pTaskScheduler->Delete(task_name);

		// create a new task
		if (FAILED(pTaskScheduler->NewWorkItem(task_name, CLSID_CTask, IID_ITask, (IUnknown**)&pTask)))
			break;

		// set trigger for task
		if (FAILED(pTask->CreateTrigger(&piNewTrigger, &pTaskTrigger)))
			break;

		if (FAILED(pTaskTrigger->SetTrigger(&tt)))
			break;

		// specify application & parametres to run
		if (FAILED(pTask->SetApplicationName(app_name)))
			break;

		if (FAILED(pTask->SetParameters(app_params)))
			break;

		if (FAILED(pTask->SetWorkingDirectory(cur_dir)))
			break;

		if (FAILED(pTask->SetFlags(TASK_FLAG_RUN_ONLY_IF_LOGGED_ON)))
			break;
		/*
		if (FAILED(pTask->SetApplicationName(L"notepad.exe")))
			break;
		*/
		// save task to the disk
		if (FAILED(pTask->QueryInterface(IID_IPersistFile, (void **)&pPersistFile)))
			break;

		hres = pPersistFile->Save(NULL, TRUE);
		if (FAILED(hres))
			break;

		hres = pTask->Run();
		if (FAILED(hres))
			break;

		// FIXME: remove Sleep
		HRESULT phrStatus;
		hres = pTask->GetStatus(&phrStatus);
		fprintf(stdout, "{+} Task status: 0x%x\n", phrStatus);

		succ = true;

	} while (false);

	// cleanup
	if (pTaskScheduler) pTaskScheduler->Release();
	if (pTask) pTask->Release();
	if (pPersistFile) pPersistFile->Release();
	if (pTrigger) pTrigger->Release();
	if (pTaskTrigger) pTaskTrigger->Release();

	CoUninitialize();

	return succ;
}


bool pipe_server_get_pid(const wchar_t *pipe_name, uint32_t wait_timeout, DWORD *pid) {
	HANDLE hPipe;
	char buffer[sizeof(DWORD)] = {};
	DWORD dwRead;
	DWORD dwTotalRead = 0;
	const uint32_t max_retries_count = 10;
	uint32_t retries_count;
	BOOL cnp;
	DWORD dwWritten = 0;
	const BOOL status = TRUE;
	BOOL write_status = FALSE;

	if (!max_retries_count)
		return false;

	if (!pid)
		return false;

	hPipe = CreateNamedPipeW(
		pipe_name,
		PIPE_ACCESS_DUPLEX,
		PIPE_NOWAIT | PIPE_TYPE_MESSAGE | PIPE_READMODE_BYTE,
		1,
		sizeof(buffer),
		sizeof(buffer),
		wait_timeout,
		NULL
	);

	if (hPipe == INVALID_HANDLE_VALUE)
		return false;

	// wait for connecting in non-blocking loop
	retries_count = 0;
	while (retries_count++ < max_retries_count) {
		cnp = ConnectNamedPipe(hPipe, NULL);
		if (cnp || (!cnp && GetLastError() == ERROR_PIPE_CONNECTED)) {
			// read input message packet

			dwTotalRead = 0;
			while (ReadFile(hPipe, buffer + dwTotalRead, sizeof(buffer) - dwTotalRead, &dwRead, NULL) && dwRead)
				dwTotalRead += dwRead;

			// write response back
			write_status = WriteFile(hPipe, &status, sizeof(status), &dwWritten, NULL);
			break;
		}

		Sleep(wait_timeout / max_retries_count);
	}

	DisconnectNamedPipe(hPipe);
	
	if (dwTotalRead != sizeof(buffer) || dwWritten != sizeof(BOOL) || !write_status)
		return false;

	memcpy(pid, buffer, sizeof(buffer));

	return true;
}


bool pipe_server_send_pid(const wchar_t *pipe_name, uint32_t wait_timeout, DWORD pid) {
	char buffer_write[sizeof(DWORD)] = {};
	BOOL buffer_read;
	DWORD dwRead;

	memcpy(buffer_write, &pid, sizeof(buffer_write));

	return CallNamedPipeW(pipe_name, buffer_write, sizeof(buffer_write), &buffer_read, sizeof(buffer_read), &dwRead, NMPWAIT_USE_DEFAULT_WAIT);
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


bool check_regkey_exists(HKEY h_key, const std::string &regkey) {
	HKEY h_regkey;

	if (RegOpenKeyExA(h_key, regkey.c_str(), 0, KEY_READ | (is_wow64() ? KEY_WOW64_64KEY : 0), &h_regkey) != ERROR_SUCCESS)
		return false;

	RegCloseKey(h_regkey);
	return true;
}

bool check_regkey_subkey_value(HKEY h_key, const std::string &regkey, const std::string &subkey, const std::string &value) {
	HKEY h_regkey;
	unsigned char regkey_buff[512] = {};
	DWORD regkey_buff_size = sizeof(regkey_buff);

	if (RegOpenKeyExA(h_key, regkey.c_str(), 0, KEY_READ | (is_wow64() ? KEY_WOW64_64KEY : 0), &h_regkey) != ERROR_SUCCESS)
		return false;

	if (RegQueryValueExA(h_regkey, subkey.c_str(), NULL, NULL, regkey_buff, &regkey_buff_size) != ERROR_SUCCESS) {
		RegCloseKey(h_regkey);
		return false;
	}

	RegCloseKey(h_regkey);

	if (StrStrIA(reinterpret_cast<LPCSTR>(regkey_buff), value.c_str()))

	return true;
}

bool check_regkey_enum_keys(HKEY h_key, const std::string &key, const std::string &subkey) {
	HKEY h_regkey;
	LSTATUS status;
	DWORD i;
	char subkeyi[255] = {};
	DWORD subkey_size;
	FILETIME ftLast;
	bool found;

	if (RegOpenKeyExA(h_key, key.c_str(), 0, KEY_READ | (is_wow64() ? KEY_WOW64_64KEY : 0), &h_regkey) != ERROR_SUCCESS)
		return false;

	i = 0;
	do {
		subkey_size = _countof(subkeyi);
		status = RegEnumKeyExA(h_regkey, i++, subkeyi, &subkey_size, NULL, NULL, NULL, &ftLast);
		if (status == ERROR_SUCCESS)
			if (StrStrIA(subkeyi, subkey.c_str())) {
				found = true;
				break;
			}
	} while (status == ERROR_SUCCESS);

	RegCloseKey(h_regkey);

	return found;
}

bool check_regkey_enum_values(HKEY h_key, const std::string &key, const std::string &value) {
	/*
	HKEY h_regkey;
	LSTATUS status;
	DWORD i;
	char value_name[16383] = {};
	DWORD value_size;
	FILETIME ftLast;
	bool found;

	if (RegOpenKeyExA(h_key, key.c_str(), 0, KEY_READ | (is_wow64() ? KEY_WOW64_64KEY : 0), &h_regkey) != ERROR_SUCCESS)
		return false;

	i = 0;
	do {
		value_size = _countof(value_name);
		status = RegEnumKeyExA(h_regkey, i++, value_name, &value_size, NULL, NULL, NULL, &ftLast);
		if (status == ERROR_SUCCESS)
			if (StrStrIA(value_name, value.c_str())) {
				found = true;
				break;
			}
	} while (status == ERROR_SUCCESS);

	RegCloseKey(h_regkey);

	return found;
	*/

	// TODO: implement
	return false;
}

bool check_file_exists(const file_name_t &fname) {
	if (!is_wow64())
		return GetFileAttributesA(fname.c_str()) != INVALID_FILE_ATTRIBUTES;

	PVOID pOld = NULL;
	disable_wow64_fs_redirection(&pOld);

	bool present = GetFileAttributesA(fname.c_str()) != INVALID_FILE_ATTRIBUTES;
	revert_wow64_fs_redirection(pOld);

	return present;
}

bool check_device_exists(const file_name_t &devname) {
	HANDLE hDevice;

	if ((hDevice = CreateFileA(devname.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)) != INVALID_HANDLE_VALUE) {
		CloseHandle(hDevice);
		return true;
	}

	return false;
}

bool disable_wow64_fs_redirection(PVOID pOld) {
	FARPROC fnWow64DisableWow64FsRedirection;

	fnWow64DisableWow64FsRedirection = GetProcAddress(GetModuleHandleW(L"kernel32"), "Wow64DisableWow64FsRedirection");

	return fnWow64DisableWow64FsRedirection && reinterpret_cast<BOOL(WINAPI *)(PVOID *)>(fnWow64DisableWow64FsRedirection)(&pOld);
}


bool revert_wow64_fs_redirection(PVOID pOld) {
	FARPROC fnWow64RevertWow64FsRedirection;

	fnWow64RevertWow64FsRedirection = GetProcAddress(GetModuleHandleW(L"kernel32"), "Wow64RevertWow64FsRedirection");

	return fnWow64RevertWow64FsRedirection && reinterpret_cast<BOOL(WINAPI *)(PVOID)>(fnWow64RevertWow64FsRedirection)(pOld);
}

bool check_process_is_running(const process_name_t &proc_name) {
	HANDLE hSnapshot;
	PROCESSENTRY32 pe = {};
	pe.dwSize = sizeof(pe);

	bool present = false;

	hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return false;

	if (Process32First(hSnapshot, &pe)) {
		do {
			if (!StrCmpI(pe.szExeFile, proc_name.c_str())) {
				present = true;
				break;
			}
		} while (Process32Next(hSnapshot, &pe));
	}

	CloseHandle(hSnapshot);
	return present;
}


bool check_mac_vendor(const std::string &ven_id) {
	// vendor id contains 3 bytes => 
	if (ven_id.length() != 3 * 2)
		return false;

	unsigned char vendor_id[3] = {};
	std::string s;
	char *p = NULL;
	IP_ADAPTER_ADDRESSES *pl, *hpl;
	bool found = false;

	for (unsigned char i = 0; i < _countof(vendor_id); ++i) {
		s = "";
		s += ven_id[i * 2];
		s += ven_id[i * 2 + 1];
		vendor_id[i] = static_cast<unsigned char>(strtol(s.c_str(), &p, 16));
		if (!p || *p != 0)
			return false;
	}

	// check if mac id is one of forbidden
	pl = get_adapters_addresses();
	if (!pl)
		return false;

	hpl = pl;
	do {
		if (pl->PhysicalAddressLength == 6) {
			if (!memcmp(pl->PhysicalAddress, vendor_id, sizeof(vendor_id))) {
				found = true;
				break;
			}
		}
		pl = pl->Next;
	} while (pl);

	free(hpl);

	return found;
}


bool check_adapter_name(const std::string &adapter_name) {
	bool found = false;
	IP_ADAPTER_ADDRESSES *pl, *hpl;
	std::wstring adapter_name_w;

	adapter_name_w.assign(adapter_name.begin(), adapter_name.end());

	pl = get_adapters_addresses();
	if (!pl)
		return false;

	hpl = pl;
	do {
		if (StrStrIW(pl->Description, adapter_name_w.c_str())) {
			found = true;
			break;
		}
		pl = pl->Next;
	} while (pl);

	free(hpl);

	return found;
}


PIP_ADAPTER_ADDRESSES get_adapters_addresses() {
	ULONG size = 0;
	IP_ADAPTER_ADDRESSES *l;

	// get size for the structure
	if (GetAdaptersAddresses(AF_UNSPEC, 0, 0, 0, &size) != ERROR_BUFFER_OVERFLOW)
		return NULL;

	l = reinterpret_cast<IP_ADAPTER_ADDRESSES *>(calloc(size, sizeof(char)));
	if (!l)
		return NULL;

	if (GetAdaptersAddresses(AF_UNSPEC, 0, 0, l, &size) != ERROR_SUCCESS) {
		free(l);
		return NULL;
	}

	return l;
}


bool check_driver_object(const std::string &directory_object, const std::string &driver_object) {
	// TODO: implement
	return false;
}

/*
 * Source code taken from VMDE project: https://github.com/hfiref0x/VMDE
 */
extern "C" BOOL enable_privilege(DWORD PrivilegeName, BOOL fEnable) {
	BOOL bResult = FALSE;
	NTSTATUS status;
	HANDLE hToken;
	TOKEN_PRIVILEGES TokenPrivileges;
	HMODULE hNtdll;

	hNtdll = GetModuleHandleW(L"ntdll");

	NTSTATUS(NTAPI *fnNtOpenProcessToken)(HANDLE, ACCESS_MASK, PHANDLE) = (NTSTATUS(NTAPI *)(HANDLE, ACCESS_MASK, PHANDLE))(GetProcAddress(hNtdll, "NtOpenProcessToken"));
	NTSTATUS(NTAPI *fnNtAdjustPrivilegesToken)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG) = (NTSTATUS(NTAPI *)(HANDLE, BOOLEAN, PTOKEN_PRIVILEGES, ULONG, PTOKEN_PRIVILEGES, PULONG))(GetProcAddress(hNtdll, "NtAdjustPrivilegesToken"));
	NTSTATUS(NTAPI *fnZwClose)(HANDLE) = (NTSTATUS(NTAPI *)(HANDLE))(GetProcAddress(hNtdll, "ZwClose"));

	if (!fnNtOpenProcessToken || !fnNtAdjustPrivilegesToken || !fnZwClose)
		return FALSE;

	status = fnNtOpenProcessToken(
		GetCurrentProcess(),
		TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
		&hToken);

	if (!NT_SUCCESS(status)) {
		return bResult;
	}

	TokenPrivileges.PrivilegeCount = 1;
	TokenPrivileges.Privileges[0].Luid.LowPart = PrivilegeName;
	TokenPrivileges.Privileges[0].Luid.HighPart = 0;
	TokenPrivileges.Privileges[0].Attributes = (fEnable) ? SE_PRIVILEGE_ENABLED : 0;
	status = fnNtAdjustPrivilegesToken(hToken, FALSE, &TokenPrivileges,
		sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, NULL);
	if (status == STATUS_NOT_ALL_ASSIGNED) {
		status = STATUS_PRIVILEGE_NOT_HELD;
	}
	bResult = NT_SUCCESS(status);
	fnZwClose(hToken);
	return bResult;
}

/*
 * Source code taken from VMDE project: https://github.com/hfiref0x/VMDE
 */
extern "C" PVOID get_firmware_table(PULONG pdwDataSize, DWORD dwSignature, DWORD dwTableID) {
	NTSTATUS Status;
	ULONG Length;
	HANDLE hProcess = NULL;
	ULONG uAddress;
	SYSTEM_FIRMWARE_TABLE_INFORMATION *sfti = NULL;
	SIZE_T memIO = 0;

	CLIENT_ID cid;
	OBJECT_ATTRIBUTES attr;
	MEMORY_REGION_INFORMATION memInfo;
	HMODULE hNtdll;

	hNtdll = GetModuleHandleW(L"ntdll");

	NTSTATUS(NTAPI *fnNtQuerySystemInformation)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG) = (NTSTATUS(NTAPI *)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG))(GetProcAddress(hNtdll, "NtQuerySystemInformation"));
	NTSTATUS(NTAPI *fnZwQueryVirtualMemory)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T) = (NTSTATUS(NTAPI *)(HANDLE, PVOID, MEMORY_INFORMATION_CLASS, PVOID, SIZE_T, PSIZE_T))(GetProcAddress(hNtdll, "ZwQueryVirtualMemory"));
	NTSTATUS(NTAPI *fnZwOpenProcess)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) = (NTSTATUS(NTAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID))(GetProcAddress(hNtdll, "ZwOpenProcess"));
	NTSTATUS(NTAPI *fnNtReadVirtualMemory)(HANDLE, PVOID, PVOID, ULONG, PULONG) = (NTSTATUS(NTAPI *)(HANDLE, PVOID, PVOID, ULONG, PULONG))(GetProcAddress(hNtdll, "NtReadVirtualMemory"));
	NTSTATUS(NTAPI *fnZwClose)(HANDLE) = (NTSTATUS(NTAPI *)(HANDLE))(GetProcAddress(hNtdll, "ZwClose"));
	ULONG(NTAPI *fnCsrGetProcessId)() = (ULONG(NTAPI *)())(GetProcAddress(hNtdll, "CsrGetProcessId"));

	if (!fnNtQuerySystemInformation || !fnZwQueryVirtualMemory || !fnZwOpenProcess || !fnNtReadVirtualMemory || !fnZwClose || !fnCsrGetProcessId)
		return NULL;

	// Use documented GetSystemFirmwareTable instead, this is it raw implementation.
	if (g_osver.dwMajorVersion > 5) {

		Length = 0x1000;
		sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
		if (sfti != NULL) {
			sfti->Action = SystemFirmwareTable_Get;
			sfti->ProviderSignature = dwSignature;
			sfti->TableID = dwTableID;
			sfti->TableBufferLength = Length;

			// Query if info class available and if how many memory we need.
			Status = fnNtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
			if (
				(Status == STATUS_INVALID_INFO_CLASS) ||
				(Status == STATUS_INVALID_DEVICE_REQUEST) ||
				(Status == STATUS_NOT_IMPLEMENTED) ||
				(Length == 0)
				)
			{
				HeapFree(GetProcessHeap(), 0, sfti);
				return NULL;
			}

			if ((!NT_SUCCESS(Status)) || (Status == STATUS_BUFFER_TOO_SMALL)) {

				HeapFree(GetProcessHeap(), 0, sfti);

				sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, Length);
				if (sfti != NULL) {
					sfti->Action = SystemFirmwareTable_Get;
					sfti->ProviderSignature = dwSignature;
					sfti->TableID = dwTableID;
					sfti->TableBufferLength = Length;
					Status = fnNtQuerySystemInformation(SystemFirmwareTableInformation, sfti, Length, &Length);
					if (!NT_SUCCESS(Status)) {
						HeapFree(GetProcessHeap(), 0, sfti);
						return NULL;
					}
					if (pdwDataSize) {
						*pdwDataSize = Length;
					}
				}
			}
			else {
				if (pdwDataSize) {
					*pdwDataSize = Length;
				}
			}
		}
	}
	else {
		//
		//  On pre Vista systems the above info class unavailable, but all required information.
		//  can be found inside csrss  memory space (stored here for VDM purposes) at few fixed addresses.
		//
		if ((dwSignature != FIRM) && (dwSignature != RSMB)) {
			return NULL;
		}

		// we are interested only in two memory regions 
		switch (dwSignature) {
		case FIRM:
			uAddress = 0xC0000; // FIRM analogue 
			break;
		case RSMB:
			uAddress = 0xE0000; // RSMB analogue 
			break;
		default:
			return NULL;
			break;
		}

		Length = 0;
		cid.UniqueProcess = (HANDLE)fnCsrGetProcessId();
		cid.UniqueThread = 0;
		InitializeObjectAttributes(&attr, NULL, 0, 0, NULL);

		// open csrss, reg. client debug privilege set 
		Status = fnZwOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &attr, &cid);
		if (NT_SUCCESS(Status)) {

			// get memory data region size for buffer allocation
			Status = fnZwQueryVirtualMemory(hProcess, (PVOID)uAddress, MemoryRegionInformation, &memInfo, sizeof(MEMORY_REGION_INFORMATION), &memIO);
			if (NT_SUCCESS(Status)) {

				sfti = (PSYSTEM_FIRMWARE_TABLE_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, memInfo.RegionSize);
				if (sfti != NULL) {

					// read data to our allocated buffer 
					Status = fnNtReadVirtualMemory(hProcess, (PVOID)uAddress, sfti, memInfo.RegionSize, &memIO);
					if (NT_SUCCESS(Status)) {

						if (pdwDataSize) {
							*pdwDataSize = (ULONG)memInfo.RegionSize;
						}
					}
					else {
						HeapFree(GetProcessHeap(), 0, sfti);
						return NULL;
					}
				}
			}
			fnZwClose(hProcess);
		}
	}
	return sfti;
}

/*
 * Source code taken from VMDE project: https://github.com/hfiref0x/VMDE
 */
extern "C" BOOL scan_mem(CHAR *Data, ULONG dwDataSize, CHAR *lpFindData, ULONG dwFindDataSize) {
	UINT i;
	SIZE_T(NTAPI *fnRtlCompareMemory)(const VOID *, const VOID *, SIZE_T) = (SIZE_T(NTAPI *)(const VOID *, const VOID *, SIZE_T))(GetProcAddress(GetModuleHandleW(L"ntdll"), "RtlCompareMemory"));
	if (!fnRtlCompareMemory)
		return FALSE;

	if (
		(Data == NULL) ||
		(lpFindData == NULL)
		)
	{
		return FALSE;
	}

	if (dwFindDataSize > dwDataSize) {
		return FALSE;
	}

	for (i = 0; i < dwDataSize - dwFindDataSize; i++) {
		if (fnRtlCompareMemory(Data + i, lpFindData, dwFindDataSize) == dwFindDataSize) {
			return TRUE;
		}
	}
	return FALSE;
}

/*
 * Source code taken from VMDE project: https://github.com/hfiref0x/VMDE
 */
extern "C" BOOL check_system_objects(const std::wstring &directory, const std::wstring &name) {
	ULONG				ctx, rlen;
	HANDLE				hDirectory = NULL;
	OBJECT_ATTRIBUTES	attr;
	UNICODE_STRING		sname;
	BOOL				found = FALSE;
	POBJECT_DIRECTORY_INFORMATION	objinf;
	HMODULE				hNtdll;

	hNtdll = GetModuleHandleW(L"ntdll");

	VOID(NTAPI *fnRtlInitUnicodeString)(PUNICODE_STRING, PCWSTR) = (VOID(NTAPI *)(PUNICODE_STRING, PCWSTR))(GetProcAddress(hNtdll, "RtlInitUnicodeString"));
	NTSTATUS(WINAPI *fnNtOpenDirectoryObject)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES) = (NTSTATUS(WINAPI *)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES))(GetProcAddress(hNtdll, "NtOpenDirectoryObject"));
	NTSTATUS(WINAPI *fnNtQueryDirectoryObject)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG) = (NTSTATUS(WINAPI *)(HANDLE, PVOID, ULONG, BOOLEAN, BOOLEAN, PULONG, PULONG))(GetProcAddress(hNtdll, "NtQueryDirectoryObject"));
	NTSTATUS(NTAPI *fnZwClose)(HANDLE) = (NTSTATUS(NTAPI *)(HANDLE))(GetProcAddress(hNtdll, "ZwClose"));

	if (!fnRtlInitUnicodeString || !fnNtOpenDirectoryObject || !fnNtQueryDirectoryObject || !fnZwClose)
		return FALSE;

	__try {

		RtlSecureZeroMemory(&sname, sizeof(sname));
		fnRtlInitUnicodeString(&sname, directory.c_str());
		InitializeObjectAttributes(&attr, &sname, OBJ_CASE_INSENSITIVE, NULL, NULL);
		if (!NT_SUCCESS(fnNtOpenDirectoryObject(&hDirectory, DIRECTORY_QUERY, &attr)))
			return FALSE;

		// Enumerate objects in directory.
		ctx = 0;
		do {
			rlen = 0;
			if (fnNtQueryDirectoryObject(hDirectory, NULL, 0, TRUE, FALSE, &ctx, &rlen) != STATUS_BUFFER_TOO_SMALL)
				break;

			objinf = (POBJECT_DIRECTORY_INFORMATION)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, rlen);
			if (!objinf)
				break;

			if (!NT_SUCCESS(fnNtQueryDirectoryObject(hDirectory, objinf, rlen, TRUE, FALSE, &ctx, &rlen))) {
				HeapFree(GetProcessHeap(), 0, objinf);
				break;
			}

			// check if object name is forbidden
			if (StrStrIW(objinf->Name.Buffer, name.c_str())) {
				HeapFree(GetProcessHeap(), 0, objinf);
				found = TRUE;
				break;
			}

			HeapFree(GetProcessHeap(), 0, objinf);

		} while (TRUE);

		if (hDirectory)
			fnZwClose(hDirectory);

	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		found = FALSE;
	}

	return found;
}