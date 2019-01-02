#include "cuckoo.h"
#include <WinNT.h>
#include <map>
#include <Ntsecapi.h>
#include "helper.h"
#include <time.h> // FIXME: should be removed
#include <list>
#include <vector>
#include <set>
#include <memory>
#include <string.h>
#include <Iphlpapi.h>
#include <WinInet.h>
#include <iostream>
#include "config.h"
#include "nt.h"
#include <math.h>


#define SLAVE_EXIT_CODE_SUCCESS 0
#define SLAVE_EXIT_CODE_FAILED	1
#define EXCEPTION_CHECK_EXC		0xE0000001

#define TASK_HOOKS_NOT_DETECTED 0x40035000
#define TASK_HOOKS_DETECTED		0x40035001

#define LOCALHOST				0x0100007f

#ifndef KI_USER_SHARED_DATA
#define KI_USER_SHARED_DATA         0x7FFE0000
#endif

#ifndef SharedUserData
#define SharedUserData  ((KUSER_SHARED_DATA * const) KI_USER_SHARED_DATA)
#endif

#pragma comment(lib, "wininet.lib")


#pragma data_seg(".whtld")
#pragma section(".whtl", read,write,execute)
#pragma comment(linker, "/section:.whtl,RWE")
#pragma comment(linker, "/merge:.whtld=.whtl")


namespace se = SandboxEvasion;

#define DATA_SECTION_ALLOC __declspec(allocate(".whtld"))
#define WHTL_CODE_SEG __declspec(code_seg(".whtl"))


// function should reside in separate section in order to be easily copied to external process
WHTL_CODE_SEG
static DWORD WINAPI process_check_hooks_impl() {
	HANDLE hEvent;
	bool b_set_event;
	bool b_hooks_found;
	size_t i;

	// should be patched while writing a memory
	LPVOID args = reinterpret_cast<LPVOID>(SandboxEvasion::MAGIC_WHTL_PROC_ARGS);

	se::pchta *_pta = static_cast<se::pchta *>(args);

	if (!_pta) {
		// just crash application
		__asm {
			ud2
		}
		return NULL;
	}

	HMODULE (WINAPI *__GetModuleHandle__)(LPCWSTR) = reinterpret_cast<HMODULE(WINAPI *)(LPCWSTR)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::GET_MODULE_HANDLE_W)]);
	FARPROC(WINAPI *__GetProcAddress__)(HMODULE, LPCSTR) = reinterpret_cast<FARPROC(WINAPI *)(HMODULE, LPCSTR)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::GET_PROC_ADDRESS)]);

	HANDLE (WINAPI *__OpenEventW__)(DWORD, BOOL, LPCWSTR) = reinterpret_cast<HANDLE(WINAPI *)(DWORD, BOOL, LPCWSTR)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::OPEN_EVENT_W)]);
	BOOL (WINAPI *__SetEvent__)(HANDLE) = reinterpret_cast<BOOL(WINAPI *)(HANDLE)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::SET_EVENT)]);
	BOOL (WINAPI *__CloseHandle__)(HANDLE) = reinterpret_cast<BOOL(WINAPI *)(HANDLE)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::CLOSE_HANDLE)]);
	VOID (WINAPI *__ExitProcess__)(UINT) = reinterpret_cast<VOID(WINAPI *)(UINT)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::EXIT_PROCESS)]);
	BOOL (WINAPI *__ReadProcessMemory__)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *) = reinterpret_cast<BOOL(WINAPI *)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::READ_PROCESS_MEMORY)]);
	HANDLE (WINAPI *__GetCurrentProcess__)(void) = reinterpret_cast<HANDLE(WINAPI *)(void)>(_pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::GET_CURRENT_PROCESS)]);

	if (!(hEvent = __OpenEventW__(EVENT_ALL_ACCESS, FALSE, _pta->event_name)))
		__ExitProcess__(SLAVE_EXIT_CODE_FAILED);

	b_hooks_found = false;

	const size_t fn_count = 4;
	LPVOID func_addresses[fn_count] = {};

	for (i = 0; i < fn_count; ++i)
		func_addresses[i] = _pta->__func_ptrs[static_cast<unsigned int>(se::ProcessCheckHooksFunc::ZW_DELAY_EXECUTION) + i];

	// check function hooks here
	HANDLE hProcess = __GetCurrentProcess__();
	BYTE code[0x10];
	DWORD dwNumberOfBytesRead;
	size_t code_i;

	for (i = 0; i < fn_count; ++i) {
		memset(code, 0x0, sizeof(code));
		if (!__ReadProcessMemory__(
			hProcess,
			func_addresses[i],
			code,
			sizeof(code),
			&dwNumberOfBytesRead))
			continue;

		// check trampolines
		code_i = 0;
		// skip all nops at the beggining
		while (code_i < sizeof(code) && code[code_i] == 0x90)
			++code_i;

		// check jmp opcodes
		b_hooks_found = (i < sizeof(code)) && (code[code_i] == 0xe9 || code[code_i] == 0xeb);

		if (b_hooks_found)
			break;

		// check push retn
		code_i = 0;
		// skip all nops at the beggining
		while (code_i < sizeof(code) && code[code_i] == 0x90)
			++code_i;

		if (code_i + 5 < sizeof(code)) {
			// check push/retn instructions
			b_hooks_found = code[i] == 0x68 && code[i + 5] == 0xc3;
		}

		if (b_hooks_found)
			break;
	}

	// check if hooks were found
	if (!b_hooks_found) {
		b_set_event = !__SetEvent__(hEvent);
		__CloseHandle__(hEvent);
		__ExitProcess__(SLAVE_EXIT_CODE_SUCCESS ? b_set_event : SLAVE_EXIT_CODE_FAILED);
	}

	__CloseHandle__(hEvent);
	__ExitProcess__(SLAVE_EXIT_CODE_SUCCESS);

	return 0;
}

WHTL_CODE_SEG
__declspec(naked)
static void process_check_hooks(void) {
	__asm {
		// magic
		ud2;
		ud2;
		int 3;
		int 3;
		int 3;
		int 3;
		ud2;
		ud2;
		int 3;
		int 3;
		int 3;
		int 3;
		// call to function
		call process_check_hooks_impl;
	}
}


namespace {
	static LARGE_INTEGER kli = { 0xFFFFFFFFFD8F0000ll }; // FIXME: change
	static struct {
		BOOLEAN Alertable;
		PLARGE_INTEGER DelayInterval;
	} kZwDelayExecutionArgs = {0, &kli};
} // anonymous


#define ARG_ITEM(x) sizeof(x), &x


namespace SandboxEvasion {

VEDetection* Cuckoo::create_instance(const json_tiny &j) {
	return new Cuckoo(j);
}

void Cuckoo::CheckAllCustom() {
	bool d;
	std::pair<std::string, std::string> report;
	std::string ce_name;

	ce_name = Config::cc2s[Config::ConfigCuckoo::UNBALANCED_STACK];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckUnbalancedStack();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::DELAYS_ACCUMULATION];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckDelaysAccumulation();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::SOCKET_TIMEOUT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSocketTimeout();
		report = GenerateReportEntry(ce_name + std::string("_probe1"), json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::INFINITE_DELAY];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckInfiniteSleep();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::DELAY_INTERVAL];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsDelayIntervalModified();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::TICK_COUNT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckTickCountIntegrity();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::FUNCTION_HOOKS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckFunctionHooks();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::AGENT_ARTIFACTS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckAgentArtifacts();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::CUCKOOMON_CONFIGURATION];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsConfigurationPresent();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::WHITELISTED_PROCESS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsWhitelistedNotTracked();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::EVENT_NAME];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckEventName();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::RAISED_EXCEPTIONS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckExceptionsNumber(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::WMI_PROCESS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsWMINotTracked(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::TASK_SCHED_PROCESS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsTaskSchedNotTracked(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::PID_REUSE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsPidReusedNotTracked(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::AGENT_LISTENER];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsAgentPresent();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::SUSPENDED_THREAD];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsSuspendedThreadNotTracked();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::SOCKET_TIMEOUT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSocketTimeout();
		report = GenerateReportEntry(ce_name + std::string("_probe2"), json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::RESULTSERVER_CONNECTION];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsResultserverConnected();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cc2s[Config::ConfigCuckoo::DEAD_ANALYZER];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsAnalyzerDeadNotTracked(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}
}

/*
 * Check for the hooked functions using the canary on the lower addresses of stack
 */
bool Cuckoo::CheckUnbalancedStack() const {
	// FIXME: add 4 more functions that are hooked by cuckoomon
	// TODO: make this configurable ???
	usf_t f = {
		{ lib_name_t(L"ntdll"), { 
			{sizeof(void *), NULL, "ZwDelayExecution", ARG_ITEM(kZwDelayExecutionArgs) }
		} }
	};
	const uint8_t canary[8] = { 0xDE, 0xAD, 0xBE, 0xEF, 0xDE, 0xAD, 0xBE, 0xEF };

	uint32_t args_size;
	const void *args_buff;
	uint32_t reserved_size;
	uint32_t reserved_size_after_call;
	uint32_t canary_size;
	FARPROC func;
	bool us_detected;
	void *canary_addr = (void *)&canary[0];
	
	static_assert((sizeof(canary) % sizeof(void *)) == 0, "Invalid canary alignement");
	
	for (auto it = f.begin(), end = f.end(); it != end; ++it) {
		for (auto &vi : it->second) {
			vi.func_addr = GetProcAddress(GetModuleHandleW(it->first.c_str()), vi.func_name.c_str());

			// call to Unbalanced Stack
			args_size = vi.args_size;
			args_buff = vi.args_buff;
			canary_size = sizeof(canary);
			reserved_size = sizeof(void *) + vi.local_vars_size + canary_size;
			reserved_size_after_call = reserved_size + args_size;
			func = vi.func_addr;
			us_detected = false;

			__asm {
				pusha
				mov ecx, args_size
				sub esp, ecx
				mov esi, args_buff
				mov edi, esp
				cld
				rep movsb
				sub esp, reserved_size
				mov ecx, canary_size
				mov esi, canary_addr
				mov edi, esp
				rep movsb
				add esp, reserved_size
				mov eax, func
				call eax
				sub esp, reserved_size_after_call
				mov ecx, canary_size
				mov esi, canary_addr
				mov edi, esp
				repz cmpsb
				cmp ecx, 0
				setnz us_detected
				add esp, reserved_size_after_call
				popa
			}

			if (us_detected)
				return true;
		}
	}

	return false;	 
}


/*
 * Check for INFINITE delay sleeping bug in cuckoomon
 * TODO: method should be called within first N seconds of execution process (5 by default in cuckoomon)
 */
bool Cuckoo::CheckInfiniteSleep() {
	return RunMasterSlaveThreads(&Cuckoo::ThreadInfiniteSleepMaster, &Cuckoo::ThreadInfiniteSleepSlave);
}


/*
 * Check if the values for sleeps are accumulated
 * TODO: method should be called within first N seconds of execution process (5 by default in cuckoomon)
 */
bool Cuckoo::CheckDelaysAccumulation() {
	return RunMasterSlaveThreads(&Cuckoo::ThreadDelaysAccumulationMaster, &Cuckoo::ThreadDelaysAccumulationSlave);
}

/*
 * Check if socket timeout equals to the normal delay sleep
 */
bool Cuckoo::CheckSocketTimeout() {
	return RunMasterSlaveThreads(&Cuckoo::ThreadCheckSocketTimeoutMaster, &Cuckoo::ThreadCheckSocketTimeoutSlave);
}


bool Cuckoo::CheckDelaysSkip() const {
	// TODO: implement
	return false;
}


bool Cuckoo::IsAgentPresent() const {
	// TODO: add support for IPv6, GetTcp6Table

	// get all current IPv4 TCP connections
	const MIB_TCPTABLE *p_tcp_table = reinterpret_cast<const MIB_TCPTABLE *>(get_tcp_table());
	network_endpoints_t net_endpoints;
	const size_t http_response_size = 1024;
	unsigned char agent_response[http_response_size + 1] = {};
	size_t http_resp_size;

	if (!p_tcp_table)
		return false;

	// retrieve all LISTENING sockets information
	get_tcp_entries(p_tcp_table, net_endpoints, MIB_TCP_STATE_LISTEN, false);
	free(const_cast<MIB_TCPTABLE *>(p_tcp_table));

	/*
	size_t nep_c = net_endpoints.size();
	size_t i = 1;
	*/

	for (auto & ne : net_endpoints) {
		http_resp_size = http_response_size;

		// fprintf(stdout, "{+} Communicating with %u/%u endpoints\n", i++, nep_c);
		// establish connection & send crafted requests and wait for response
		if (!CommunicateWithAgent(ne, agent_response, &http_resp_size))
			continue;

		// check if received response belongs to agent
		if (CheckResponseIsAgent(agent_response, http_resp_size))
			return true;
	}

	return false;
}


bool Cuckoo::IsResultserverConnected() const {
	// TODO: add support for IPv6, GetTcp6Table

	// get all current IPv4 TCP connections
	const MIB_TCPTABLE *p_tcp_table = reinterpret_cast<const MIB_TCPTABLE *>(get_tcp_table());
	network_endpoints_t net_endpoints;
	
	if (!p_tcp_table)
		return false;

	// retrieve all ESTABLISHED connections
	get_tcp_entries(p_tcp_table, net_endpoints, MIB_TCP_STATE_ESTAB, true);
	free(const_cast<MIB_TCPTABLE *>(p_tcp_table));

	for (auto & ne : net_endpoints) {
		if(ntohs(static_cast<INTERNET_PORT>(ne.second)) == 2042)
			return true;
	}

	return false;
}


bool Cuckoo::CheckFunctionHooks() const {
	// return True if functions are hooked
	// TODO: make this configurable ???
	func_hooked_t func_hooked = {{
			lib_name_t(L"ntdll"), {
				func_name_t("ZwDelayExecution"),
				func_name_t("ZwCreateProcess"),
				func_name_t("ZwCreateThread"),
				func_name_t("ZwOpenThread"),
				func_name_t("NtOpenProcess"),
				func_name_t("NtTerminateProcess"),
				func_name_t("NtCreateSection"),
				func_name_t("NtMapViewOfSection"),
				func_name_t("NtUnmapViewOfSection"),
				func_name_t("NtClose"),
				func_name_t("NtAllocateVirtualMemory"),
				func_name_t("NtFreeVirtualMemory"),
				func_name_t("NtWriteVirtualMemory"),
				func_name_t("LdrLoadDll"),
				func_name_t("RtlInitUnicodeString"),
				func_name_t("RtlDecompressBuffer"),
				func_name_t("RtlMoveMemory"),
				func_name_t("RtlZeroMemory"),
				func_name_t("strstr"),
				func_name_t("tolower")
			}
		}
	};

	return CheckFunctionHooks(GetCurrentProcess(), func_hooked);
}


bool Cuckoo::IsConfigurationPresent() const {
	// TODO: do we need to create a thread here ???

	// my implementation
	/*
	char temp_path[MAX_PATH + 1] = { 0 };

	if (!GetTempPathA(sizeof(temp_path) - 1, temp_path))
		return false;
	*/

	wchar_t app_params[] = L"--action --cfg";
	PROCESS_INFORMATION pi = {};
	const size_t max_retries = 5;
	const DWORD retry_delay = 500;

	if (!run_self_susp(app_params, &pi))
		return false;

	// original cuckoo implementation (except of wchars usage)
	wchar_t *temp_path = NULL;
	if (!get_envvar_w(L"TEMP", &temp_path))
		return false;

	pfi _pfi = { NULL, false, NULL };
	wchar_t old_filename[MAX_PATH + 1] = {};
	wchar_t new_filename[MAX_PATH + 1] = {};

	_snwprintf_s(old_filename, _countof(old_filename), _TRUNCATE, L"%d.ini", pi.dwProcessId);
	_snwprintf_s(new_filename, _countof(new_filename), _TRUNCATE, L"cuckoo_%lu.ini", pi.dwProcessId);

	size_t mri = 0;
	while (mri++ < max_retries) {
		// check for configuration file of cuckoomon
		memset(&_pfi, 0, sizeof(_pfi));
		enumerate_directory_w(temp_path, 0, 0, NULL, &_pfi, { file_name_w_t(old_filename) });
		if (_pfi.matched)
			break;

		// check for configuration file of monitor
		memset(&_pfi, 0, sizeof(_pfi));
		enumerate_directory_w(L"C:\\", 0, 0, NULL, &_pfi, { file_name_w_t(new_filename) });
		if (_pfi.matched)
			break;

		Sleep(retry_delay);
	}

	free(temp_path);
	temp_path = NULL;

	// process termination and objects closing
	TerminateProcess(pi.hProcess, 1);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return _pfi.matched;
}


bool Cuckoo::CheckEventName() {
	return RunMasterSlaveThreadsEventName(&Cuckoo::ThreadCheckEventNameMaster, &Cuckoo::ThreadCheckEventNameSlave);
}


bool Cuckoo::CheckAgentArtifacts() const {
	// TODO: should user some generic function and be configurable from the JSON file ???

	// TODO: should we do only regexp as a file to find and use callback function for performing some extra checks???
	std::list<file_name_w_t> cuckoo_files {
		file_name_w_t(L"analyzer.py"),
		file_name_w_t(L"analysis.conf")
	};

	pfi _pfi = { NULL, false, NULL };

	enumerate_directory_w(L"C:\\", 1, 0, NULL, &_pfi, cuckoo_files);
	
	return _pfi.matched;
}


bool Cuckoo::IsPidReusedNotTracked(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return IsPidReusedNotTrackedMaster();
	case ProcessWorkingMode::SLAVE:
		return IsPidReusedNotTrackedSlave();
	default:
		return false;
	}
}


bool Cuckoo::IsWMINotTracked(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return IsWMINotTrackedMaster();
	case ProcessWorkingMode::SLAVE:
		return IsWMINotTrackedSlave();
	default:
		return false;
	}
}


bool Cuckoo::IsTaskSchedNotTracked(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return IsTaskSchedNotTrackedMaster();
	case ProcessWorkingMode::SLAVE:
		return IsTaskSchedNotTrackedSlave();
	default:
		return false;
	}
}


bool Cuckoo::IsServiceNotTracked() const {
	// TODO: implement
	return false;
}


bool Cuckoo::IsWhitelistedNotTracked() const {
	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	GetStartupInfoW(&si);

	PROCESS_INFORMATION pi = {};
	bool wla_detected = false;

	LPCVOID inj_code, inj_data;
	LPVOID section_code;
	unsigned char *ppatch;
	bool whitelisted_proc_detected = false;
	event_name_t event_name;
	pchta pta_args = {};

	// TODO: should be taken from configuration ???
	std::list<file_path_t> whitelisted_processes {
		file_path_t(L"C:\\WINDOWS\\system32\\dwwin.exe"),
		file_path_t(L"C:\\WINDOWS\\system32\\dumprep.exe"),
		file_path_t(L"C:\\WINDOWS\\system32\\drwtsn32.exe")
	};

	SYSTEM_INFO sys_i = {};
	GetSystemInfo(&sys_i);

	DWORD section_va;
	LPCVOID process_check_hooks_ep;

	bool cp_mode = CheckFunctionHooks();

	// init function addresses

	if (!resolve_func_addresses({
								{ L"kernel32", { "GetModuleHandleW", "GetProcAddress", "OpenEventW", "SetEvent", "CloseHandle", "ExitProcess", "ReadProcessMemory", "GetCurrentProcess" } },
								{ L"ntdll", { "ZwDelayExecution", "ZwCreateProcess", "ZwCreateThread", "ZwOpenThread" } }
								}, &pta_args))
		return false;

	for (auto &wp : whitelisted_processes) {
		// prepare non-const string in non-ugly way
		std::vector<wchar_t> app(wp.begin(), wp.end());
		app.push_back(0);
		
		// create process specified in the whitelist
		if (!CreateProcessW(
			NULL,
			&app[0],
			NULL,
			NULL,
			TRUE,
			CREATE_SUSPENDED, 
			NULL,
			NULL,
			&si,
			&pi
			)) {
			continue;
		}

		// if process was successfully created, then inject a stub there that will be responsible for checking if process is hooked
		// in case is not hooked, then we are cool and cuckoo is evaded

		// create event name used for communication with child process
		event_name = GeneratePrintableBuffer(EVENT_NAME_MAX_LEN - 1, pi.dwProcessId);

		// copy event name to structure
		memset(pta_args.event_name, 0x0, sizeof(pta_args.event_name));
		if (wcscpy_s(pta_args.event_name, EVENT_NAME_MAX_LEN, event_name.c_str())) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			continue;
		}

		// patch code that will be responsible for testing if functions are hooked, prepare a stub that will be responsible for checking

		inj_data = inject_data(pi.hProcess, reinterpret_cast<const data_t *>(&pta_args), sizeof(pta_args));

		// patch address of argument for the thread
		section_code = calloc(sys_i.dwPageSize, sizeof(code_t));
		if (!section_code) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			continue;
		}

		// find virtual address where section is loaded
		section_va = align_down(reinterpret_cast<DWORD>(process_check_hooks), sys_i.dwPageSize);

		memcpy(section_code, reinterpret_cast<const void*>(section_va), sys_i.dwPageSize);

		ppatch = __memmem(reinterpret_cast<const code_t*>(section_code), sys_i.dwPageSize, reinterpret_cast<const unsigned char *>(&SandboxEvasion::MAGIC_WHTL_PROC_ARGS), sizeof(SandboxEvasion::MAGIC_WHTL_PROC_ARGS));

		if (!ppatch) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			free(section_code);
			continue;
		}

		memcpy(ppatch, &inj_data, sizeof(SandboxEvasion::MAGIC_WHTL_PROC_ARGS));

		process_check_hooks_ep = __memmem(reinterpret_cast<const code_t*>(section_va), sys_i.dwPageSize, SandboxEvasion::I_magic, sizeof(SandboxEvasion::I_magic));

		inj_code = inject_code(pi.hProcess, reinterpret_cast<const code_t *>(section_code), sys_i.dwPageSize);

		// align process_check_hooks_ep as far as it is copied to another address in another process
		process_check_hooks_ep = reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD>(process_check_hooks_ep) + (reinterpret_cast<DWORD>(inj_code) - section_va) + sizeof(SandboxEvasion::I_magic));

		if (!inj_data || !inj_code || !process_check_hooks_ep) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			free(section_code);
			continue;
		}

		// execute injected code to the process
		if (!thread_context_execute_code(pi.hThread, reinterpret_cast<LPTHREAD_START_ROUTINE>(process_check_hooks_ep), const_cast<LPVOID>(inj_data), TRUE)) {
			TerminateProcess(pi.hProcess, 0);
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			free(section_code);
			continue;
		}

		// FIXME: should timeout be configurable?
		wla_detected = WaitForNotificationFromSlaveUsingEvent(event_name, pi.hProcess, pi.hThread, 100);

		// process has terminated itself
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		free(section_code);

		if (wla_detected) {
			break;
		}

		// TODO: do we need to collect error code of terminated process here???
	}

	EvasionMachineMode es = get_evasion_status(cp_mode, !wla_detected);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}

bool Cuckoo::IsSuspendedThreadNotTracked() const {
	STARTUPINFOW si = {};
	si.cb = sizeof(si);
	GetStartupInfoW(&si);

	PROCESS_INFORMATION pi = {};
	bool st_detected = false;

	LPCVOID inj_code, inj_data;
	LPVOID section_code = NULL;
	unsigned char *ppatch;
	event_name_t event_name;
	pchta pta_args = {};

	SYSTEM_INFO sys_i = {};
	GetSystemInfo(&sys_i);

	DWORD section_va;
	LPCVOID process_check_hooks_ep;

	bool ok = true;

	HANDLE hHelperThread = INVALID_HANDLE_VALUE;

	bool cp_mode = CheckFunctionHooks();

	// init function addresses

	if (!resolve_func_addresses({
		{ L"kernel32",{ "GetModuleHandleW", "GetProcAddress", "OpenEventW", "SetEvent", "CloseHandle", "ExitProcess", "ReadProcessMemory", "GetCurrentProcess" } },
		{ L"ntdll",{ "ZwDelayExecution", "ZwCreateProcess", "ZwCreateThread", "ZwOpenThread" } }
	}, &pta_args))
		return false;

	if (!run_self_susp(NULL, &pi))
		return false;

	do {
		// if process was successfully created, then inject a stub there that will be responsible for checking if process is hooked
		// in case is not hooked, then we are cool and cuckoo is evaded

		// create event name used for communication with child process
		event_name = GeneratePrintableBuffer(EVENT_NAME_MAX_LEN - 1, pi.dwProcessId);

		// copy event name to structure
		memset(pta_args.event_name, 0x0, sizeof(pta_args.event_name));
		if (wcscpy_s(pta_args.event_name, EVENT_NAME_MAX_LEN, event_name.c_str())) {
			ok = false;
			break;
		}

		// patch code that will be responsible for testing if functions are hooked, prepare a stub that will be responsible for checking

		inj_data = inject_data(pi.hProcess, reinterpret_cast<const data_t *>(&pta_args), sizeof(pta_args));

		// patch address of argument for the thread
		section_code = calloc(sys_i.dwPageSize, sizeof(code_t));
		if (!section_code) {
			ok = false;
			break;
		}

		// find virtual address where section is loaded
		section_va = align_down(reinterpret_cast<DWORD>(process_check_hooks), sys_i.dwPageSize);

		memcpy(section_code, reinterpret_cast<const void*>(section_va), sys_i.dwPageSize);

		ppatch = __memmem(reinterpret_cast<const code_t*>(section_code), sys_i.dwPageSize, reinterpret_cast<const unsigned char *>(&SandboxEvasion::MAGIC_WHTL_PROC_ARGS), sizeof(SandboxEvasion::MAGIC_WHTL_PROC_ARGS));

		if (!ppatch) {
			ok = false;
			break;
		}

		memcpy(ppatch, &inj_data, sizeof(SandboxEvasion::MAGIC_WHTL_PROC_ARGS));

		process_check_hooks_ep = __memmem(reinterpret_cast<const code_t*>(section_va), sys_i.dwPageSize, SandboxEvasion::I_magic, sizeof(SandboxEvasion::I_magic));

		inj_code = inject_code(pi.hProcess, reinterpret_cast<const code_t*>(section_code), sys_i.dwPageSize);

		// align process_check_hooks_ep as far as it is copied to another address in another process
		process_check_hooks_ep = reinterpret_cast<LPCVOID>(reinterpret_cast<DWORD>(process_check_hooks_ep) + (reinterpret_cast<DWORD>(inj_code) - section_va) + sizeof(SandboxEvasion::I_magic));

		if (!inj_data || !inj_code || !process_check_hooks_ep) {
			ok = false;
			break;
		}

		// create a new thread that will not be tracked
		if (!execute_code(pi.hProcess, reinterpret_cast<LPTHREAD_START_ROUTINE>(process_check_hooks_ep), const_cast<LPVOID>(inj_data), &hHelperThread, CREATE_SUSPENDED)) {
			ok = false;
			break;
		}

		// FIXME: should timeout be configurable?
		st_detected = WaitForNotificationFromSlaveUsingEvent(event_name, pi.hProcess, hHelperThread, 100);

	} while (false);

	// clean

	TerminateProcess(pi.hProcess, 0);
	CloseHandle(pi.hThread);
	CloseHandle(hHelperThread);
	CloseHandle(pi.hProcess);

	if (section_code) {
		free(section_code);
		section_code = NULL;
	}

	if (!ok)
		return false;

	EvasionMachineMode es = get_evasion_status(cp_mode, !st_detected);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}

// ATTENTION: Should be called as last method withon Cuckoo Environment test, because ruins all environment
bool Cuckoo::IsAnalyzerDeadNotTracked(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return IsAnalyzerDeadNotTrackedMaster();
	case ProcessWorkingMode::SLAVE:
		return IsAnalyzerDeadNotTrackedSlave();
	default:
		return false;
	}
}


bool Cuckoo::CheckExceptionsNumber(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return CheckExceptionsNumberMaster();
	case ProcessWorkingMode::SLAVE:
		return CheckExceptionsNumberSlave();
	default:
		return false;
	}
}

bool Cuckoo::IsDelayIntervalModified() const {
	LARGE_INTEGER DelayInterval = { 0 };
	LARGE_INTEGER cDelayInterval = { 0 };

	cDelayInterval.QuadPart = 0xFFFFFFFFFD8F0000ll;

	NTSTATUS (NTAPI *lpZwDelayExecution)(BOOLEAN, PLARGE_INTEGER) = reinterpret_cast<NTSTATUS(NTAPI *)(BOOLEAN, PLARGE_INTEGER)>(GetProcAddress(GetModuleHandleW(L"ntdll"), "ZwDelayExecution"));

	if (!lpZwDelayExecution)
		return false;

	DelayInterval = cDelayInterval;

	lpZwDelayExecution(FALSE, &DelayInterval);

	return !!memcmp(&DelayInterval, &cDelayInterval, sizeof(LARGE_INTEGER));;
}

bool Cuckoo::CheckTickCountIntegrity() const {
	DWORD tick_count_f, tick_count_ku;
	DWORD tick_count_diff;
	const uint32_t delay_ms = 4000; // timeout in milliseconds
	KUSER_SHARED_DATA * t = SharedUserData;
	DWORD major_version;

	// sleep before applying GetTickCount check
	SleepEx(delay_ms, FALSE);

	major_version = static_cast<DWORD>(LOBYTE(LOWORD(GetVersion())));

	// check both tick count & kuser_shared_data
	tick_count_f = GetTickCount();

	if (major_version == 5)
		tick_count_ku = static_cast<ULONG>((static_cast<ULONGLONG>(SharedUserData->TickCountLowDeprecated) * SharedUserData->TickCountMultiplier) >> 24);
	else if (major_version > 5)
		tick_count_ku = SharedUserData->TickCountMultiplier * (SharedUserData->TickCount.High1Time << 8) + 
		(SharedUserData->TickCount.LowPart * (unsigned __int64)SharedUserData->TickCountMultiplier >> 24);

	tick_count_diff = abs(static_cast<long>(tick_count_ku - tick_count_f));

	return tick_count_diff > 100;
}


DWORD Cuckoo::ThreadInfiniteSleepMaster(LPVOID thread_params) {
	ptpsi p_thread_param_si = static_cast<ptpsi>(thread_params);
	HANDLE hEvent;
	DWORD event_state;

	if (!p_thread_param_si)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_param_si->threads_count != dwThreadMasterSlaveBarrier);

	if (!(hEvent = CreateEventW(NULL, FALSE, FALSE, p_thread_param_si->event_name)))
		return FALSE;
	
	event_state = WaitForSingleObject(hEvent, 100); // FIXME: dwMilliseconds constant
	if (event_state == WAIT_OBJECT_0) {
		p_thread_param_si->detected = TRUE;
		CloseHandle(hEvent);
		return TRUE;
	}
	else if (event_state == WAIT_TIMEOUT) {
		p_thread_param_si->detected = FALSE;
		TerminateThread(p_thread_param_si->h_slave_thread, 0);
		CloseHandle(hEvent);

		return TRUE;
	}

	return FALSE;
}


DWORD Cuckoo::ThreadInfiniteSleepSlave(LPVOID thread_params) {
	ptpsi p_thread_param_si = static_cast<ptpsi>(thread_params);
	HANDLE hEvent;
	BOOL b_set_event;

	if (!p_thread_param_si)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_param_si->threads_count != dwThreadMasterSlaveBarrier);

	// perform infinite delay sleep
	Sleep(INFINITE);
	
	// in case INFINITE delay is skipped, the code will continue execution from the following instructions
	if (!(hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, p_thread_param_si->event_name)))
		return FALSE;

	b_set_event = !SetEvent(hEvent);
	CloseHandle(hEvent);

	return b_set_event;
}


DWORD Cuckoo::ThreadDelaysAccumulationMaster(LPVOID thread_params) {
	ptpsi p_thread_param_si = static_cast<ptpsi>(thread_params);
	HANDLE hEvent;
	DWORD event_state;
	// SYSTEMTIME st_start, st_end;
	LARGE_INTEGER st_start, st_end;

	if (!p_thread_param_si)
		return FALSE;
	
	NTSTATUS(NTAPI *fnNtQuerySystemTime)(OUT PLARGE_INTEGER SystemTime) = (NTSTATUS(NTAPI *)(OUT PLARGE_INTEGER SystemTime))GetProcAddress(GetModuleHandleW(L"ntdll"), "NtQuerySystemTime");
	if (!fnNtQuerySystemTime)
		return FALSE;

	// get current system time at the begining of a function
	fnNtQuerySystemTime(&st_start);
	// FIXME: should be deleted
	// printf("Seconds passed: %llu\n", st_start.QuadPart / (10000 * 1000));

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_param_si->threads_count != dwThreadMasterSlaveBarrier);

	if (!(hEvent = CreateEventW(NULL, FALSE, FALSE, p_thread_param_si->event_name)))
		return FALSE;

	event_state = WaitForSingleObject(hEvent, 100); // FIXME: dwMilliseconds constant
	if (event_state == WAIT_OBJECT_0) {
		// sleep was definitely skipped, but let's check the current date
		fnNtQuerySystemTime(&st_end);

		// printf("Seconds passed: %llu\n", st_end.QuadPart / (10000 * 1000));
		unsigned long long diff = (st_end.QuadPart - st_start.QuadPart) / (10000 * 1000);
		// printf("Difference between two intervals: %llu\n", diff);

		// FIXME: value should not be taken from ass :)
		p_thread_param_si->detected = diff > 2 * 24 * 60 * 60;

		CloseHandle(hEvent);
		return TRUE;
	}
	else if (event_state == WAIT_TIMEOUT) {
		p_thread_param_si->detected = FALSE;
		TerminateThread(p_thread_param_si->h_slave_thread, 0);
		CloseHandle(hEvent);

		return TRUE;
	}

	return FALSE;
}


DWORD Cuckoo::ThreadDelaysAccumulationSlave(LPVOID thread_params) {
	ptpsi p_thread_param_si = static_cast<ptpsi>(thread_params);
	HANDLE hEvent;
	BOOL b_set_event;

	if (!p_thread_param_si)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_param_si->threads_count != dwThreadMasterSlaveBarrier);

	// perform sleep for a few days, like from 2 till 5
	// FIXME: generate random number of days to sleep
	Sleep(3 * 24 * 60 * 60 * 1000); // 3 days to Zzz

	// in case delay is skipped, the code will continue execution from the following instructions
	if (!(hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, p_thread_param_si->event_name)))
		return FALSE;

	b_set_event = !SetEvent(hEvent);
	CloseHandle(hEvent);

	return b_set_event;
}


/*
 * Generates random buffer using printable characters.
 * If suceeded, then pointer to generated buffer is returned.
 * Returned buffer should be freed after usage.
 */
const event_name_t Cuckoo::GeneratePrintableBuffer(SIZE_T length, DWORD seed) {
	// FARPROC fpRtlGenRandom;
	event_name_t event_name(L"");

	if (length <= 0)
		return event_name;

	// FIXME: add RtlGenRandom & hexlify usage
	/*
	if (!RtlGenRandom((LPVOID)pEventName, length))
		return NULL;
	*/

	srand(static_cast<unsigned int>(time(NULL) ? seed == SEED_DEFAULT : seed));

	for (SIZE_T i = 0; i < length; ++i)
		event_name += rand() % 26 + 'a';

	return event_name;
}

bool Cuckoo::IsAnalyzerDeadNotTrackedMaster() const {
	wchar_t app_params[] = L"--action --dan";
	event_name_t event_name;
	bool dan_escape_detected = false;
	PROCESS_INFORMATION pi = { 0 };

	bool cp_mode = CheckFunctionHooks();

	if (!KillSuspiciousProcesses())
		return false;

	if (!run_self_susp(app_params, &pi))
		return false;

	event_name = GeneratePrintableBuffer(8, pi.dwProcessId);

	dan_escape_detected = WaitForNotificationFromSlaveUsingEvent(event_name, pi.hProcess, pi.hThread, 100);

	TerminateProcess(pi.hProcess, 0);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	EvasionMachineMode es = get_evasion_status(cp_mode, !dan_escape_detected);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}

bool Cuckoo::IsAnalyzerDeadNotTrackedSlave() const {
	return NotifyFunctionHooks();
}

bool Cuckoo::RunMasterSlaveThreads(	DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_master)(LPVOID),
									DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_slave)(LPVOID)) {
	DWORD tid_master, tid_slave;
	HANDLE hThread_master, hThread_slave;
	event_name_t event_name;

	event_name = GeneratePrintableBuffer(7);

	dwThreadMasterSlaveBarrier = 0;

	tpsi thread_param_si = { event_name.c_str(), 2, FALSE };

	thread_wrapper
		tw_m = { this, thread_master, &thread_param_si },
		tw_s = { this, thread_slave, &thread_param_si };

	// create slave thread
	if (!(hThread_slave = CreateThread(
		NULL,
		0,
		thread_wrapper_routine,
		&tw_s,
		0,
		&tid_slave
		))) {

		return false;
	}

	thread_param_si.h_slave_thread = hThread_slave;

	// create master thread
	if (!(hThread_master = CreateThread(
		NULL,
		0,
		thread_wrapper_routine,
		&tw_m,
		0,
		&tid_master
		))) {

		TerminateThread(hThread_slave, 0);

		return false;
	}

	// wait for threads to finish
	HANDLE hThreads[] = { hThread_master, hThread_slave };
	DWORD dwWaitObjects;
	bool si_detected = false;

	dwWaitObjects = WaitForMultipleObjects(sizeof(hThreads) / sizeof(HANDLE), hThreads, TRUE, INFINITE);
	if (dwWaitObjects == WAIT_OBJECT_0) {
		si_detected = thread_param_si.detected;
	}

	CloseHandle(hThread_master);
	CloseHandle(hThread_slave);

	return si_detected;
}


bool Cuckoo::RunMasterSlaveThreadsEventName(DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_master)(LPVOID),
											DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_slave)(LPVOID)) {

	PROCESS_INFORMATION pi = {};
	wchar_t app_params[] = L"--action --evt";

	DWORD event_name_detected = false;

	if (!run_self_susp(app_params, &pi))
		return false;

	// check if event with specific name is present implement

	tpen thread_param_en = { 2, pi.hProcess, pi.hThread, pi.dwProcessId, 0, false };

	DWORD tid_master, tid_slave;
	HANDLE hThread_master, hThread_slave;

	dwThreadMasterSlaveBarrier = 0;

	thread_wrapper
		tw_m = { this, thread_master, &thread_param_en },
		tw_s = { this, thread_slave, &thread_param_en };

	// create slave thread
	if (!(hThread_slave = CreateThread(
		NULL,
		0,
		thread_wrapper_routine,
		&tw_s,
		0,
		&tid_slave
		))) {

		return false;
	}

	thread_param_en.h_slave_thread = hThread_slave;

	// create master thread
	if (!(hThread_master = CreateThread(
		NULL,
		0,
		thread_wrapper_routine,
		&tw_m,
		0,
		&tid_master
		))) {

		TerminateThread(hThread_slave, 0);

		return false;
	}

	// wait for threads to finish
	HANDLE hThreads[] = { hThread_master, hThread_slave };
	DWORD dwWaitObjects;
	bool en_detected = false;

	dwWaitObjects = WaitForMultipleObjects(sizeof(hThreads) / sizeof(HANDLE), hThreads, TRUE, INFINITE);
	if (dwWaitObjects == WAIT_OBJECT_0) {
		en_detected = thread_param_en.detected;
	}

	CloseHandle(hThread_master);
	CloseHandle(hThread_slave);

	return en_detected;
}


bool Cuckoo::CheckFunctionHooks(HANDLE hProcess, const func_hooked_t &func_hooked) const {
	FARPROC fpProcAddr;

	for (auto lib_i = func_hooked.cbegin(), lib_e = func_hooked.cend(); lib_i != lib_e; ++lib_i) {
		for (auto &func_i : lib_i->second) {
			// enumerate over each function and get its address
			fpProcAddr = GetProcAddress(GetModuleHandleW(lib_i->first.c_str()), func_i.c_str());
			if (!fpProcAddr)
				continue;
			if (IsFunctionHooked(hProcess, fpProcAddr))
				return true;
		}
	}
	return false;
}


bool Cuckoo::IsFunctionHooked(HANDLE hProcess, FARPROC fpProcAddr) const {
	DWORD dwNumberOfBytesRead;
	BYTE code[0x10] = { };
	
	std::list<bool (SandboxEvasion::Cuckoo::*)(const BYTE*, SIZE_T) const> hook_check {
		&Cuckoo::IsCodeTrampoline,
		&Cuckoo::IsCodePushRet
	};

	if (!ReadProcessMemory(
			hProcess,
			fpProcAddr,
			code,
			sizeof(code),
			&dwNumberOfBytesRead
		))
		return false;

	// enumerate all hooking check functions
	for (auto &hc : hook_check) {
		if (((const_cast<SandboxEvasion::Cuckoo*>(this))->*(hc))(code, dwNumberOfBytesRead))
			return true;
	}

	return false;
}


bool Cuckoo::IsCodeTrampoline(const BYTE *code, SIZE_T code_size) const {
	SIZE_T i = 0;

	// skip all nops at the beggining
	while (i < code_size && code[i] == 0x90)
		++i;

	// check `jmp xxx` opcodes and `jmp dword ptr [xxx]`
	return ((i < code_size) && (code[i] == 0xe9 || code[i] == 0xeb))
		|| (i + 1 < code_size && *LPWORD(code) == 0x25FF);
}


bool Cuckoo::IsCodePushRet(const BYTE *code, SIZE_T code_size) const {
	SIZE_T i = 0;

	// skip all nops at the beggining
	while (i < code_size && code[i] == 0x90)
		++i;

	if (i + 5 >= code_size)
		return false;

	// check push/retn instructions
	return code[i] == 0x68 && code[i + 5] == 0xc3;
}


bool Cuckoo::IsPidReusedNotTrackedMaster() const {
	std::set<DWORD> pids;
	PROCESS_INFORMATION pi = {};
	wchar_t app_params[] = L"--action --pid";

	event_name_t event_name;
	bool pid_escape_detected = false;
	
	bool cp_mode = CheckFunctionHooks();

	while (true) {
		// create process with parametres
		if (!run_self_susp(app_params, &pi))
			break;

		// process is created in suspended state, check if pid is reused
		const bool found = pids.find(pi.dwProcessId) != pids.end();

		if (found) {
			event_name = GeneratePrintableBuffer(8, pi.dwProcessId);
			// FIXME: should timeout be configurable
			pid_escape_detected = WaitForNotificationFromSlaveUsingEvent(event_name, pi.hProcess, pi.hThread, 100);
		}
		else {
			TerminateProcess(pi.hProcess, 0);
			pids.insert(pi.dwProcessId);
		}

		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);

		if (found)
			break;
	}

	EvasionMachineMode es = get_evasion_status(cp_mode, !pid_escape_detected);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}


bool Cuckoo::IsPidReusedNotTrackedSlave() const {
	return NotifyFunctionHooks();
}


bool Cuckoo::NotifyFunctionHooks() const {
	event_name_t event_name;
	HANDLE hEvent;

	event_name = GeneratePrintableBuffer(8, GetCurrentProcessId());

	if (!(hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, event_name.c_str()))) {
		return false;
	}

	// check if functions are hooked by cuckoomon
	if (!CheckFunctionHooks()) {
		const bool b_set_event = !SetEvent(hEvent);
		CloseHandle(hEvent);
		return b_set_event;
	}

	CloseHandle(hEvent);
	return true;
}


bool Cuckoo::CheckExceptionsNumberMaster() const {
	PROCESS_INFORMATION pi = {};
	wchar_t app_params[] = L"--action --exc";
	DWORD ec;

	bool exception_escape_detected = false;

	if (!run_self_susp(app_params, &pi))
		return false;

	if (ResumeThread(pi.hThread) == -1) {
		CloseHandle(pi.hThread);
		CloseHandle(pi.hProcess);
		return false;
	}

	// implement wait for application to finish
	do {
		if (!GetExitCodeProcess(pi.hProcess, &ec)) {
			ec = STILL_ACTIVE;
			break;
		}
	} while (ec == STILL_ACTIVE);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	// fprintf(stdout, "{+} Exceptions process exit code: 0x%x\n", ec);

	// check if exit code is a specific one
	return ec == SLAVE_EXIT_CODE_FAILED;
}


bool Cuckoo::CheckExceptionsNumberSlave() const {
	uint32_t exceptions_count;

	// disable message boxes
	SetErrorMode(SEM_NOGPFAULTERRORBOX | SEM_FAILCRITICALERRORS);

	// generate specific number of exceptions in order to ExitProcess and thus check if we are running in sandbox environment
	for (exceptions_count = 0; exceptions_count < SandboxEvasion::EXCEPTION_MAXCOUNT; ++exceptions_count) {
		__try {
			RaiseException(EXCEPTION_CHECK_EXC + exceptions_count, 0, 0, NULL);
		}
		__except (EXCEPTION_EXECUTE_HANDLER) {
			// fprintf(stdout, "[+] Exception raised for %u time\n", exceptions_count + 1);
		}
	}

	ExitProcess(SLAVE_EXIT_CODE_SUCCESS);
	return true;
}


bool Cuckoo::IsWMINotTrackedMaster() const {
	wchar_t app_params[] = L"--action --wmi";
	DWORD pid;
	HANDLE hProcess;
	HANDLE hThread;
	std::vector<DWORD> tids;
	event_name_t event_name;
	bool wmi_escape_detected;
	
	bool cp_mode = CheckFunctionHooks();

	if (!run_self_susp_wmi(app_params, &pid))
		return false;

	// get handles to process and main thread
	if (!get_all_tids_by_pid(pid, tids) || tids.size() != 1)
		return false;

	hThread = open_thread_by_tid(tids[0], THREAD_SUSPEND_RESUME);
	if (hThread == INVALID_HANDLE_VALUE)
		return false;

	hProcess = open_process_by_pid(pid, PROCESS_QUERY_INFORMATION);
	if (hProcess == INVALID_HANDLE_VALUE) {
		// FIXME: try to open for termination ???
		CloseHandle(hThread);
		return false;
	}

	// waiting for notification from the child process

	event_name = GeneratePrintableBuffer(8, pid);
	// FIXME: should timeout be configurable
	wmi_escape_detected = WaitForNotificationFromSlaveUsingEvent(event_name, hProcess, hThread, 100);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	EvasionMachineMode es = get_evasion_status(cp_mode, !wmi_escape_detected);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}


bool Cuckoo::IsWMINotTrackedSlave() const {
	event_name_t event_name;
	HANDLE hEvent;

	event_name = GeneratePrintableBuffer(8, GetCurrentProcessId());

	if (!(hEvent = OpenEventW(EVENT_ALL_ACCESS, FALSE, event_name.c_str())))
		return false;

	// check if functions are hooked by cuckoomon
	if (!CheckFunctionHooks()) {
		const bool b_set_event = !SetEvent(hEvent);
		CloseHandle(hEvent);
		return b_set_event;
	}

	CloseHandle(hEvent);

	return false;
}


bool Cuckoo::IsTaskSchedNotTrackedMaster() const {
	wchar_t app_params[] = L"--action --tsh";
	DWORD pid;
	HANDLE hProc;
	DWORD ec;

	bool cp_mode = CheckFunctionHooks();

	if (!run_self_tsched(app_params, &pid))
		return false;

	// waiting for the task notification
	if (!pipe_server_get_pid(se::task_pipe_name, se::task_proc_wait_timeout, &pid))
		return false;

	hProc = open_process_by_pid(pid, PROCESS_QUERY_INFORMATION);
	if (hProc == INVALID_HANDLE_VALUE)
		return false;

	// check process exit code
	do {
		if (!GetExitCodeProcess(hProc, &ec)) {
			CloseHandle(hProc);
			return false;
		}
	} while (ec == STILL_ACTIVE);

	EvasionMachineMode es = get_evasion_status(cp_mode, ec != TASK_HOOKS_NOT_DETECTED);

	return es == EvasionMachineMode::SANDBOX_EVADED;
}


bool Cuckoo::IsTaskSchedNotTrackedSlave() const {
	const DWORD delay_timeout = 5000;

	if (!pipe_server_send_pid(se::task_pipe_name, se::task_proc_wait_timeout, GetCurrentProcessId())) {
		Sleep(delay_timeout);
		ExitProcess(0xFEEDDCCB); // just random exit code
	}

	Sleep(delay_timeout);
	ExitProcess(CheckFunctionHooks() ? TASK_HOOKS_DETECTED : TASK_HOOKS_NOT_DETECTED);

	return true;
}


bool Cuckoo::WaitForNotificationFromSlaveUsingEvent(const event_name_t &event_name, HANDLE hProcess, HANDLE hThread, DWORD timeout) const {
	HANDLE hEvent;
	DWORD event_state;
	DWORD child_exit_code;
	bool is_notified = false;

	if (!(hEvent = CreateEventW(NULL, FALSE, FALSE, event_name.c_str())))
		return false;

	// resume thread, then wait for notification status
	ResumeThread(hThread);

	// wait for the response from the child process about its current state
	while (true) {
		event_state = WaitForSingleObject(hEvent, timeout); // FIXME: dwMilliseconds constant
		if (event_state == WAIT_OBJECT_0) {
			is_notified = true;
			break;
		}
		else if (event_state != WAIT_TIMEOUT) {
			break;
		}
		else {
			// check process state if is finished, then detection failed, otherwise wait one more time in loop
			if (!GetExitCodeProcess(hProcess, &child_exit_code) || child_exit_code != STILL_ACTIVE) {
				// we should check here for the last time of event object was not signaled, as far as it may be signaled before exiting
				is_notified = WaitForSingleObject(hEvent, timeout) == WAIT_OBJECT_0; // FIXME: dwMilliseconds constant
				break;
			}
		}
	}

	CloseHandle(hEvent);
	return is_notified;
}


DWORD Cuckoo::ThreadCheckEventNameSlave(LPVOID thread_params)  {
	ptpen p_thread_params_en = static_cast<ptpen>(thread_params);

	if (!p_thread_params_en)
		return FALSE;

	HANDLE hProc = p_thread_params_en->hProcess;
	DWORD pid = p_thread_params_en->pid;

	char event_name[64] = {};
	HANDLE hEvent;
	const DWORD wait_timeout = 50; 
	DWORD ec;

	_snprintf_s(event_name, _countof(event_name), "CuckooEvent%d", pid);

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_params_en->threads_count != dwThreadMasterSlaveBarrier);

	// wait in loop for specific event
	while (true) {
		hEvent = OpenEvent(EVENT_ALL_ACCESS, FALSE, event_name);
		if (hEvent) {
			CloseHandle(hEvent);
			p_thread_params_en->detected = true;
			break;
		}

		if (!GetExitCodeProcess(hProc, &ec) || ec != STILL_ACTIVE) {
			p_thread_params_en->detected = false;
			break;
		}

		Sleep(wait_timeout);
	}

	return TRUE;
}


DWORD Cuckoo::ThreadCheckEventNameMaster(LPVOID thread_params) {
	ptpen p_thread_params_en = static_cast<ptpen>(thread_params);

	if (!p_thread_params_en)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_params_en->threads_count != dwThreadMasterSlaveBarrier);

	// resume thread execution from the created process
	if (ResumeThread(p_thread_params_en->hThread) == -1) {
		return TerminateThread(p_thread_params_en->h_slave_thread, 0);
	}

	return TRUE;
}


DWORD WINAPI Cuckoo::ThreadCheckSocketTimeoutMaster(LPVOID thread_params) {
	ptpsi p_thread_params_en = static_cast<ptpsi>(thread_params);
	DWORD tick_start, tick_end, time_elapsed_ms;
	const DWORD timeout = 20000; // should be multiple of 1000! The same as in slave thread
	const DWORD max_error = 100;	// max error is 100 ms
	// DWORD thread_max_wait = timeout << 1;
	DWORD thread_slave_wait_state;
	DWORD thread_slave_exit_code;

	if (!p_thread_params_en)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_params_en->threads_count != dwThreadMasterSlaveBarrier);

	tick_start = GetTickCount();

	// puts("Sleep...");
	Sleep(timeout);	// on normal systems should sleep around timeout
	// puts("Sleep finished");

	thread_slave_wait_state = WaitForSingleObject(p_thread_params_en->h_slave_thread, INFINITE);
	if (thread_slave_wait_state != WAIT_OBJECT_0)
		return FALSE;

	if (GetExitCodeThread(p_thread_params_en->h_slave_thread, &thread_slave_exit_code) == FALSE)
		return FALSE;

	if (thread_slave_exit_code == FALSE)
		return FALSE;

	// normally we should receive a notification just after sleep, because delay is the same as for socket
	// however in the Cuckoo the delays must probably will be skipped, thus time flow will not be the same
	tick_end = GetTickCount();

	time_elapsed_ms = tick_end - tick_start;

	// printf("\tRequested %d elapsed %d\n", timeout, time_elapsed_ms);

	p_thread_params_en->detected = abs(static_cast<long>(time_elapsed_ms) - static_cast<long>(timeout)) > max_error;

	return TRUE;
}


DWORD WINAPI Cuckoo::ThreadCheckSocketTimeoutSlave(LPVOID thread_params) {
	ptpsi p_thread_params_en = static_cast<ptpsi>(thread_params);

	if (!p_thread_params_en)
		return FALSE;

	// barrier sync
	InterlockedIncrement(&dwThreadMasterSlaveBarrier);
	while (p_thread_params_en->threads_count != dwThreadMasterSlaveBarrier);

	int iResult;
	DWORD timeout = 20000; // should be multiple of 1000!
	DWORD OK = TRUE;

	SOCKADDR_IN sa = { 0 };
	SOCKET sock = INVALID_SOCKET;

	// this code snippet should take around lTimeout milliseconds, take a look on Master thread for the better understanding
	do {
		memset(&sa, 0, sizeof(sa));
		sa.sin_family = AF_INET;
		// sa.sin_addr.s_addr = inet_addr("132.249.0.22");	// TODO: how to choose IP address ?
		sa.sin_addr.s_addr = inet_addr("8.8.4.3");	// WARNING: we should have a route to this IP address, however we should not be able to connect to it
		sa.sin_port = htons(64523);
		
		sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
		if (sock == INVALID_SOCKET) {
			// wprintf(L"socket function failed with error: %ld\n", WSAGetLastError());
			OK = FALSE;
			break;
		}

		// setting socket timeout
		unsigned long iMode = 1;
		iResult = ioctlsocket(sock, FIONBIO, &iMode);

		iResult = connect(sock, (SOCKADDR*)&sa, sizeof(sa));
		if (iResult == false) {
			// wprintf(L"\tconnect failed with error: %d\n", WSAGetLastError());
			OK = FALSE;
			break;
		}

		// restart the socket mode
		iMode = 0;
		iResult = ioctlsocket(sock, FIONBIO, &iMode);
		if (iResult != NO_ERROR) {
			// printf("ioctlsocket failed with error: %ld\n", iResult);
			OK = FALSE;
			break;
		}

		// fd set data
		fd_set Write, Err;
		FD_ZERO(&Write);
		FD_ZERO(&Err);
		FD_SET(sock, &Write);
		FD_SET(sock, &Err);
		timeval tv = { 0 };
		tv.tv_sec = timeout / 1000;

		// check if the socket is ready, this call should take lTimeout milliseconds
		// puts("select...");
		select(0, NULL, &Write, &Err, &tv);
		// puts("select finished");

		if (FD_ISSET(sock, &Err)) {
			// printf("Last socket error: %d\n", WSAGetLastError());
			OK = FALSE;
			break;
		}

	} while (false);

	if (sock != INVALID_SOCKET)
		closesocket(sock);

	return OK;
}


bool Cuckoo::CommunicateWithAgent(const network_endpoint_t &net_endpoint, unsigned char *agent_response, size_t *agent_response_size) const {
	HINTERNET hInternet;
	HINTERNET hSession;
	HINTERNET hRequest;
	PCSTR rgpszAcceptTypes[] = { "gzip", NULL};

	DWORD bytes_read;
	DWORD bytes_total_read;
	const DWORD net_timeout = 3000;

	struct in_addr ia;
	ia.S_un.S_addr = net_endpoint.first ? net_endpoint.first : LOCALHOST;

	char *addr = inet_ntoa(ia);
	if (!addr)
		return false;

	const INTERNET_PORT port = ntohs(static_cast<INTERNET_PORT>(net_endpoint.second));

	// fprintf(stdout, "{+}\t%s:%u\n", addr, port);

	if (!(hInternet = InternetOpenA("xmlrpclib.py/1.0.1 (by www.pythonware.com)", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0)))
		return false;

	// set timeout options for the connection and send operations
	InternetSetOptionA(hInternet, INTERNET_OPTION_RECEIVE_TIMEOUT, const_cast<DWORD *>(&net_timeout), sizeof(net_timeout));
	InternetSetOptionA(hInternet, INTERNET_OPTION_SEND_TIMEOUT, const_cast<DWORD *>(&net_timeout), sizeof(net_timeout));
	InternetSetOptionA(hInternet, INTERNET_OPTION_CONNECT_TIMEOUT, const_cast<DWORD *>(&net_timeout), sizeof(net_timeout));

	// connect to service
	if (!(hSession = InternetConnectA(hInternet, addr, port, NULL, NULL, INTERNET_SERVICE_HTTP, 0, NULL))) {
		InternetCloseHandle(hInternet);
		return false;
	}

	if (!(hRequest = HttpOpenRequestA(hSession, "POST", "RPC2", "HTTP/1.1", NULL, rgpszAcceptTypes, INTERNET_FLAG_NO_AUTH | INTERNET_FLAG_NO_COOKIES | INTERNET_FLAG_RELOAD, 0))) {
		InternetCloseHandle(hInternet);
		InternetCloseHandle(hSession);
		return false;
	}

	// FIXME: do we need to add more methods than just one get_status
	std::string headers("Content-Type: text/xml\n");
	std::string request("<?xml version='1.0'?>\n<methodCall>\n<methodName>get_status</methodName>\n<params>\n</params>\n</methodCall>\n");

	if (!HttpSendRequestA(hRequest, headers.c_str(), headers.length(), const_cast<char *>(request.c_str()), request.length())) {
		// fprintf(stdout, "[+] HttpSendRequest last error: %x\n", GetLastError());

		InternetCloseHandle(hInternet);
		InternetCloseHandle(hSession);
		InternetCloseHandle(hRequest);
		return false;
	} 
	
	bytes_read = 0;
	bytes_total_read = 0;

	while (InternetReadFile(hRequest, agent_response + bytes_total_read, *agent_response_size - bytes_total_read, &bytes_read) && bytes_read) {
		bytes_total_read += bytes_read;
		agent_response[bytes_total_read] = 0;
		bytes_read = 0;
	}

	InternetCloseHandle(hInternet);
	InternetCloseHandle(hSession);
	InternetCloseHandle(hRequest);

	*agent_response_size = bytes_total_read;

	return bytes_total_read != 0;
}


bool Cuckoo::CheckResponseIsAgent(const unsigned char *response, size_t response_size) const {
	/*
	HTTP/1.0 200 OK
	Server: BaseHTTP/0.3 Python/2.7.10
	Date: Fri, 06 May 2016 17:30:50 GMT
	Content-type: text/xml
	Content-length: 121

	<?xml version='1.0'?>
	<methodResponse>
	<params>
	<param>
	<value><int>1</int></value>
	</param>
	</params>
	</methodResponse>
	*/

	/*
	char *hex_response = hexlify(response, response_size);
	if (!hex_response)
		return false;

	fprintf(stdout, "[+] HttpResponse: %s\n", hex_response);

	free(hex_response);
	*/

	std::vector<std::basic_string<char>> matches;

	// FIXME: should be moved as a class member ?

	const std::string agent_response_re("<\\?xml version='1\\.0'\\?><methodResponse><params><param><value><int>([[:digit:]]+)</int></value></param></params></methodResponse>");
	std::string s_response(reinterpret_cast<const char *>(response));

	s_response.erase(std::remove(s_response.begin(), s_response.end(), '\r'), s_response.end());
	s_response.erase(std::remove(s_response.begin(), s_response.end(), '\n'), s_response.end());

	if (!match_regexp<char>(agent_response_re, s_response, &matches))
		return false;
	
	return matches.size() == 1;
}

/*
 * Try to kill Analyzer
 */
bool Cuckoo::KillSuspiciousProcesses() const {
	STARTUPINFO si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	std::list<std::string> proc_names { "python", "pythonw" };
	std::list<cp_pids> pc_proc;
	HANDLE hProcess;
	char proc_name[MAX_PATH + 1] = { 0 };
	char proc_args[0x80] = { 0 };

	if (get_parent_child_proc_pair(pc_proc, proc_names) == FALSE)
		return false;

	if (!pc_proc.size())
		return false;

	// try to terminate Analyzer process

	for (const auto &pc : pc_proc) {

		// kill all child processes
		if ((hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pc.second)) != NULL) {
			TerminateProcess(hProcess, 0xDEAD);
			CloseHandle(hProcess);
		}
	}

	return true;
}


/*
 * Calculate difference between two SYSTEMTIMEs
 * Return value in milliseconds
 */
ULARGE_INTEGER Cuckoo::CompareDatetime(SYSTEMTIME *st_1, SYSTEMTIME *st_2) {
	FILETIME ft;
	ULARGE_INTEGER st_diff;
	ULONGLONG v_1, v_2;

	SystemTimeToFileTime(st_1, &ft);
	st_diff.LowPart = ft.dwLowDateTime;
	st_diff.HighPart = ft.dwHighDateTime;
	v_1 = st_diff.QuadPart;

	SystemTimeToFileTime(st_2, &ft);
	st_diff.LowPart = ft.dwLowDateTime;
	st_diff.HighPart = ft.dwHighDateTime;
	v_2 = st_diff.QuadPart;

	st_diff.QuadPart = v_1 - v_2;

	return st_diff;
}

/*
bool Cuckoo::IsAgentArtifact(PVOID proc_args) {
	pfi *ppfi = static_cast<pfi *>(proc_args);
	if (!ppfi)
		return false;

	for (const auto &bs : ppfi->file_names) {
		if (!bs.compare(ppfi->file_name)) {
			ppfi->matched = true;
			return true;
		}
	}

	return false;
}
*/


extern "C"
DWORD WINAPI thread_wrapper_routine(LPVOID _ptw) {
	thread_wrapper *pTW = static_cast<thread_wrapper *>(_ptw);

	if (!pTW)
		return NULL;

	if (!pTW->thread_routine)
		return NULL;

	// return (((SandboxEvasion::Cuckoo*)(pTW->obj))->*(pTW->thread_routine))(pTW->thread_params);
	return ((const_cast<SandboxEvasion::Cuckoo*>(pTW->obj))->*(pTW->thread_routine))(pTW->thread_params);
}


bool resolve_func_addresses(const func_hooked_t &fn, pchta *pta_args) {
	size_t cnt = 0;
	FARPROC fp;
	HMODULE hModule;
	bool loaded;

	if (!pta_args)
		return false;

	for (auto &l : fn) {
		loaded = false;
		hModule = GetModuleHandleW(l.first.c_str());

		if (!hModule) {
			hModule = LoadLibraryW(l.first.c_str());
			if (!hModule)
				return false;
		}

		for (auto &f : l.second) {
			fp = GetProcAddress(hModule, f.c_str());
			if (!fp) {
				if (loaded) {
					FreeLibrary(hModule);
					return false;
				}
			}
			pta_args->__func_ptrs[cnt++] = fp;
		}

		if (loaded)
			FreeLibrary(hModule);
	}

	return true;
}

} // SandboxEvasion
