#ifndef _CUCKOO_H
#define _CUCKOO_H

#include "ve_detection.h"
#include "helper.h"
#include <Windows.h>
#include "json.h"


namespace SandboxEvasion {
// enum class ProcessWorkingMode { MASTER, SLAVE };
enum class ProcessCheckHooksFunc { GET_MODULE_HANDLE_W, GET_PROC_ADDRESS, OPEN_EVENT_W, SET_EVENT, CLOSE_HANDLE, EXIT_PROCESS, READ_PROCESS_MEMORY, GET_CURRENT_PROCESS, ZW_DELAY_EXECUTION, ZW_CREATE_PROCESS, ZW_CREATE_THREAD, ZW_OPEN_THREAD, Count };
const uint32_t MAGIC_WHTL_PROC_ARGS = 0xBAADF00D;
const unsigned char I_magic[] = { 0x0F, 0x0B, 0x0F, 0x0B, 0xCC, 0xCC, 0xCC, 0xCC, 0x0F, 0x0B, 0x0F, 0x0B, 0xCC, 0xCC, 0xCC, 0xCC };
const uint32_t EXCEPTION_MAXCOUNT = 1024 + 50;
const wchar_t task_pipe_name[] = L"\\\\.\\pipe\\task_sched_se";
const uint32_t task_proc_wait_timeout = 2500;

class Cuckoo : public VEDetection {
public:
	Cuckoo(const json_tiny &j) : 
		VEDetection(j) {
		module_name = std::string("CUCKOO");
	}
	virtual ~Cuckoo() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();

	bool CheckUnbalancedStack() const;
	bool CheckInfiniteSleep();
	bool CheckDelaysAccumulation();
	bool CheckDelaysSkip() const;
	bool IsAgentPresent() const;
	bool CheckFunctionHooks() const;
	bool IsConfigurationPresent() const;
	bool CheckEventName();
	bool CheckAgentArtifacts() const;
	bool IsPidReusedNotTracked(ProcessWorkingMode) const;
	bool IsWMINotTracked(ProcessWorkingMode) const;
	bool IsTaskSchedNotTracked(ProcessWorkingMode) const;
	bool IsServiceNotTracked() const;
	bool IsWhitelistedNotTracked() const;
	bool IsAnalyzerDeadNotTracked(ProcessWorkingMode) const;
	bool CheckExceptionsNumber(ProcessWorkingMode) const;

	static const event_name_t GeneratePrintableBuffer(SIZE_T length, DWORD seed = SEED_DEFAULT);
	static ULARGE_INTEGER CompareDatetime(SYSTEMTIME *st_1, SYSTEMTIME *st_2);

private:

	// FIXME: make common function for both implementations
	bool RunMasterSlaveThreads(	DWORD (WINAPI SandboxEvasion::Cuckoo::*thread_master)(LPVOID), 
								DWORD (WINAPI SandboxEvasion::Cuckoo::*thread_slave)(LPVOID));
	bool RunMasterSlaveThreadsEventName(DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_master)(LPVOID),
										DWORD(WINAPI SandboxEvasion::Cuckoo::*thread_slave)(LPVOID));

	// FIXME: add wrappers for master and slave threads

	bool NotifyFunctionHooks() const;

	// functions related to the hooking check
	bool CheckFunctionHooks(HANDLE, const func_hooked_t &) const;
	bool IsFunctionHooked(HANDLE, FARPROC) const;
	bool IsCodeTrampoline(const BYTE*, SIZE_T) const;
	bool IsCodePushRet(const BYTE*, SIZE_T) const;

	bool IsPidReusedNotTrackedMaster() const;
	bool IsPidReusedNotTrackedSlave() const;

	bool CheckExceptionsNumberMaster() const;
	bool CheckExceptionsNumberSlave() const;

	bool IsWMINotTrackedMaster() const;
	bool IsWMINotTrackedSlave() const;

	bool IsTaskSchedNotTrackedMaster() const;
	bool IsTaskSchedNotTrackedSlave() const;

	bool IsAnalyzerDeadNotTrackedMaster() const;
	bool IsAnalyzerDeadNotTrackedSlave() const;

	bool WaitForNotificationFromSlaveUsingEvent(const event_name_t &, HANDLE, HANDLE, DWORD) const;

	bool CommunicateWithAgent(const network_endpoint_t &net_endpoint, unsigned char *agent_response, size_t *agent_response_size) const;
	bool CheckResponseIsAgent(const unsigned char *response, size_t response_size) const;

	bool KillSuspiciousProcesses() const;

	DWORD WINAPI ThreadInfiniteSleepMaster(LPVOID);
	DWORD WINAPI ThreadInfiniteSleepSlave(LPVOID);
	DWORD WINAPI ThreadDelaysAccumulationMaster(LPVOID);
	DWORD WINAPI ThreadDelaysAccumulationSlave(LPVOID);
	DWORD WINAPI ThreadCheckEventNameMaster(LPVOID);
	DWORD WINAPI ThreadCheckEventNameSlave(LPVOID);

	volatile DWORD dwThreadMasterSlaveBarrier;
};

typedef DWORD(WINAPI SandboxEvasion::Cuckoo::*THREAD_ROUTINE)(LPVOID);

struct thread_wrapper {
	const Cuckoo *obj;					// address of instance
	THREAD_ROUTINE thread_routine;		// address of routine to execute
	LPVOID thread_params;				// arguments for the original thread routine
};

typedef struct thread_params_sleep_inf {
	const wchar_t *event_name;		// event name
	DWORD threads_count;			// number of threads to wait before execution continue
	HANDLE h_slave_thread;			// slave thread handle
	bool detected;					// sleep infinite bug detected
} tpsi, *ptpsi;

typedef struct thread_params_event_name {
	DWORD threads_count;	// number of threads to wait before execution continue
	HANDLE hProcess;		// process' handle
	HANDLE hThread;			// process' thread handle
	DWORD pid;				// process Id
	HANDLE h_slave_thread;	// slave thread handle
	bool detected;			// specific event name detected
} tpen, *ptpen;

/*
* Wrapper for thread routines in classes
*/
extern "C" DWORD WINAPI thread_wrapper_routine(LPVOID);

typedef struct proc_check_hooks_thread_arg {
	wchar_t event_name[EVENT_NAME_MAX_LEN];															// event name used for notification
	FARPROC __func_ptrs[static_cast<unsigned int>(SandboxEvasion::ProcessCheckHooksFunc::Count)];	// pointers to functions that are used in injected process space
} pchta;

bool resolve_func_addresses(const func_hooked_t &fn, pchta *pta_args);
}

#endif // !_CUCKOO_H

