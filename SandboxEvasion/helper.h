#ifndef _HELPER_H
#define _HELPER_H

#include <stdint.h>
#include <string>
#include <WinSock2.h>
#include <Windows.h>
#include <map>
#include <vector>
#include <list>
#include <regex>
#include <Iphlpapi.h>
#include <WinDNS.h>
#include <setupapi.h>
#include <devguid.h>


#define INVALID_PID_VALUE	0xFFFFFFFF
#define SEED_DEFAULT		0xFFFFFFFF
#define INVALID_HKEY		0xFFFFFFFF
#define EVENT_NAME_MAX_LEN	0x10

#define FIRM 'FIRM'
#define RSMB 'RSMB'

typedef std::wstring lib_name_t;
typedef std::string func_name_t;
typedef std::string file_name_t;
typedef std::wstring file_name_w_t;
typedef std::wstring file_path_t;
typedef std::wstring event_name_t;
typedef std::string process_name_t;
typedef unsigned char code_t;
typedef unsigned char data_t;
typedef char* arg_t;


typedef struct unbalanced_stack_func_info {
	uint16_t local_vars_size;	// size of local variables
	FARPROC func_addr;			// address of function
	func_name_t func_name;		// name of function
	uint16_t args_size;			// size of arguments in bytes
	const void *args_buff;		// buffer with arguments
} usfi;



typedef std::vector<usfi> vf;
typedef std::map<lib_name_t, vf> usf_t;

typedef std::map<lib_name_t, std::vector<func_name_t> > func_hooked_t;

typedef struct proc_file_info_w {
	LPCWSTR file_name;		// file name TODO: should we store full path
	LPCWSTR full_path;		// TODO: do we need it ???
	LPCVOID optional_param;	// optional parametres
	bool matched;			// file matches conditions
} pfi;

typedef bool (*FILE_ROUTINE)(PVOID);
typedef LPVOID (*TORS_ROUTINE)(LPVOID);

typedef std::pair<DWORD, DWORD> network_endpoint_t;
typedef std::list<network_endpoint_t> network_endpoints_t;

typedef std::map<arg_t, arg_t> args_t;

typedef std::pair<DWORD, DWORD> cp_pids;

enum class LogMessageLevel { NO, DBG, INFO, WARNING, ERR, PANIC };
enum console_color_t { DEFAULT = 0, GREEN = FOREGROUND_GREEN, RED = FOREGROUND_RED, BLUE = FOREGROUND_BLUE };
enum class ProcessWorkingMode { MASTER, SLAVE };
enum class EvasionMachineMode { REAL_PC, SANDBOX_CHLD_MON, SANDBOX_EVADED, SANDBOX_NOT_EVADED };

typedef struct _GETVERSIONOUTPARAMS {
	BYTE bVersion;      // Binary driver version.
	BYTE bRevision;     // Binary driver revision.
	BYTE bReserved;     // Not used.
	BYTE bIDEDeviceMap; // Bit map of IDE devices.
	DWORD fCapabilities; // Bit mask of driver capabilities.
	DWORD dwReserved[4]; // For future use.
} GETVERSIONOUTPARAMS, *PGETVERSIONOUTPARAMS, *LPGETVERSIONOUTPARAMS;

void enable_verbose_mode();
void log_message(LogMessageLevel msg_l, const std::string & module, const std::string &msg, console_color_t cc=DEFAULT);

void enable_wow64();
bool is_wow64();

HKEY get_hkey(const std::string &key);

extern "C" void* __memchr(const void *s, unsigned char c, size_t n);
extern "C" unsigned char* __memmem(const unsigned char *haystack, size_t hlen, const unsigned char *needle, size_t nlen);

extern "C" BOOL cdtors(TORS_ROUTINE *p_ir, size_t ir_count);
extern "C" BOOL ctors(TORS_ROUTINE *p_ir, size_t ir_count);
extern "C" BOOL dtors(TORS_ROUTINE *p_ir, size_t ir_count);

extern "C" LPVOID ctors_wsa(LPVOID);
extern "C" LPVOID dtors_wsa(LPVOID);

extern "C" LPVOID ctors_check_wow64(LPVOID);

extern "C" LPVOID ctors_get_os_ver(LPVOID);

extern "C" DWORD find_process_by_name(LPCSTR);
extern "C" HANDLE open_process_by_pid(DWORD, DWORD);
extern "C" HANDLE open_thread_by_tid(DWORD, DWORD);
extern "C" HANDLE open_process_by_name(LPCSTR, DWORD);
extern "C" BOOL terminate_process(HANDLE);
extern "C" BOOL check_current_parent_folder_w(const wchar_t *);
extern "C" BOOL enumerate_directory_w(const wchar_t *, SIZE_T, SIZE_T, FILE_ROUTINE, PVOID, const std::list<file_name_w_t> &);
extern "C" LPCVOID inject_data(HANDLE, const data_t *, SIZE_T, DWORD protect = PAGE_READWRITE);
extern "C" LPCVOID inject_code(HANDLE, const code_t *, SIZE_T);
extern "C" BOOL execute_code(HANDLE, LPTHREAD_START_ROUTINE, LPVOID args, HANDLE *phThread, DWORD dwCreationFlags=0);
extern "C" BOOL thread_context_execute_code(HANDLE, LPTHREAD_START_ROUTINE, LPVOID args, BOOL suspended);
extern "C" DWORD align_down(DWORD val, DWORD align);
extern "C" DWORD align_up(DWORD val, DWORD align);
extern "C" LPCVOID get_tcp_table();
extern "C" char* hexlify(const unsigned char *data, size_t data_size);
bool string_replace_substring(std::string &s, const std::string &what, const std::string &rep);
void get_tcp_entries(const MIB_TCPTABLE *p_tcp_table, network_endpoints_t &net_endpoints, DWORD state, bool remote);
bool get_app_full_name(const wchar_t *app_params, wchar_t *app_name, size_t app_name_size, wchar_t *cur_dir, size_t cur_dir_size);
bool get_envvar(const char *env, char **out);
bool get_envvar_w(const wchar_t *env, wchar_t **out);
bool run_self_susp(const wchar_t *app_params, PROCESS_INFORMATION *ppi);
bool run_self_susp_wmi(const wchar_t *app_params, DWORD *ppid);
bool run_self_tsched(const wchar_t *app_params, DWORD *ppid);
bool run_self_tsched_vista_up(const wchar_t *app_params, DWORD *ppid);
bool run_self_tsched_xp_down(const wchar_t *app_params, DWORD *ppid);
bool get_all_tids_by_pid(DWORD pid, std::vector<DWORD> &tids);
bool check_regkey_exists(HKEY h_key, const std::string &regkey);
bool check_regkey_subkey_value(HKEY h_key, const std::string &regkey, const std::string &value_name, const std::string &value_data, bool rec);
bool check_regkey_subkey_value_nrec(HKEY h_key, const std::string &regkey, const std::string &value_name, const std::string &value_data);
bool check_regkey_subkey_value_rec(HKEY h_key, const std::string &regkey, const std::string &value_name, const std::string &value_data);
bool check_regkey_enum_keys(HKEY h_key, const std::string & key, const std::string & subkey);
bool check_regkey_enum_values(HKEY h_key, const std::string & key, const std::string & subkey);
bool check_file_exists(const file_name_t &fname);
bool check_device_exists(const file_name_t &fname);
bool disable_wow64_fs_redirection(PVOID pOld);
bool revert_wow64_fs_redirection(PVOID pOld);
bool check_process_is_running(const process_name_t &proc_name);
bool get_running_process_list(std::list<std::wstring> &procList);
bool check_mac_vendor(const std::string &ven_id);
bool check_adapter_name(const std::string &adapter_name);
PIP_ADAPTER_ADDRESSES get_adapters_addresses();
extern "C" PVOID get_firmware_table(PULONG pdwDataSize, DWORD dwSignature, DWORD dwTableID);
extern "C" BOOL enable_privilege(DWORD PrivilegeName, BOOL fEnable);
extern "C" BOOL scan_mem(CHAR *Data, ULONG dwDataSize, CHAR *lpFindData, ULONG dwFindDataSize);
extern "C" BOOL check_system_objects(const std::wstring &directory, const std::wstring &name);
bool is_hypervisor();
void get_cpu_hypevisor_id(char *vendor_id);
void get_cpu_vendor_id(char *vendor_id);
DWORD get_number_of_processors();
bool get_web_time(const std::string &net_resource, FILETIME &rv);
int64_t operator-(const FILETIME &endTime, const FILETIME &startTime);
bool perform_dns_request(const std::string &domain_name, std::list<IP4_ADDRESS> &ips);
bool get_disk_friendly_name(HDEVINFO hDevs, DWORD i, std::list<std::string> &disk_names);
bool get_drive_print_names(std::list<std::string> &disks);
bool get_drive_models(std::list<std::string> &drive_models);
bool get_drive_model(const std::string &device, ULONG ioctl, unsigned int drive, std::list<std::string>& drive_model_names);
bool get_drive_model_st_q(const std::string &device, std::list<std::string>& drive_model_names);
bool get_drive_model_drv_d(const std::string &device, unsigned int drive, std::list<std::string>& drive_model_names);
bool drv_convert_to_string(DWORD diskdata[256], DWORD diskdata_size, unsigned int firstIndex, unsigned int lastIndex, std::string &buffer);
bool do_identify(HANDLE hPhysicalDriveIOCTL, PSENDCMDINPARAMS pSCIP, PSENDCMDOUTPARAMS pSCOP, BYTE bIDCmd, BYTE bDriveNum, PDWORD lpcbBytesReturned);
bool file_interface_save(const std::string &module, const std::string &name, bool detected);
bool dns_interface_save(const std::string &module, const std::string &name, bool detected);
std::string compose_domain(const std::string &module, const std::string &name, bool detected);
std::wstring string_to_wstring(const std::string &s);
std::string remove_whitespaces(const std::string &s);
bool is_module_loaded(const std::string &module);
bool get_module_wfilename(std::wstring &result);

bool pipe_server_get_pid(const wchar_t *pipe_name, uint32_t wait_timeout, DWORD *pid);
bool pipe_server_send_pid(const wchar_t *pipe_name, uint32_t wait_timeout, DWORD pid);

bool get_parent_child_proc_pair(std::list<cp_pids> &pc_proc, const std::list<std::string> &proc_names);

EvasionMachineMode get_evasion_status(bool parent_hooked, bool child_hooked);

bool is_user_name_match(const std::string &s);
bool is_computer_name_match(const std::string &s);
bool is_host_name_match(const std::string &s);

bool is_audio_device_absent();


template <typename T> bool match_regexp(const std::basic_string<T> &regexp, const std::basic_string<T> &str, std::vector<std::basic_string<T>> *matches = NULL);
template bool match_regexp<char>(const std::basic_string<char> &, const std::basic_string<char> &, std::vector<std::basic_string<char>> *);
template bool match_regexp<wchar_t>(const std::basic_string<wchar_t> &, const std::basic_string<wchar_t> &, std::vector<std::basic_string<wchar_t>> *);

#endif
