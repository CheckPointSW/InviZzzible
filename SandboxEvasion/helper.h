#ifndef _HELPER_H
#define _HELPER_H

#include <stdint.h>
#include <string>
#include <Windows.h>
#include <map>
#include <vector>
#include <list>
#include <regex>
#include <Iphlpapi.h>

#define INVALID_PID_VALUE	0xFFFFFFFF
#define SEED_DEFAULT		0xFFFFFFFF
#define EVENT_NAME_MAX_LEN	0x10


typedef std::wstring lib_name_t;
typedef std::string func_name_t;
typedef std::string file_name_t;
typedef std::wstring file_name_w_t;
typedef std::wstring file_path_t;
typedef std::wstring event_name_t;
typedef unsigned char code_t;
typedef unsigned char data_t;
// typedef std::string regexp_t;
// typedef std::string regexp_match_t;
// typedef std::list<regexp_t> regexpl_t;


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

extern "C" void* __memchr(const void *s, unsigned char c, size_t n);
extern "C" unsigned char* __memmem(const unsigned char *haystack, size_t hlen, const unsigned char *needle, size_t nlen);

extern "C" BOOL cdtors(TORS_ROUTINE *p_ir, size_t ir_count);
extern "C" BOOL ctors(TORS_ROUTINE *p_ir, size_t ir_count);
extern "C" BOOL dtors(TORS_ROUTINE *p_ir, size_t ir_count);

extern "C" LPVOID ctors_wsa(LPVOID);
extern "C" LPVOID dtors_wsa(LPVOID);

extern "C" BOOL send_all(SOCKET s, const char *buf, int len, int flags);
extern "C" BOOL recv_all(SOCKET s, char *buf, int len, int flags);

extern "C" DWORD find_process_by_name(LPCSTR);
extern "C" HANDLE open_process_by_pid(DWORD, DWORD);
extern "C" HANDLE open_thread_by_tid(DWORD, DWORD);
extern "C" HANDLE open_process_by_name(LPCSTR, DWORD);
extern "C" BOOL terminate_process(HANDLE);
extern "C" BOOL check_if_path_exists(LPCSTR, DWORD*);
extern "C" BOOL check_current_parent_folder_w(const wchar_t *);
extern "C" BOOL enumerate_directory_w(const wchar_t *, SIZE_T, SIZE_T, FILE_ROUTINE, PVOID, const std::list<file_name_w_t> &);
extern "C" LPCVOID inject_data(HANDLE, const data_t *, SIZE_T, DWORD protect = PAGE_READWRITE);
extern "C" LPCVOID inject_code(HANDLE, const code_t *, SIZE_T);
extern "C" BOOL execute_code(HANDLE, LPTHREAD_START_ROUTINE, LPVOID args, HANDLE *phThread);
extern "C" BOOL thread_context_execute_code(HANDLE, LPTHREAD_START_ROUTINE, LPVOID args, BOOL suspended);
extern "C" DWORD align_down(DWORD val, DWORD align);
extern "C" DWORD align_up(DWORD val, DWORD align);
extern "C" LPCVOID get_tcp_table();
extern "C" char* hexlify(const unsigned char *data, size_t data_size);
void get_tcp_entries(const MIB_TCPTABLE *p_tcp_table, network_endpoints_t &net_endpoints, DWORD state);
bool get_app_full_name(const wchar_t *app_params, wchar_t *app_name, size_t app_name_size, wchar_t *cur_dir, size_t cur_dir_size);
bool get_envvar(const char *env, char **out);
bool get_envvar_w(const wchar_t *env, wchar_t **out);
bool run_self_susp(const wchar_t *app_params, PROCESS_INFORMATION *ppi);
bool run_self_susp_wmi(const wchar_t *app_params, DWORD *ppid);
bool get_all_tids_by_pid(DWORD pid, std::vector<DWORD> &tids);


template <typename T> bool match_regexp(const std::basic_string<T> &regexp, const std::basic_string<T> &str, std::vector<std::basic_string<T>> *matches = NULL);
template bool match_regexp<char>(const std::basic_string<char> &, const std::basic_string<char> &, std::vector<std::basic_string<char>> *);
template bool match_regexp<wchar_t>(const std::basic_string<wchar_t> &, const std::basic_string<wchar_t> &, std::vector<std::basic_string<wchar_t>> *);

//template <typename T> std::basic_string<T> escape_regexp(const std::basic_string<T> &str);
//template std::basic_string<char> escape_regexp(const std::basic_string<char> &str);
//template std::basic_string<wchar_t> escape_regexp(const std::basic_string<wchar_t> &str);

#endif
