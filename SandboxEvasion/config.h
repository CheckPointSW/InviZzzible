#ifndef _CONFIG_H
#define _CONFIG_H

#include <map>

namespace SandboxEvasion {
namespace Config {
	enum class ConfigGlobal { DESCRIPTION, COUNTERMEASURES, TYPE, ENABLED, ARGUMENTS };
	enum class ConfigGlobalType { CUSTOM, REGISTRY, FILE, DEVICE, PROCESS, MAC, ADAPTER, DISK, DRIVE_MODEL, FIRMWARE, OBJECT, CPUID, WINDOW, SHARED };
	enum class ConfigGlobalEnabled { YES, NO };
	enum class ConfigCuckoo { UNBALANCED_STACK, INFINITE_DELAY, DELAYS_ACCUMULATION, SOCKET_TIMEOUT, FUNCTION_HOOKS, AGENT_ARTIFACTS, CUCKOOMON_CONFIGURATION, WHITELISTED_PROCESS, EVENT_NAME, RAISED_EXCEPTIONS, WMI_PROCESS, TASK_SCHED_PROCESS, PID_REUSE, AGENT_LISTENER, SUSPENDED_THREAD, DELAY_INTERVAL, TICK_COUNT, DEAD_ANALYZER };
	enum class ConfigArgs { CHECK, NAME, HKEY, KEY, SUBKEY, VALUE_NAME, VALUE_DATA, VENDOR, DIRECTORY, RECURSIVE };
	enum class ConfigArgsRegCheckType { EXISTS, CONTAINS, ENUM_KEYS, ENUM_VALUES };
	enum class ConfigArgsFirmwareCheckType { FIRMBIOS, RSMBBIOS };
	enum class ConfigArgsWindowCheckType { CLASS, WINDOW };
	enum class ConfigVMWare { HYPERVISOR_PORT, HYPERVISOR_PORT_ENUM, HYPERVISOR_BIT };
	enum class ConfigGeneric { SYSTEM_UPTIME, RAM, DISK_SIZE, DRIVE_SIZE, DEVICE_NPF_NDIS, MOUSE_ACTIVE, SLEEP_DUMMY, PROCESSORS_COUNT, DNS_RESPONSE, TIME_TAMPERING, PERFORMANCE_COUNTER };
	
	extern std::map<ConfigGlobal, std::string> cg2s;
	extern std::map<ConfigGlobalType, std::string> cgt2s;
	extern std::map<ConfigGlobalEnabled, std::string> cge2s;
	extern std::map<ConfigCuckoo, std::string> cc2s;
	extern std::map<ConfigArgs, std::string> ca2s;
	extern std::map<ConfigArgsRegCheckType, std::string> carct2s;
	extern std::map<ConfigVMWare, std::string> cvm2s;
	extern std::map<ConfigArgsFirmwareCheckType, std::string> cafct2s;
	extern std::map<ConfigArgsWindowCheckType, std::string> cawct2s;
	extern std::map<ConfigGeneric, std::string> cgen2s;

} // Config
} // SandboxEvasion

#endif // !_CONFIG_H

