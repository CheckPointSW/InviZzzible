#ifndef _CONFIG_H
#define _CONFIG_H

#include <map>

namespace SandboxEvasion {
namespace Config {
	enum class ConfigGlobal { DESCRIPTION, COUNTERMEASURES, TYPE, ARGUMENTS };
	enum class ConfigGlobalType { CUSTOM, REGISTRY, FILE, DEVICE, PROCESS, MAC, ADAPTER, DISK, FIRMWARE };
	enum class ConfigCuckoo { UNBALANCED_STACK, INFINITE_DELAY, DELAYS_ACCUMULATION, FUNCTION_HOOKS, AGENT_ARTIFACTS, CUCKOOMON_CONFIGURATION, WHITELISTED_PROCESS, EVENT_NAME, RAISED_EXCEPTIONS, WMI_PROCESS, TASK_SCHED_PROCESS, PID_REUSE, AGENT_LISTENER };
	enum class ConfigArgs { CHECK, NAME, HKEY, KEY, SUBKEY, VALUE_NAME, VALUE_DATA, VENDOR };
	enum class ConfigArgsRegCheckType { EXISTS, CONTAINS, ENUM_KEYS, ENUM_VALUES };
	enum class ConfigArgsFirmwareCheckType { FIRMBIOS, RSMBBIOS };
	enum class ConfigVMWare { HYPERVISOR_PORT, DEVICE_NPF_NDIS };
	
	extern std::map<ConfigGlobal, std::string> cg2s;
	extern std::map<ConfigGlobalType, std::string> cgt2s;
	extern std::map<ConfigCuckoo, std::string> cc2s;
	extern std::map<ConfigArgs, std::string> ca2s;
	extern std::map<ConfigArgsRegCheckType, std::string> carct2s;
	extern std::map<ConfigVMWare, std::string> cvm2s;
	extern std::map<ConfigArgsFirmwareCheckType, std::string> cafct2s;

} // Config
} // SandboxEvasion

#endif // !_CONFIG_H

