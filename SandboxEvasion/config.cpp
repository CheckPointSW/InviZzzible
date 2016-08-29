#include "config.h"

namespace SandboxEvasion {
namespace Config {

	std::map<ConfigGlobal, std::string> cg2s = {
		{ ConfigGlobal::DESCRIPTION, "description" },
		{ ConfigGlobal::COUNTERMEASURES, "countermeasures" },
		{ ConfigGlobal::TYPE, "type" },
		{ ConfigGlobal::ARGUMENTS, "arguments" }
	};

	std::map<ConfigGlobalType, std::string> cgt2s = {
		{ ConfigGlobalType::CUSTOM, "custom" },
		{ ConfigGlobalType::FILE, "file" },
		{ ConfigGlobalType::REGISTRY, "registry" },
		{ ConfigGlobalType::DEVICE, "device" },
		{ ConfigGlobalType::PROCESS, "process" },
		{ ConfigGlobalType::MAC, "mac" },
		{ ConfigGlobalType::ADAPTER, "adapter" }
	};

	std::map<ConfigCuckoo, std::string> cc2s = {
		{ ConfigCuckoo::UNBALANCED_STACK, "UnbalancedStack" },
		{ ConfigCuckoo::INFINITE_DELAY, "InfiniteDelay" },
		{ ConfigCuckoo::DELAYS_ACCUMULATION, "DelaysAccumulation" },
		{ ConfigCuckoo::FUNCTION_HOOKS, "FunctionHooks" },
		{ ConfigCuckoo::AGENT_ARTIFACTS, "AgentArtifacts" },
		{ ConfigCuckoo::CUCKOOMON_CONFIGURATION, "CuckoomonConfiguration" },
		{ ConfigCuckoo::WHITELISTED_PROCESS, "WhitelistedProcess" },
		{ ConfigCuckoo::EVENT_NAME, "EventName" },
		{ ConfigCuckoo::RAISED_EXCEPTIONS, "RaisedExceptions" },
		{ ConfigCuckoo::WMI_PROCESS, "WMIProcess" },
		{ ConfigCuckoo::TASK_SCHED_PROCESS, "TaskSchedulerProcess" },
		{ ConfigCuckoo::PID_REUSE, "PidReuse" },
		{ ConfigCuckoo::AGENT_LISTENER, "AgentListener" }
	};

	std::map<ConfigArgs, std::string> ca2s = {
		{ ConfigArgs::CHECK, "check" },
		{ ConfigArgs::HKEY, "hkey" },
		{ ConfigArgs::KEY, "key" },
		{ ConfigArgs::SUBKEY, "subkey" },
		{ ConfigArgs::VALUE_NAME, "value_name" },
		{ ConfigArgs::VALUE_DATA, "value_data" },
		{ ConfigArgs::NAME, "name" },
		{ ConfigArgs::VENDOR, "vendor" }
	};

	std::map<ConfigArgsRegCheckType, std::string> carct2s = {
		{ ConfigArgsRegCheckType::EXISTS, "exists" },
		{ ConfigArgsRegCheckType::CONTAINS, "contains" },
		{ ConfigArgsRegCheckType::ENUM_KEYS, "enum_keys" },
		{ ConfigArgsRegCheckType::ENUM_VALUES, "enum_values" }
	};

} // Config
} // SandboxEvasion