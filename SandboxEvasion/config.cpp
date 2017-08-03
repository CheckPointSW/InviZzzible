#include "config.h"

namespace SandboxEvasion {
namespace Config {

	std::map<ConfigGlobal, std::string> cg2s = {
		{ ConfigGlobal::DESCRIPTION, "description" },
		{ ConfigGlobal::COUNTERMEASURES, "countermeasures" },
		{ ConfigGlobal::TYPE, "type" },
		{ ConfigGlobal::ENABLED, "enabled" },
		{ ConfigGlobal::ARGUMENTS, "arguments" }
	};

	std::map<ConfigGlobalType, std::string> cgt2s = {
		{ ConfigGlobalType::CUSTOM, "custom" },
		{ ConfigGlobalType::FILE, "file" },
		{ ConfigGlobalType::REGISTRY, "registry" },
		{ ConfigGlobalType::DEVICE, "device" },
		{ ConfigGlobalType::PROCESS, "process" },
		{ ConfigGlobalType::MAC, "mac" },
		{ ConfigGlobalType::ADAPTER, "adapter" },
		{ ConfigGlobalType::DISK, "disk" },
		{ ConfigGlobalType::DRIVE_MODEL, "drive_model" },
		{ ConfigGlobalType::FIRMWARE, "firmware" },
		{ ConfigGlobalType::OBJECT, "object" },
		{ ConfigGlobalType::CPUID, "cpuid" },
		{ ConfigGlobalType::WINDOW, "window" },
		{ ConfigGlobalType::SHARED, "shared" }
	};

	std::map<ConfigGlobalEnabled, std::string> cge2s = {
		{ ConfigGlobalEnabled::YES, "yes" },
		{ ConfigGlobalEnabled::NO, "no" }
	};

	std::map<ConfigCuckoo, std::string> cc2s = {
		{ ConfigCuckoo::UNBALANCED_STACK, "UnbalancedStack" },
		{ ConfigCuckoo::INFINITE_DELAY, "InfiniteDelay" },
		{ ConfigCuckoo::DELAYS_ACCUMULATION, "DelaysAccumulation" },
		{ ConfigCuckoo::SOCKET_TIMEOUT, "SocketTimeout" },
		{ ConfigCuckoo::FUNCTION_HOOKS, "FunctionHooks" },
		{ ConfigCuckoo::AGENT_ARTIFACTS, "AgentArtifacts" },
		{ ConfigCuckoo::CUCKOOMON_CONFIGURATION, "CuckoomonConfiguration" },
		{ ConfigCuckoo::WHITELISTED_PROCESS, "WhitelistedProcess" },
		{ ConfigCuckoo::EVENT_NAME, "EventName" },
		{ ConfigCuckoo::RAISED_EXCEPTIONS, "RaisedExceptions" },
		{ ConfigCuckoo::WMI_PROCESS, "WMIProcess" },
		{ ConfigCuckoo::TASK_SCHED_PROCESS, "TaskSchedulerProcess" },
		{ ConfigCuckoo::PID_REUSE, "PidReuse" },
		{ ConfigCuckoo::AGENT_LISTENER, "AgentListener" },
		{ ConfigCuckoo::SUSPENDED_THREAD, "SuspendedThread" },
		{ ConfigCuckoo::DELAY_INTERVAL, "DelayInterval" },
		{ ConfigCuckoo::TICK_COUNT, "TickCount" },
		{ ConfigCuckoo::DEAD_ANALYZER, "DeadAnalyzer" }
	};

	std::map<ConfigArgs, std::string> ca2s = {
		{ ConfigArgs::CHECK, "check" },
		{ ConfigArgs::HKEY, "hkey" },
		{ ConfigArgs::KEY, "key" },
		{ ConfigArgs::SUBKEY, "subkey" },
		{ ConfigArgs::VALUE_NAME, "value_name" },
		{ ConfigArgs::VALUE_DATA, "value_data" },
		{ ConfigArgs::NAME, "name" },
		{ ConfigArgs::VENDOR, "vendor" },
		{ ConfigArgs::DIRECTORY, "directory" },
		{ ConfigArgs::RECURSIVE, "recursive" }
	};

	std::map<ConfigArgsRegCheckType, std::string> carct2s = {
		{ ConfigArgsRegCheckType::EXISTS, "exists" },
		{ ConfigArgsRegCheckType::CONTAINS, "contains" },
		{ ConfigArgsRegCheckType::ENUM_KEYS, "enum_keys" },
		{ ConfigArgsRegCheckType::ENUM_VALUES, "enum_values" }
	};

	std::map<ConfigVMWare, std::string> cvm2s = {
		{ ConfigVMWare::HYPERVISOR_PORT, "HypervisorPort" },
		{ ConfigVMWare::HYPERVISOR_PORT_ENUM, "HypervisorPortEnum" },
		{ ConfigVMWare::HYPERVISOR_BIT,  "HypervisorBit" }
	};

	std::map<ConfigArgsFirmwareCheckType, std::string> cafct2s = {
		{ ConfigArgsFirmwareCheckType::FIRMBIOS, "firm" },
		{ ConfigArgsFirmwareCheckType::RSMBBIOS, "rsmb" }
	};

	std::map<ConfigArgsWindowCheckType, std::string> cawct2s = {
		{ ConfigArgsWindowCheckType::CLASS, "class" },
		{ ConfigArgsWindowCheckType::WINDOW, "window" }
	};

	std::map<ConfigGeneric, std::string> cgen2s = {
		{ ConfigGeneric::DISK_SIZE, "DiskSize" },
		{ ConfigGeneric::DRIVE_SIZE, "DriveSize" },
		{ ConfigGeneric::MOUSE_ACTIVE, "MouseActive" },
		{ ConfigGeneric::RAM, "RAM" },
		{ ConfigGeneric::DEVICE_NPF_NDIS, "DeviceNPF_NDIS" },
		{ ConfigGeneric::SYSTEM_UPTIME, "SystemUptime" },
		{ ConfigGeneric::SLEEP_DUMMY, "SleepDummyPatch" },
		{ ConfigGeneric::PROCESSORS_COUNT, "ProcessorsCount" },
		{ ConfigGeneric::DNS_RESPONSE, "DnsResponse" },
		{ ConfigGeneric::TIME_TAMPERING, "TimeTampering" },
		{ ConfigGeneric::SOCKET_TIMEOUT, "SocketTimeout" }
	};

} // Config
} // SandboxEvasion