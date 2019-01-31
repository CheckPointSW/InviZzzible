#ifndef _VE_DETECTION_H
#define _VE_DETECTION_H

#include "json.h"
#include "config.h"
#include "report.h"


namespace SandboxEvasion {
class VEDetection {
public:
	VEDetection(const json_tiny &j) : conf(j), p_report(NULL), file_interface(false) {}
	virtual ~VEDetection() {};

	void CheckAll();

	std::string GetModuleName() const { return module_name; }
	void AddReportModule(Report *_report);
	void SetFileInterfaceModule(bool _fim);
	void SetDNSInterfaceModule(bool _dns);

protected:
	json_tiny conf;
	std::string module_name;
	Report *p_report;
	bool file_interface;
	bool dns_interface;

	void CheckAllRegistry() const;
	void CheckAllFilesExist() const;
	void CheckAllDevicesExists() const;
	void CheckAllProcessRunning() const;
	void CheckAllMacVendors() const;
	void CheckAllAdaptersName() const;
	void CheckAllFirmwareTables() const;
	void CheckAllDirectoryObjects() const;
	void CheckAllCpuid() const;
	void CheckAllWindows() const;
	void CheckAllSharedFolders() const;
	void CheckAllDiskNames() const;
	void CheckAllDriveModels() const;
	void CheckAllLoadedModules() const;
	void CheckAllFilePathPatterns() const;
	void CheckAllUserNames() const;
	void CheckAllComputerNames() const;
	void CheckAllHostNames() const;


	virtual void CheckAllCustom() = 0;

	// registry-related checks
	void CheckAllRegistryKeyExists(const std::list<std::pair<std::string, json_tiny>> &jl) const;
	void CheckAllRegistryKeyValueContains(const std::list<std::pair<std::string, json_tiny>> &jl) const;
	void CheckAllRegistryEnumKeys(const std::list<std::pair<std::string, json_tiny>> &jl) const;
	void CheckAllRegistryEnumValues(const std::list<std::pair<std::string, json_tiny>> &jl) const;

	bool CheckRegKeyExists(const std::string &key_root, const std::string &key) const;
	bool CheckRegKeyValueContains(const std::string &key_root, const std::string &key, const std::string &subkey, const std::string &value, bool rec=false) const;
	bool CheckRegKeyEnumKeys(const std::string &key_root, const std::string &key, const std::string &subkey) const;
	bool CheckRegKeyEnumValues(const std::string &key_root, const std::string &key, const std::string &value) const;

	bool CheckFileExists(const file_name_t &file_name) const;
	bool CheckDeviceExists(const file_name_t &dev_name) const;
	bool CheckProcessIsRunning(const process_name_t &proc_name) const;
	bool CheckMacVendor(const std::string &ven_id) const;
	bool CheckAdapterName(const std::string &adapter_name) const;
	bool CheckFirmwareTableFIRM(const std::string &vendor) const;
	bool CheckFirmwareTableRSMB(const std::string &vendor) const;
	bool CheckDirectoryObject(const std::string &directory, const std::string &object) const;
	bool CheckCpuHypervisorId(const std::string &cpuid_s) const;
	bool GetCpuVendorId(std::string &cpuid_s) const;
	bool CheckWindowWindowName(const std::string &wname) const;
	bool CheckWindowClassName(const std::string &cname) const;
	bool CheckSharedFolder(const std::string &name) const;
	bool CheckDiskName(const std::string &name) const;
	bool CheckDriveModel(const std::string &drive_model) const;

	bool IsEnabled(const std::string &detection_name, const std::string &enabled) const;

	std::pair<std::string, std::string> GenerateReportEntry(const std::string &name, const json_tiny &j, bool detected) const;
};
}

#endif // !_VM_DETECTION_H

