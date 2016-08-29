#include "ve_detection.h"
#include <iostream>
#include <boost\foreach.hpp>

using std::cout;
using std::endl;

namespace SandboxEvasion {

	// return first: html information
	// return second: debug information
	std::pair<std::string, std::string> VEDetection::GenerateReportEntry(const std::string &name, const json_tiny &j, bool detected) const {
		std::ostringstream ostream_debug;
		std::ostringstream ostream_html;

		std::string desc = j.get<std::string>(Config::cg2s[Config::ConfigGlobal::DESCRIPTION], "");
		std::string wtd = j.get<std::string>(Config::cg2s[Config::ConfigGlobal::COUNTERMEASURES], "");
		std::string dtype = j.get<std::string>(Config::cg2s[Config::ConfigGlobal::TYPE], "");

		ostream_debug << name  << "> " << desc << ": " << detected << std::endl;
		
		// FIXME: generate HTML template stream

		return std::pair<std::string, std::string>(ostream_html.str(), ostream_debug.str());
	}

	void VEDetection::CheckAll() {
		CheckAllCustom();
		CheckAllRegistryExists();
		CheckAllRegistryValues();
		CheckAllFilesExist();
		CheckAllDevicesExists();
		CheckAllProcessRunning();
		CheckAllMacVendors();
	}

	void VEDetection::CheckAllRegistryExists() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::REGISTRY]);
		json_tiny jt;

		// iterate through all registry exists detections
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::EXISTS]) {
				detected = CheckRegKeyExists(
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""));

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second);
			}
		}
	}

	void VEDetection::CheckAllRegistryValues() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::REGISTRY]);
		json_tiny jt;

		// iterate through all registry keys contains specific values
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::CONTAINS]) {
				detected = CheckRegKeySubkeyContains(
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""), 
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::SUBKEY], ""),
					jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY_VALUE], "")
					);

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second);
			}
		}
	}

	void VEDetection::CheckAllFilesExist() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::FILE]);
		json_tiny jt;

		// check for the presence of all files
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			detected = CheckFileExists(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], ""));
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllDevicesExists() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::DEVICE]);
		json_tiny jt;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			detected = CheckDeviceExists(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], ""));
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllProcessRunning() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::PROCESS]);
		json_tiny jt;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			detected = CheckProcessIsRunning(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], ""));
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllMacVendors() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::MAC]);
		json_tiny jt;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			detected = CheckMacVendor(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VENDOR], ""));
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	bool VEDetection::CheckRegKeyExists(const std::string &key_root, const std::string &key) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;

		return check_regkey_exists(hRootKey, key);
	}

	bool VEDetection::CheckRegKeySubkeyContains(const std::string &key_root, const std::string &key, const std::string &subkey, const std::string &value) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;

		return check_regkey_subkey_value(hRootKey, key, subkey, value);
	}

	bool VEDetection::CheckFileExists(const file_name_t &file_name) const {
		return check_file_exists(file_name);
	}

	bool VEDetection::CheckDeviceExists(const file_name_t & dev_name) const {
		return check_device_exists(dev_name);
	}

	bool VEDetection::CheckProcessIsRunning(const process_name_t & proc_name) const {
		return check_process_is_running(proc_name);
	}

	bool VEDetection::CheckMacVendor(const std::string &ven_id) const {
		return check_mac_vendor(ven_id);
	}

} // SandboxEvasion
