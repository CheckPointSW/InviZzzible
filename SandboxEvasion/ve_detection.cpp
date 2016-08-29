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
		CheckAllAdaptersName();
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
		std::string key_value;
		std::list<std::string> key_values;

		// iterate through all registry keys contains specific values
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::CONTAINS]) {
				key_value = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY_VALUE], "");
				if (key_value == "") {
					key_values = jt.get_array(Config::ca2s[Config::ConfigArgs::KEY_VALUE]);
					for (auto &kv : key_values) {
						detected = CheckRegKeySubkeyContains(
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::SUBKEY], ""),
							kv
							);
						if (detected)
							break;
					}
				}
				else {
					detected = CheckRegKeySubkeyContains(
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::SUBKEY], ""),
						key_value
						);
				}

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
		std::string fname;
		std::list<std::string> fnames;

		// check for the presence of all files
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			fname = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (fname == "") {
				fnames = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &fn : fnames) {
					detected = CheckFileExists(fn);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckFileExists(fname);
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllDevicesExists() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::DEVICE]);
		json_tiny jt;
		std::string devicename;
		std::list<std::string> devicenames;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			devicename = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (devicename == "") {
				devicenames = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &dn : devicenames) {
					detected = CheckDeviceExists(dn);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckDeviceExists(devicename);
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllProcessRunning() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::PROCESS]);
		json_tiny jt;
		std::string procname;
		std::list<std::string> procnames;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			procname = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (procname == "") {
				procnames = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &pn : procnames) {
					detected = CheckProcessIsRunning(pn);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckProcessIsRunning(procname);
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllMacVendors() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::MAC]);
		json_tiny jt;
		std::string macaddr;
		std::list<std::string> macaddrs;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			macaddr = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VENDOR], "");
			if (macaddr == "") {
				macaddrs = jt.get_array(Config::ca2s[Config::ConfigArgs::VENDOR]);
				for (auto &mac : macaddrs) {
					detected = CheckMacVendor(mac);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckMacVendor(macaddr);
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second);
		}
	}

	void VEDetection::CheckAllAdaptersName() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::ADAPTER]);
		json_tiny jt;
		std::string adapter;
		std::list<std::string> adapters;

		// check for the presence of devices
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			adapter = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (adapter == "") {
				adapters = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &adp : adapters) {
					detected = CheckAdapterName(adp);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckAdapterName(adapter);
			}
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

	bool VEDetection::CheckDeviceExists(const file_name_t &dev_name) const {
		return check_device_exists(dev_name);
	}

	bool VEDetection::CheckProcessIsRunning(const process_name_t &proc_name) const {
		return check_process_is_running(proc_name);
	}

	bool VEDetection::CheckMacVendor(const std::string &ven_id) const {
		return check_mac_vendor(ven_id);
	}

	bool VEDetection::CheckAdapterName(const std::string &adapter_name) const {
		return check_adapter_name(adapter_name);
	}

} // SandboxEvasion
