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
		CheckAllRegistry();
		CheckAllFilesExist();
		CheckAllDevicesExists();
		CheckAllProcessRunning();
		CheckAllMacVendors();
		CheckAllAdaptersName();
		CheckAllFirmwareTables();
		CheckAllDirectoryObjects();
	}

	void VEDetection::CheckAllRegistry() const {
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::REGISTRY]);

		CheckAllRegistryKeyExists(jl);
		CheckAllRegistryKeyValueContains(jl);
		CheckAllRegistryEnumKeys(jl);
		CheckAllRegistryEnumValues(jl);
	}

	void VEDetection::CheckAllRegistryKeyExists(const std::list<std::pair<std::string, json_tiny>> &jl) const {
		bool detected;
		std::pair<std::string, std::string> report;
		json_tiny jt;
		std::string key;
		std::list<std::string> keys;

		// iterate through all registry exists detections
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());
			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::EXISTS]) {
				key = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], "");
				if (key == "") {
					keys = jt.get_array(Config::ca2s[Config::ConfigArgs::KEY]);
					for (auto &k : keys) {
						detected = CheckRegKeyExists(
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
							k
							);
						if (detected)
							break;
					}
				}
				else {
					detected = CheckRegKeyExists(
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
						key
						);
				}

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
			}
		}
	}

	void VEDetection::CheckAllRegistryKeyValueContains(const std::list<std::pair<std::string, json_tiny>> &jl) const {
		bool detected;
		std::pair<std::string, std::string> report;
		json_tiny jt;
		std::string value_data;
		std::list<std::string> vd;

		// iterate through all registry keys contains specific values
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::CONTAINS]) {
				value_data = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VALUE_DATA], "");
				if (value_data == "") {
					vd = jt.get_array(Config::ca2s[Config::ConfigArgs::VALUE_DATA]);
					for (auto &kv : vd) {
						detected = CheckRegKeyValueContains(
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VALUE_NAME], ""),
							kv
							);
						if (detected)
							break;
					}
				}
				else {
					detected = CheckRegKeyValueContains(
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VALUE_NAME], ""),
						value_data
						);
				}

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
			}
		}
	}

	void VEDetection::CheckAllRegistryEnumKeys(const std::list<std::pair<std::string, json_tiny>>& jl) const {
		bool detected;
		std::pair<std::string, std::string> report;
		json_tiny jt;
		std::string subkey;
		std::list<std::string> subkeys;

		// iterate through all registry keys contains specific values
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::ENUM_KEYS]) {
				subkey = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::SUBKEY], "");
				if (subkey == "") {
					subkeys = jt.get_array(Config::ca2s[Config::ConfigArgs::SUBKEY]);
					for (auto &sk : subkeys) {
						detected = CheckRegKeyEnumKeys(
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
							sk
							);

						if (detected)
							break;
					}
				}
				else {
					detected = CheckRegKeyEnumKeys(
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
						subkey
						);
				}

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
			}
		}
	}

	void VEDetection::CheckAllRegistryEnumValues(const std::list<std::pair<std::string, json_tiny>>& jl) const {
		bool detected;
		std::pair<std::string, std::string> report;
		json_tiny jt;
		std::string value;
		std::list<std::string> values;

		// iterate through all registry keys contains specific values
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::carct2s[Config::ConfigArgsRegCheckType::ENUM_VALUES]) {
				value = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::VALUE_NAME], "");
				if (value == "") {
					values = jt.get_array(Config::ca2s[Config::ConfigArgs::VALUE_NAME]);
					for (auto &v : values) {
						detected = CheckRegKeyEnumValues(
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
							jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
							v
							);

						if (detected)
							break;
					}
				}
				else {
					detected = CheckRegKeyEnumValues(
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::HKEY], ""),
						jt.get<std::string>(Config::ca2s[Config::ConfigArgs::KEY], ""),
						value
						);
				}

				report = GenerateReportEntry(o.first, o.second, detected);
				log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
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

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

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
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
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

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

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
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
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

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

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
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
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

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

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
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
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

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

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
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
		}
	}

	void VEDetection::CheckAllFirmwareTables() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::FIRMWARE]);
		json_tiny jt;
		std::string firmware;
		std::list<std::string> firmwares;

		// check for the presence of all files
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			firmware = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (firmware == "") {
				firmwares = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &f : firmwares) {
					if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::cafct2s[Config::ConfigArgsFirmwareCheckType::FIRMBIOS])
						detected = CheckFirmwareTableFIRM(f);
					else if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::cafct2s[Config::ConfigArgsFirmwareCheckType::RSMBBIOS])
						detected = CheckFirmwareTableRSMB(f);
					else detected = false;
					if (detected)
						break;
				}
			}
			else {
				if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::cafct2s[Config::ConfigArgsFirmwareCheckType::FIRMBIOS])
					detected = CheckFirmwareTableFIRM(firmware);
				else if (jt.get<std::string>(Config::ca2s[Config::ConfigArgs::CHECK], "") == Config::cafct2s[Config::ConfigArgsFirmwareCheckType::RSMBBIOS])
					detected = CheckFirmwareTableRSMB(firmware);
				else detected = false;
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
		}

	}

	void VEDetection::CheckAllDirectoryObjects() const {
		bool detected;
		std::pair<std::string, std::string> report;
		std::list<std::pair<std::string, json_tiny>> jl = conf.get_objects(Config::cg2s[Config::ConfigGlobal::TYPE], Config::cgt2s[Config::ConfigGlobalType::OBJECT]);
		json_tiny jt;
		std::string dirobject;
		std::list<std::string> dirobjects;

		// check for the presence of specific directory objects
		for each (auto &o in jl) {
			jt = o.second.get(Config::cg2s[Config::ConfigGlobal::ARGUMENTS], pt::ptree());

			if (!IsEnabled(o.first, conf.get<std::string>(o.first + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], "")))
				continue;

			dirobject = jt.get<std::string>(Config::ca2s[Config::ConfigArgs::NAME], "");
			if (dirobject == "") {
				dirobjects = jt.get_array(Config::ca2s[Config::ConfigArgs::NAME]);
				for (auto &dir : dirobjects) {
					detected = CheckDirectoryObject(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::DIRECTORY], ""), dir);
					if (detected)
						break;
				}
			}
			else {
				detected = CheckDirectoryObject(jt.get<std::string>(Config::ca2s[Config::ConfigArgs::DIRECTORY], ""), dirobject);
			}
			report = GenerateReportEntry(o.first, o.second, detected);
			log_message(LogMessageLevel::INFO, module_name, report.second, detected ? RED : GREEN);
		}
	}

	bool VEDetection::CheckRegKeyExists(const std::string &key_root, const std::string &key) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;

		return check_regkey_exists(hRootKey, key);
	}

	bool VEDetection::CheckRegKeyValueContains(const std::string &key_root, const std::string &key, const std::string &subkey, const std::string &value) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;

		return check_regkey_subkey_value(hRootKey, key, subkey, value);
	}

	bool VEDetection::CheckRegKeyEnumKeys(const std::string & key_root, const std::string & key, const std::string & subkey) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;

		return check_regkey_enum_keys(hRootKey, key, subkey);
	}

	bool VEDetection::CheckRegKeyEnumValues(const std::string & key_root, const std::string & key, const std::string & value) const {
		HKEY hRootKey = get_hkey(key_root);
		if (hRootKey == reinterpret_cast<HKEY>(INVALID_HKEY))
			return false;
		
		return check_regkey_enum_values(hRootKey, key, value);
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

	bool VEDetection::CheckFirmwareTableFIRM(const std::string &vendor) const {
		CHAR *sfti;
		DWORD data_size;
		bool found;

		sfti = reinterpret_cast<CHAR *>(get_firmware_table(&data_size, FIRM, 0xC0000));
		if (!sfti)
			return false;

		found = scan_mem(sfti, data_size, const_cast<char *>(vendor.c_str()), vendor.length());

		LocalFree(sfti);

		return found;
	}

	bool VEDetection::CheckFirmwareTableRSMB(const std::string &vendor) const {
		CHAR *sfti;
		DWORD data_size;
		bool found;

		sfti = reinterpret_cast<CHAR *>(get_firmware_table(&data_size, RSMB, 0x0));
		if (!sfti)
			return false;

		found = scan_mem(sfti, data_size, const_cast<char *>(vendor.c_str()), vendor.length());

		LocalFree(sfti);

		return found;
	}

	bool VEDetection::CheckDirectoryObject(const std::string &directory, const std::string &object) const {
		std::wstring directory_w;
		std::wstring object_w;

		directory_w.assign(directory.begin(), directory.end());
		object_w.assign(object.begin(), object.end());

		return check_system_objects(directory_w, object_w);
	}

	bool VEDetection::IsEnabled(const std::string &detection_name, const std::string &enabled) const {
		return detection_name != "" && enabled == Config::cge2s[Config::ConfigGlobalEnabled::YES];
	}

} // SandboxEvasion
