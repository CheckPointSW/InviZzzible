#include "generic.h"

namespace SandboxEvasion {

VEDetection* Generic::create_instance(const json_tiny &j) {
	return new Generic(j);
}

void Generic::CheckAllCustom() {
	bool d;
	std::pair<std::string, std::string> report;
	std::string ce_name;

	ce_name = Config::cgen2s[Config::ConfigGeneric::DISK_SIZE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckDiskSize();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::DRIVE_SIZE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckDriveSize();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::MOUSE_ACTIVE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckMouseActive();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::RAM];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckRAM();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::SYSTEM_UPTIME];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSystemUptime();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::SLEEP_DUMMY];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSleepDummyPatch();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::PROCESSORS_COUNT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckNumberOfProcessors();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::DNS_RESPONSE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckDNSResponse();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}
}

bool Generic::CheckSystemUptime() const {
	// FIXME: make it configurable ?
	const DWORD uptime = 1000 * 60 * 12; // 12 minutes
	
	return GetTickCount() < uptime;
}

bool Generic::CheckRAM() const {
	MEMORYSTATUSEX ms = {};
	ms.dwLength = sizeof(ms);

	// FIXME: make it configurable ?
	const DWORDLONG min_ram = 1024 * 1024 * 1024; // 1GB

	if (!GlobalMemoryStatusEx(&ms))
		return false;

	return ms.ullTotalPhys < min_ram;
}

bool Generic::CheckDiskSize() const {
	HANDLE hDrive;
	GET_LENGTH_INFORMATION gli = {};
	DWORD dwReturned;
	uint32_t min_disk_size_gb = 60; 	// FIXME: make it configurable ?

	hDrive = CreateFile("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (hDrive == INVALID_HANDLE_VALUE)
		return false;

	if (!DeviceIoControl(hDrive, IOCTL_DISK_GET_LENGTH_INFO, NULL, 0, &gli, sizeof(gli), &dwReturned, NULL)) {
		CloseHandle(hDrive);
		return false;
	}

	CloseHandle(hDrive);
	return (gli.Length.QuadPart / (1024 * 1024 * 1024)) < min_disk_size_gb;
}

bool Generic::CheckDriveSize() const {
	ULARGE_INTEGER drive_size = {};
	uint32_t min_disk_size_gb = 60; 	// FIXME: make it configurable ?

	if (GetDiskFreeSpaceExA("C:\\", NULL, &drive_size, NULL))
		return (drive_size.QuadPart / (1024 * 1024 * 1024)) < min_disk_size_gb;

	return false;
}

bool Generic::CheckMouseActive() const {
	POINT pos_f, pos_s;
	const uint32_t timeout = 3000; // timeout in milliseconds

	GetCursorPos(&pos_f);
	Sleep(timeout);
	GetCursorPos(&pos_s);

	return !(pos_s.x - pos_f.x) && !(pos_s.y - pos_f.y);
}

bool Generic::CheckSleepDummyPatch() const {
	DWORD tick_count;
	const uint32_t delay_ms = 900; // timeout in milliseconds

	tick_count = GetTickCount();
	Sleep(delay_ms);

	return (GetTickCount() - tick_count) < delay_ms;
}

bool Generic::CheckNumberOfProcessors() const {
	const DWORD min_proc_count = 2;
	SYSTEM_INFO si = {};

	if (get_number_of_processors() < min_proc_count)
		return true;

	GetSystemInfo(&si);

	return si.dwNumberOfProcessors < min_proc_count;
}

bool Generic::CheckDNSResponse() const {
	// Calling function DnsQuery to query Host or PTR records   
	std::list<IP4_ADDRESS> ips;
	// FIXME: should it be configurable?
	std::map<std::string, size_t> dns_r = {
		{ "google.com",		6 },
		{ "bbc.com",		3 },
		{ "twitter.com",	3 }
	};
	bool sandbox_detected = false;
	unsigned char ip_addr[4];

	for (auto &dns : dns_r) {
		ips = {};
		if (!perform_dns_request(dns.first, ips))
			continue;

		// perform check on number of received domains
		if (ips.size() < dns.second) {
			sandbox_detected = true;
			break;
		}

		// perform check on received IP-addresses
		for (auto &ip : ips) {
			memcpy(ip_addr, reinterpret_cast<void *>(&ip), sizeof(ip_addr));
			if (!(((ip_addr[0] != 10) && (((ip_addr[0] != 0xac) || (ip_addr[1] <= 15)) || (ip_addr[1] >= 0x20))) && ((ip_addr[0] != 0xc0) || (ip_addr[1] != 0xa8)))) {
				sandbox_detected = true;
				break;
			}
		}
	}

	return sandbox_detected;
}

} // SandboxEvasion
