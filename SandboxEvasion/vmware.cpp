#include "vmware.h"

namespace SandboxEvasion {

VEDetection* VMWare::create_instance(const json_tiny &j){
	return new VMWare(j);
}

void VMWare::CheckAllCustom() {
	bool d;
	std::pair<std::string, std::string> report;
	std::string ce_name;

	d = CheckHypervisorPort();
	ce_name = Config::cvm2s[Config::ConfigVMWare::HYPERVISOR_PORT];
	report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
	log_message(LogMessageLevel::INFO, module_name, report.second);

	d = CheckNDISFile();
	ce_name = Config::cvm2s[Config::ConfigVMWare::DEVICE_NPF_NDIS];
	report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
	log_message(LogMessageLevel::INFO, module_name, report.second);
}

bool VMWare::CheckHypervisorPort() const {
	bool is_vm = false;

	__try {
		__asm {
			push edx;
			push ecx;
			push ebx;
			mov eax, 'VMXh';
			mov ebx, 0;
			mov ecx, 10;
			mov edx, 'VX';
			in eax, dx;
			cmp ebx, 'VMXh';
			setz[is_vm];
			pop ebx;
			pop ecx;
			pop edx;
		}
	} 
	__except (EXCEPTION_EXECUTE_HANDLER) {
		is_vm = false;
	}

	return is_vm;
}

bool VMWare::CheckNDISFile() const {
	HANDLE hFile;
	const wchar_t ndis_wan_ip_fname[] = L"\\\\.\\NPF_NdisWanIp";
	DWORD err;

	hFile = CreateFileW(ndis_wan_ip_fname, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		return err != ERROR_PATH_NOT_FOUND && err != ERROR_FILE_NOT_FOUND;
	}

	return true;
}

} // SandboxEvasion