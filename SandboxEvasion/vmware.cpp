#include "vmware.h"

namespace SandboxEvasion {

VEDetection* VMWare::create_instance(const json_tiny &j){
	return new VMWare(j);
}

void VMWare::CheckAllCustom() {
	bool d;
	std::pair<std::string, std::string> report;
	std::string ce_name;

	ce_name = Config::cvm2s[Config::ConfigVMWare::HYPERVISOR_PORT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckHypervisorPort();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cvm2s[Config::ConfigVMWare::HYPERVISOR_BIT];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = IsHypervisor();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

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

bool VMWare::IsHypervisor() const {
	/*
	int32_t cpuinfo[4] = { 0 };

	__cpuid(cpuinfo, 0x00000000);

	return (cpuinfo[2] >> 31) & 1;
	*/
	return is_hypervisor();
}


} // SandboxEvasion