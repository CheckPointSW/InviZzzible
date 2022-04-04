#include <WinSock2.h>  // must be before <Windows.h>
#include <Windows.h>

#include "generic.h"

#include "cuckoo.h"
#include "joebox.h"

#include "ve_detection.h"
#include "bochs.h"
#include "hyperv.h"
#include "kvm.h"
#include "parallels.h"
#include "qemu.h"
#include "sandboxie.h"
#include "vbox.h"
#include "virtualpc.h"
#include "vmware.h"
#include "xen.h"
#include "wine.h"

#include "misc.h"

#include "report.h"

#include <iostream>
#include <map>
#include <sstream>

#if defined(_WIN32) && defined(_WIN64)
#error "Only Win32 is supported"
#endif // _WIN32

using SandboxEvasion::Generic;

using SandboxEvasion::Cuckoo;
using SandboxEvasion::Joebox;

using SandboxEvasion::VEDetection;
using SandboxEvasion::BOCHS;
using SandboxEvasion::HyperV;
using SandboxEvasion::KVM;
using SandboxEvasion::Parallels;
using SandboxEvasion::QEMU;
using SandboxEvasion::Sandboxie;
using SandboxEvasion::VBOX;
using SandboxEvasion::VirtualPC;
using SandboxEvasion::VMWare;
using SandboxEvasion::Xen;
using SandboxEvasion::Wine;

using SandboxEvasion::Misc;

using std::iostream;

typedef VEDetection* (*fact_meth)(const json_tiny &);

static std::map<std::string, fact_meth> k_fm = {
	{ "--generic",	 Generic::create_instance   },
	{ "--cuckoo",	 Cuckoo::create_instance	},
	{ "--joebox",	 Joebox::create_instance	},
	{ "--bochs",	 BOCHS::create_instance     },
	{ "--hyperv",	 HyperV::create_instance	},
	{ "--kvm",		 KVM::create_instance		},
	{ "--parallels", Parallels::create_instance },
	{ "--qemu",		 QEMU::create_instance	    },
	{ "--sandboxie", Sandboxie::create_instance },
	{ "--virtualpc", VirtualPC::create_instance },
	{ "--vbox",		 VBOX::create_instance	    },
	{ "--vmware",	 VMWare::create_instance	},
	{ "--xen",		 Xen::create_instance       },
	{ "--wine",		 Wine::create_instance      },
	{ "--misc",		 Misc::create_instance      }
};

static args_t k_args = {
	{ "--generic",	 NULL },
	{ "--cuckoo",	 NULL },
	{ "--joebox",	 NULL },
	{ "--bochs",	 NULL },
	{ "--hyperv",	 NULL },
	{ "--kvm",		 NULL },
	{ "--parallels", NULL },
	{ "--qemu",		 NULL },
	{ "--sandboxie", NULL },
	{ "--virtualpc", NULL },
	{ "--vbox",		 NULL },
	{ "--vmware",	 NULL },
	{ "--xen",		 NULL },
	{ "--wine",		 NULL },
	{ "--misc",		 NULL }
};


void perform_action(const char *action) {
	Cuckoo cuckoo = Cuckoo(json_tiny());
	Generic gen = Generic(json_tiny());

	/*
	 * Cuckoo actions
	 */
	if (!strncmp(action, "--pid", 5)) {
		cuckoo.IsPidReusedNotTracked(ProcessWorkingMode::SLAVE);
	}
	else if (!strncmp(action, "--evt", 5)) {
		// just sleep for some time and then exit process
		Sleep(1000);
		ExitProcess(0);
	}
	else if (!strncmp(action, "--cfg", 5)) {
		// just sleep for some time and then exit process
		Sleep(2000);
		ExitProcess(0);
	}
	else if (!strncmp(action, "--exc", 5)) {
		cuckoo.CheckExceptionsNumber(ProcessWorkingMode::SLAVE);
	}
	else if (!strncmp(action, "--wmi", 5)) {
		cuckoo.IsWMINotTracked(ProcessWorkingMode::SLAVE);
	}
	else if (!strncmp(action, "--tsh", 5)) {
		cuckoo.IsTaskSchedNotTracked(ProcessWorkingMode::SLAVE);
	}
	else if (!strncmp(action, "--dan", 5)) {
		cuckoo.IsAnalyzerDeadNotTracked(ProcessWorkingMode::SLAVE);
	}
	/*
	 * Generic actions
	 */
	else if (!strncmp(action, "--dtt", 5)) {
		bool d = gen.CheckTimeTampering(ProcessWorkingMode::SLAVE);
		ExitProcess(d);
	}
	else if (!strncmp(action, "--mra", 5)) {
		bool d = gen.CheckMouseRawActive(ProcessWorkingMode::SLAVE);
		ExitProcess(d);
	}
	else if (!strncmp(action, "--user-input", 12)) {
		bool d = gen.CheckUserInputActivity(ProcessWorkingMode::SLAVE);
		ExitProcess(d);
	}
}


void apply_default_mode(std::list<VEDetection*> &detects, std::list<json_tiny *> &jsons, bool &bfile, bool &bdns) {
	// as for now default mode executes only cuckoo checks
	#include "default_configs.h"
		
	for (auto &item : default_configs) {
		json_tiny *pj;
		std::stringstream ss;
		ss << item.second;
		
		pj = json_tiny::load(ss);
			
		if (pj) {
			detects.push_back(k_fm[std::string("--") + item.first](*pj));
			jsons.push_back(pj);
		}
		else {
			log_message(LogMessageLevel::ERR, "MAIN", std::string("Unable to load configuration for --" + item.first));
		}
	}
	
	enable_verbose_mode();
	bfile = true;
	bdns = true;
}


void banner() {
	std::string module_name("");

	log_message(LogMessageLevel::NO, module_name, std::string(30, '*'), BLUE);
	log_message(LogMessageLevel::NO, module_name, "********SandboxEvasion********", BLUE);
	log_message(LogMessageLevel::NO, module_name, std::string(30, '*'), BLUE);
}


int main(int argc, char **argv, char **env) {
	int arg_no;
	args_t args;
	const char verbose_mode[] = "--verbose";
	const char action_mode[] = "--action";
	const char file_mode[] = "--file";
	std::string module_name("MAIN");
	const char dns_mode[] = "--dns";
	std::list<VEDetection*> detects;
	std::list<json_tiny *> jsons;
	json_tiny *pj;
	bool action = false;
	bool bfile = false;
	char *chosen_action = NULL;
	bool bdns = false;
	Report report;
	Report *pReport;
	char report_file[MAX_PATH] = {};
	SYSTEMTIME st;

	// TODO: do we need to disable FsRedirection when enumerating directory?
	// TODO: do we need placeholders for report and cuckoo default stuff?

	TORS_ROUTINE ctors_r[] = { ctors_wsa, ctors_check_wow64, ctors_get_os_ver };
	TORS_ROUTINE dtors_r[] = { dtors_wsa };

	if (!ctors(ctors_r, _countof(ctors_r))) {
		enable_verbose_mode();
		log_message(LogMessageLevel::ERR, module_name, "Unable to initialize constructors. Exiting...");
		return 1;
	}

	// parse incoming arguments
	for (auto &a : k_args) {
		arg_no = 1;
		while (arg_no < argc) {
			if (!strncmp(a.first, argv[arg_no], strlen(a.first)) && arg_no + 1 < argc) {
				a.second = argv[arg_no + 1];
				++arg_no;
			}
			else if (!strncmp(verbose_mode, argv[arg_no], strlen(verbose_mode))) {
				enable_verbose_mode();
			}
			else if (!strncmp(file_mode, argv[arg_no], strlen(file_mode))) {
				bfile = true;
			}
			else if (!strncmp(dns_mode, argv[arg_no], strlen(dns_mode))) {
				bdns = true;
			}
			else if (!strncmp(action_mode, argv[arg_no], strlen(action_mode)) && arg_no + 1 < argc) {
				action = true;
				chosen_action = argv[arg_no + 1];
				++arg_no;
			}
			++arg_no;
		}
	}

	if (action && chosen_action) {
		perform_action(chosen_action);
		return 0;
	}

	banner();

	pReport = report.load() ? &report : NULL;

	// printf debug info
	log_message(LogMessageLevel::INFO, module_name, std::string("Initialize virtual environment detection modules..."));

	for (auto &a : k_args) {
		if (a.second) {
			pj = json_tiny::load(a.second);
			if (pj) {
				detects.push_back(k_fm[a.first](*pj));
				jsons.push_back(pj);
			}
			else {
				std::stringstream ss;
				ss << "Unable to load configuration for " << a.first;
				log_message(LogMessageLevel::ERR, "MAIN", ss.str());
			}
		}
	}

	// in case if no class checks parametres were not specified, then use default execution mode
	if (detects.empty()) {
		apply_default_mode(detects, jsons, bfile, bdns);
	}

	// printf info
	for (auto &d : detects) {
		log_message(LogMessageLevel::INFO, d->GetModuleName(), std::string("Starting checks..."));
		d->AddReportModule(pReport);
		d->SetFileInterfaceModule(bfile);
		d->SetDNSInterfaceModule(bdns);
		d->CheckAll();
		log_message(LogMessageLevel::INFO, d->GetModuleName(), std::string("Checks finished\n") + std::string(60, '*') + std::string("\n"));
	}

	if (pReport && detects.size()) {
		GetSystemTime(&st);
		_snprintf_s(report_file, _countof(report_file), "SandboxEvasion_%.02u%.02u%.02u_%.02u%.02u%.02u.html", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

		if (report.dump(report_file))
			log_message(LogMessageLevel::INFO, module_name, std::string("Report was successfully saved to file: ") + std::string(report_file));
	}

	// free all data
	for (auto &d : detects)
		delete[]d;

	for (auto &j : jsons)
		delete[]j;

	dtors(dtors_r, _countof(dtors_r));
	system("pause");

	return 0;
}
