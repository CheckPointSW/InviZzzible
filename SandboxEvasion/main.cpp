#include <Windows.h>
#include "cuckoo.h"
#include <conio.h>
#include <iostream>


#if defined(_WIN32) && defined(_WIN64)
#error "Only Win32 supported"
#endif // _WIN32


using SandboxEvasion::Cuckoo;
using std::iostream;

int main(int argc, char **argv, char **env) {
	Cuckoo cd;
	TORS_ROUTINE ctors_r[] = { ctors_wsa };
	TORS_ROUTINE dtors_r[] = { dtors_wsa };

	if (!ctors(ctors_r, _countof(ctors_r))) {
		fprintf(stdout, "[+] Unable to init constructors. Exiting...\n");
		return 1;
	}

	// checking mode
	if (argc < 2) {
		fprintf(stdout, "[+] Unbalanced stack detected: %u\n", cd.CheckUnbalancedStack());
		fprintf(stdout, "[+] INFINITE delay skipping detected: %u\n", cd.CheckInfiniteSleep());
		fprintf(stdout, "[+] Delays accumulation detected: %u\n", cd.CheckDelaysAccumulation());
		fprintf(stdout, "[+] Functions hooking detected: %u\n", cd.CheckFunctionHooks());
		fprintf(stdout, "[+] Agent artifacts detected: %u\n", cd.CheckAgentArtifacts());
		fprintf(stdout, "[+] Cuckoomon configuration detected: %u\n", cd.IsConfigurationPresent());
		fprintf(stdout, "[+] Whitelisted process escape detected: %u\n", cd.IsWhitelistedNotTracked());
		fprintf(stdout, "[+] Pid reusage escape detected: %u\n", cd.IsPidReusedNotTracked(SandboxEvasion::ProcessWorkingMode::MASTER));
		fprintf(stdout, "[+] Event name detected: %u\n", cd.CheckEventName());
		fprintf(stdout, "[+] Exceptions escape detected: %u\n", cd.CheckExceptionsNumber(SandboxEvasion::ProcessWorkingMode::MASTER));
		fprintf(stdout, "[+] WMI escape detected: %u\n", cd.IsWMINotTracked(SandboxEvasion::ProcessWorkingMode::MASTER));
		fprintf(stdout, "[+] Agent detected: %u\n", cd.IsAgentPresent());
		fflush(stdout);

		_getch();
	}
	else {
		// FIXME: add modes parsing
		if (argc < 3) {
			if (!strncmp(argv[1], "--pid", 5)) {
				cd.IsPidReusedNotTracked(SandboxEvasion::ProcessWorkingMode::SLAVE);
			}
			else if (!strncmp(argv[1], "--evt", 5)) {
				// just sleep for some time and then exit process
				Sleep(1000);
				ExitProcess(0);
			}
			else if (!strncmp(argv[1], "--exc", 5)) {
				cd.CheckExceptionsNumber(SandboxEvasion::ProcessWorkingMode::SLAVE);
			}
			else if (!strncmp(argv[1], "--wmi", 5)) {
				cd.IsWMINotTracked(SandboxEvasion::ProcessWorkingMode::SLAVE);
			}

		}

	}

	dtors(dtors_r, _countof(dtors_r));

	return 0;
}