#include "generic.h"

namespace SandboxEvasion {

VEDetection* Generic::create_instance(const json_tiny &j) {
	return new Generic(j);
}

void Generic::CheckAllCustom() {
	bool d;
	std::pair<std::string, std::string> report;
	std::string ce_name;

	ce_name = Config::cgen2s[Config::ConfigGeneric::SLEEP_DUMMY];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSleepDummyPatch();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::PERFORMANCE_COUNTER];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckPerformanceCounter();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

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

	ce_name = Config::cgen2s[Config::ConfigGeneric::DEVICE_NPF_NDIS];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckNDISFile();
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

	ce_name = Config::cgen2s[Config::ConfigGeneric::BIG_RAM_ALLOC];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + "." + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckBigRAMAllocate();
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::SYSTEM_UPTIME];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckSystemUptime();
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

	ce_name = Config::cgen2s[Config::ConfigGeneric::TIME_TAMPERING];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckTimeTampering(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::MOUSE_RAW_ACTIVE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + std::string(".") + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckMouseRawActive(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::USER_INPUT_ACTIVITY];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + "." + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckUserInputActivity(ProcessWorkingMode::MASTER);
		report = GenerateReportEntry(ce_name, json_tiny(conf.get(ce_name, pt::ptree())), d);
		log_message(LogMessageLevel::INFO, module_name, report.second, d ? RED : GREEN);
	}

	ce_name = Config::cgen2s[Config::ConfigGeneric::AUDIO_DEVICE_ABSENCE];
	if (IsEnabled(ce_name, conf.get<std::string>(ce_name + "." + Config::cg2s[Config::ConfigGlobal::ENABLED], ""))) {
		d = CheckAudioDeviceAbsence();
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

bool Generic::CheckBigRAMAllocate() const
{
	void* mem = VirtualAllocEx(GetCurrentProcess(), nullptr, 0x279C6A13, MEM_COMMIT, PAGE_READWRITE);
	const bool rv = !mem;
	if (mem)
	{
		memset(mem, 0xBD, 0x279C6A13);
		VirtualFreeEx(GetCurrentProcess(), mem, 0, MEM_RELEASE);
	}
	return rv;
}

bool Generic::CheckDiskSize() const {
	HANDLE hDrive;
	GET_LENGTH_INFORMATION gli = {};
	DWORD dwReturned;
	uint32_t min_disk_size_gb = 60; 	// FIXME: make it configurable ?

	hDrive = CreateFileA("\\\\.\\PhysicalDrive0", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
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

bool Generic::CheckNDISFile() const {
	HANDLE hFile;
	const wchar_t ndis_wan_ip_fname[] = L"\\\\.\\NPF_NdisWanIp";
	DWORD err;

	hFile = CreateFileW(ndis_wan_ip_fname, 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
	if (hFile == INVALID_HANDLE_VALUE) {
		err = GetLastError();
		return err != ERROR_PATH_NOT_FOUND && err != ERROR_FILE_NOT_FOUND;
	}
	CloseHandle(hFile);

	return true;
}

bool Generic::CheckMouseActive() const {
	POINT pos_f, pos_s;
	const uint32_t timeout = 1000; // timeout in milliseconds
	const uint8_t tries = 5;

	for (uint8_t i = 0; i < tries; ++i) {
		GetCursorPos(&pos_f);
		Sleep(timeout);
		GetCursorPos(&pos_s);

		if ((pos_s.x - pos_f.x) || (pos_s.y - pos_f.y))
			return false;
	}

	return true;
}


bool Generic::CheckSleepDummyPatch() const {
	DWORD tick_count_f, tick_count_s;
	const DWORD delay_ms = 900; // timeout in milliseconds

	tick_count_f = GetTickCount();
	SleepEx(delay_ms, FALSE);
	tick_count_s = GetTickCount();

	return (tick_count_s - tick_count_f) < (delay_ms - 50);
}

bool Generic::CheckPerformanceCounter() const {
	LARGE_INTEGER Frequency = { 0 };
	LARGE_INTEGER StartingTime = { 0 };
	LARGE_INTEGER EndingTime = { 0 };
	LARGE_INTEGER ElapsedTimeMs = { 0 };

	const DWORD delay_ms = 10000;	// timeout in milliseconds
	const DWORD max_delta = 50;		// delay in milliseconds

	QueryPerformanceFrequency(&Frequency);
	QueryPerformanceCounter(&StartingTime);

	// Activity to be timed
	Sleep(delay_ms);

	QueryPerformanceCounter(&EndingTime);

	ElapsedTimeMs.QuadPart = 1000ll * (EndingTime.QuadPart - StartingTime.QuadPart) / Frequency.QuadPart;

	// printf("Elapsed: %u. Waited: %u\n", ElapsedTimeMs.LowPart, delay_ms);

	return abs(static_cast<long>(ElapsedTimeMs.LowPart) - static_cast<long>(delay_ms)) > max_delta;
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
		{ "microsoft.com",	3 },
		{ "bbc.com",		3 },
		{ "amazon.com",		3 }
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

bool Generic::CheckTimeTampering(ProcessWorkingMode wm) const {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return CheckTimeTamperingMaster();
	case ProcessWorkingMode::SLAVE:
		return CheckTimeTamperingSlave();
	default:
		return false;
	}
}


bool Generic::CheckTimeTamperingMaster() const {
	wchar_t app_params[] = L"--action --dtt";
	PROCESS_INFORMATION pi = {};

	if (!run_self_susp(app_params, &pi))
		return false;

	ResumeThread(pi.hThread);

	// wait process for finish
	DWORD ec;
	do {
		if (!GetExitCodeProcess(pi.hProcess, &ec)) {
			TerminateProcess(pi.hProcess, 0xFF);
			CloseHandle(pi.hThread);
			CloseHandle(pi.hProcess);
			return false;
		}
		Sleep(100);
	} while (ec == STILL_ACTIVE);

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return ec == 1;
}


bool Generic::CheckTimeTamperingSlave() const {
	const int delta = 5 * 1000; // 5 sec
	const int64_t k100NStoMSecs = 10000ll;
	bool sandboxDetected = false;
	const std::string host("google.com");	// FIXME: should be configurable?

	FILETIME ftLocalStart, ftLocalEnd, ftWebStart, ftWebEnd;

	GetSystemTimeAsFileTime(&ftLocalStart);
	if (!get_web_time(host, ftWebStart))
		return false;

	int64_t totalMSec = 0;
	for (int i = 0; i < 10; ++i) {
		const int sleepSec = 1 + (rand() % 10);
		totalMSec += sleepSec * 1000;
		SleepEx(sleepSec * 1000, FALSE);
	}

	GetSystemTimeAsFileTime(&ftLocalEnd);
	if (!get_web_time(host, ftWebEnd))
		return false;

	// PC's clock validation
	const int64_t localTimeDiff = std::abs(ftLocalEnd - ftLocalStart) / k100NStoMSecs;
	const int64_t webTimeDiff = std::abs(ftWebEnd - ftWebStart) / k100NStoMSecs;

	if (std::abs(localTimeDiff - webTimeDiff) > delta)
		sandboxDetected = true;

	// second check for proper sleep delay
	if (!sandboxDetected) {
		if (localTimeDiff < totalMSec)
			sandboxDetected = true;
		if (webTimeDiff < totalMSec)
			sandboxDetected = true;
	}
	return sandboxDetected;
}


bool Generic::CheckMouseRawActive(ProcessWorkingMode wm) {
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return CheckMouseRawActiveMaster();
	case ProcessWorkingMode::SLAVE:
		return CheckMouseRawActiveSlave();
	default:
		return false;
	}
}


bool Generic::CheckMouseRawActiveMaster() {
	wchar_t app_params[] = L"--action --mra";
	PROCESS_INFORMATION pi = {};
	const uint32_t timeout = 1000; // timeout in milliseconds
	const uint8_t tries = 10;

	if (!run_self_susp(app_params, &pi))
		return false;

	ResumeThread(pi.hThread);

	// wait process for finish
	DWORD ec;
	for (uint8_t i = 0; i < tries; ++i) {
		GetExitCodeProcess(pi.hProcess, &ec);
		if (ec != STILL_ACTIVE)
			break;
		Sleep(timeout);
	} 

	TerminateProcess(pi.hProcess, 0xFF);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return ec != 0;
}


bool Generic::CheckMouseRawActiveSlave() {
	MSG msg;
	HINSTANCE hInstance = GetModuleHandleA(NULL);

	if (MouseRawActiveRegisterClass(hInstance) == NULL)
		return false;

	if (MouseRawActiveInitInstance(hInstance) == FALSE)
		return false;

	while (GetMessage(&msg, NULL, 0, 0)) {
		TranslateMessage(&msg);
		DispatchMessage(&msg);
	}

	return false;
}


bool Generic::CheckUserInputActivity(ProcessWorkingMode wm)
{
	switch (wm) {
	case ProcessWorkingMode::MASTER:
		return CheckUserInputActivityMaster();
	case ProcessWorkingMode::SLAVE:
		return CheckUserInputActivitySlave();
	default:
		return false;
	}
}


bool Generic::CheckUserInputActivityMaster() {
	wchar_t app_params[] = L"--action --user-input";
	PROCESS_INFORMATION pi = {};
	const uint32_t timeout = 1000; // timeout in milliseconds
	const uint8_t tries = 10;

	if (!run_self_susp(app_params, &pi))
		return false;

	ResumeThread(pi.hThread);

	// wait process for finish
	DWORD ec;
	for (uint8_t i = 0; i < tries; ++i) {
		GetExitCodeProcess(pi.hProcess, &ec);
		if (ec != STILL_ACTIVE)
			break;
		Sleep(timeout);
	}

	TerminateProcess(pi.hProcess, 0xFF);
	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);

	return ec != 0;
}


bool Generic::CheckUserInputActivitySlave() {
	int tries = 0xFFFAF99;
	LASTINPUTINFO lii = {};
	int okTries = 0;
	DWORD lastTime = 0;
	while (1)
	{
		lii.cbSize = 8;
		lii.dwTime = 0;
		if (!GetLastInputInfo(&lii))
			return true;
		if (lii.dwTime - lastTime >= 0x1F2)
		{
			++okTries;
			lastTime = lii.dwTime;
		}
		SleepEx(0x11Bu, 0);
		if (okTries > 5)
			return false;
		if (!--tries)
			return true;
	}
	return true;
}


bool Generic::CheckAudioDeviceAbsence() const {
	return is_audio_device_absent();
}


ATOM Generic::MouseRawActiveRegisterClass(HINSTANCE hInstance) {
	WNDCLASSEXA wcex;

	wcex.cbSize = sizeof(WNDCLASSEXA);

	wcex.style = CS_HREDRAW | CS_VREDRAW;
	wcex.lpfnWndProc = Generic::MouseRawWndProc;
	wcex.cbClsExtra = 0;
	wcex.cbWndExtra = 0;
	wcex.hInstance = hInstance;
	wcex.hIcon = NULL;
	wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
	wcex.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
	wcex.lpszMenuName = NULL;
	wcex.lpszClassName = mouse_raw_wnd_class.c_str();
	wcex.hIconSm = NULL;

	return RegisterClassExA(&wcex);
}


BOOL Generic::MouseRawActiveInitInstance(HINSTANCE hInstance) {
	HWND hWnd;

	// hWnd = CreateWindowExA(WS_EX_TOOLWINDOW, mouse_raw_wnd_class.c_str(), "ABCD", 0, 0, 0, 680, 480, NULL, NULL, hInstance, NULL);
	hWnd = CreateWindowExA(WS_EX_TOOLWINDOW | WS_EX_TOPMOST, mouse_raw_wnd_class.c_str(), "ABCD", 0, 0, 0, 640, 480, NULL, NULL, hInstance, NULL);

	if (!hWnd)
		return FALSE;

	ShowWindow(hWnd, SW_SHOW);
	UpdateWindow(hWnd);

	// register raw input device
	RAWINPUTDEVICE Rid[1];

	Rid[0].usUsagePage = 0x01;
	Rid[0].usUsage = 0x02;
	Rid[0].dwFlags = RIDEV_NOLEGACY;   // adds HID mouse and also ignores legacy mouse messages
	Rid[0].hwndTarget = hWnd;

	return RegisterRawInputDevices(Rid, 1, sizeof(Rid[0]));
}


LRESULT CALLBACK Generic::MouseRawWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam) {
	PAINTSTRUCT ps;
	HDC hdc;
	const uint8_t total_tries = 20;
	const uint8_t real_after = 5;

	switch (message) {
	case WM_INPUT: {
		
		UINT dwSize;

		// puts("WM_INPUT");

		GetRawInputData((HRAWINPUT)lParam, RID_INPUT, NULL, &dwSize, sizeof(RAWINPUTHEADER));
		LPBYTE lpb = new BYTE[dwSize];

		if (lpb == NULL)
			return 0;

		if (GetRawInputData((HRAWINPUT)lParam, RID_INPUT, lpb, &dwSize, sizeof(RAWINPUTHEADER)) != dwSize) {
			delete[] lpb;
			lpb = NULL;

			return 0;
		}

		RAWINPUT *raw = (RAWINPUT*)lpb;

		if (raw->header.dwType == RIM_TYPEMOUSE) {
			static LONG lastX = 0;
			static LONG lastY = 0;
			static uint8_t count = 0;
			static uint8_t tries = 0;

			++tries;

			if (lastX != raw->data.mouse.lLastX && lastY != raw->data.mouse.lLastY)
				++count;

			lastX = raw->data.mouse.lLastX;
			lastY = raw->data.mouse.lLastY;

			// not detected
			if (count >= real_after) {
				ExitProcess(0);
			}

			// detected
			if (tries >= total_tries) {
				ExitProcess(1);
			}
		}

		delete[] lpb;
		lpb = NULL;

		break;
	}
	case WM_PAINT:
		hdc = BeginPaint(hWnd, &ps);
		EndPaint(hWnd, &ps);
		break;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	default:
		return DefWindowProc(hWnd, message, wParam, lParam);
	}
	return 0;
}

} // SandboxEvasion
