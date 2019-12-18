#ifndef _GENERIC_H
#define _GENERIC_H

#include "ve_detection.h"
#include "json.h"
#include "helper.h"

namespace SandboxEvasion {

class Generic : VEDetection {
public:
	Generic(const json_tiny &j) : VEDetection(j) {
		module_name = std::string("GENERIC");
		mouse_raw_wnd_class = "MouseRawWnd";
	}
	virtual ~Generic() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();

	bool CheckTimeTampering(ProcessWorkingMode wm) const;
	bool CheckMouseRawActive(ProcessWorkingMode wm);
	bool CheckUserInputActivity(ProcessWorkingMode wm);

	static LRESULT CALLBACK MouseRawWndProc(HWND hWnd, UINT message, WPARAM wParam, LPARAM lParam);

protected:
	bool CheckSystemUptime() const;
	bool CheckRAM() const;
	bool CheckBigRAMAllocate() const;
	bool CheckDiskSize() const;
	bool CheckDriveSize() const;
	bool CheckNDISFile() const;
	bool CheckMouseActive() const;
	bool CheckSleepDummyPatch() const;
	bool CheckPerformanceCounter() const;
	bool CheckNumberOfProcessors() const;
	bool CheckDNSResponse() const;
	bool CheckTimeTamperingMaster() const;
	bool CheckTimeTamperingSlave() const;
	bool CheckMouseRawActiveMaster();
	bool CheckMouseRawActiveSlave();
	bool CheckUserInputActivityMaster();
	bool CheckUserInputActivitySlave();
	bool CheckAudioDeviceAbsence() const;

private:
	std::string mouse_raw_wnd_class;
	HINSTANCE mouse_raw_hinst;

	ATOM MouseRawActiveRegisterClass(HINSTANCE hInstance);
	BOOL MouseRawActiveInitInstance(HINSTANCE hInstance);
};

} // SandboxEvasion

#endif // !_GENERIC_H
