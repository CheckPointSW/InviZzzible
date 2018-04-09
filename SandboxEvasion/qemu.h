#ifndef _QEMU_H
#define _QEMU_H

#include "ve_detection.h"

namespace SandboxEvasion {

class QEMU : VEDetection {
public:
	QEMU(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("QEMU");
	}
	virtual ~QEMU() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _QEMU_H
