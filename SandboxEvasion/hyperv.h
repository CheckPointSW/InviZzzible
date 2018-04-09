#ifndef _HYPERV_H
#define _HYPERV_H

#include "ve_detection.h"

namespace SandboxEvasion {

class HyperV : VEDetection {
public:
	HyperV(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("HYPERV");
	}
	virtual ~HyperV() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _HYPERV_H
