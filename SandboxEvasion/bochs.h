#ifndef _BOCHS_H
#define _BOCHS_H

#include "ve_detection.h"

namespace SandboxEvasion {

class BOCHS : VEDetection {
public:
	BOCHS(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("BOCHS");
	}
	virtual ~BOCHS() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _BOCHS_H
