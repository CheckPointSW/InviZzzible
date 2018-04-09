#ifndef _MISC_H
#define _MISC_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Misc : VEDetection {
public:
	Misc(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("MISC");
	}
	virtual ~Misc() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _MISC_H
