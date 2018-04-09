#ifndef _PARALLELS_H
#define _PARALLELS_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Parallels : VEDetection {
public:
	Parallels(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("PARALLELS");
	}
	virtual ~Parallels() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _PARALLELS_H
