#ifndef _JOEBOX_H
#define _JOEBOX_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Joebox : VEDetection {
public:
	Joebox(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("JOEBOX");
	}
	virtual ~Joebox() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _JOEBOX_H
