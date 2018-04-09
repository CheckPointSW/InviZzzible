#ifndef _WINE_H
#define _WINE_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Wine : VEDetection {
public:
	Wine(const json_tiny &j) :
		VEDetection(j) {
		module_name = std::string("WINE");
	}
	virtual ~Wine() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _WINE_H
