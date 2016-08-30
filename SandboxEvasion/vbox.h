#ifndef _VBOX_H
#define _VBOX_H

#include "ve_detection.h"

namespace SandboxEvasion {

class VBOX : VEDetection {
public:
	VBOX(const json_tiny &j) : VEDetection(j) {
		module_name = std::string("VBOX");
	}
	virtual ~VBOX() {}

	static VEDetection* create_instance(const json_tiny &j);

	// overriden
	virtual void CheckAllCustom();

};

} // SandboxEvasion


#endif // !_VBOX_H

