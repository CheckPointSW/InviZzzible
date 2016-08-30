#include "vbox.h"

namespace SandboxEvasion {

	VEDetection* VBOX::create_instance(const json_tiny &j) {
		return new VBOX(j);
	}

	void VBOX::CheckAllCustom() {

	}

} // SandboxEvasion
