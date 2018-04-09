#include "misc.h"

namespace SandboxEvasion {

VEDetection* Misc::create_instance(const json_tiny &j) {
	return new Misc(j);
}

void Misc::CheckAllCustom() {

}

} // SandboxEvasion
