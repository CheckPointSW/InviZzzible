#include "bochs.h"

namespace SandboxEvasion {

VEDetection* BOCHS::create_instance(const json_tiny &j) {
	return new BOCHS(j);
}

void BOCHS::CheckAllCustom() {

}

} // SandboxEvasion
