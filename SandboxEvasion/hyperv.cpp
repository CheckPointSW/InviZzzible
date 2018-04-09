#include "hyperv.h"

namespace SandboxEvasion {

VEDetection* HyperV::create_instance(const json_tiny &j) {
	return new HyperV(j);
}

void HyperV::CheckAllCustom() {

}

} // SandboxEvasion
