#include "qemu.h"

namespace SandboxEvasion {

VEDetection* QEMU::create_instance(const json_tiny &j) {
	return new QEMU(j);
}

void QEMU::CheckAllCustom() {

}

} // SandboxEvasion
