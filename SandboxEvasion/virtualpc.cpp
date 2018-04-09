#include "virtualpc.h"

namespace SandboxEvasion {

VEDetection* VirtualPC::create_instance(const json_tiny &j) {
    return new VirtualPC(j);
}

void VirtualPC::CheckAllCustom() {

}

} // SandboxEvasion
