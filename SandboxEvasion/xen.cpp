#include "xen.h"

namespace SandboxEvasion {

VEDetection* Xen::create_instance(const json_tiny &j) {
    return new Xen(j);
}

void Xen::CheckAllCustom() {

}

} // SandboxEvasion
