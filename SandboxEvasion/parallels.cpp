#include "parallels.h"

namespace SandboxEvasion {

VEDetection* Parallels::create_instance(const json_tiny &j) {
    return new Parallels(j);
}

void Parallels::CheckAllCustom() {

}

} // SandboxEvasion
