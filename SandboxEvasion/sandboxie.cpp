#include "sandboxie.h"

namespace SandboxEvasion {

VEDetection* Sandboxie::create_instance(const json_tiny &j) {
    return new Sandboxie(j);
}

void Sandboxie::CheckAllCustom() {

}

} // SandboxEvasion
