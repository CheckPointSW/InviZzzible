#include "joebox.h"

namespace SandboxEvasion {

VEDetection* Joebox::create_instance(const json_tiny &j) {
	return new Joebox(j);
}

void Joebox::CheckAllCustom() {

}

} // SandboxEvasion
