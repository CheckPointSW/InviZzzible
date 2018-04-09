#include "wine.h"

namespace SandboxEvasion {

VEDetection* Wine::create_instance(const json_tiny &j) {
	return new Wine(j);
}

void Wine::CheckAllCustom() {

}

} // SandboxEvasion
