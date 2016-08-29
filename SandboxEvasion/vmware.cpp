#include "vmware.h"

namespace SandboxEvasion {

VEDetection* VMWare::create_instance(const json_tiny &j){
	return new VMWare(j);
}

void VMWare::CheckAllCustom() {
	// FIXME: implement checking all custom techniques

}

} // SandboxEvasion