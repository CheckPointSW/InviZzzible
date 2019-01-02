#include "kvm.h"

namespace SandboxEvasion {

KVM::KVM(const json_tiny &j)
	: VEDetection(j)
{
	module_name = std::string("KVM");
}

VEDetection* KVM::create_instance(const json_tiny &j)
{
	return new KVM(j);
}

void KVM::CheckAllCustom()
{
}


} // SandboxEvasion
