#pragma once

#include "ve_detection.h"

namespace SandboxEvasion {

class KVM : VEDetection {
public:
    KVM(const json_tiny &j);
    virtual ~KVM() {}

    static VEDetection* create_instance(const json_tiny &j);

    // overriden
    virtual void CheckAllCustom();
};

} // SandboxEvasion
