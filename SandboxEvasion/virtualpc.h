#ifndef _VIRTUALPC_H
#define _VIRTUALPC_H

#include "ve_detection.h"

namespace SandboxEvasion {

class VirtualPC : VEDetection {
public:
    VirtualPC(const json_tiny &j) :
        VEDetection(j) {
        module_name = std::string("VIRTUALPC");
    }
    virtual ~VirtualPC() {}

    static VEDetection* create_instance(const json_tiny &j);

    // overriden
    virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _VIRTUALPC_H
