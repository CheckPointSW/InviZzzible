#ifndef _XEN_H
#define _XEN_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Xen : VEDetection {
public:
    Xen(const json_tiny &j) :
        VEDetection(j) {
        module_name = std::string("XEN");
    }
    virtual ~Xen() {}

    static VEDetection* create_instance(const json_tiny &j);

    // overriden
    virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _XEN_H
