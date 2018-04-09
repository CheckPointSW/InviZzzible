#ifndef _SANDBOXIE_H
#define _SANDBOXIE_H

#include "ve_detection.h"

namespace SandboxEvasion {

class Sandboxie : VEDetection {
public:
    Sandboxie(const json_tiny &j) :
        VEDetection(j) {
        module_name = std::string("SANDBOXIE");
    }
    virtual ~Sandboxie() {}

    static VEDetection* create_instance(const json_tiny &j);

    // overriden
    virtual void CheckAllCustom();
};

} // SandboxEvasion

#endif // ! _SANDBOXIE_H
