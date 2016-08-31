#ifndef  _VMWARE_H
#define _VMWARE_H

#include "ve_detection.h"

namespace SandboxEvasion {
	class VMWare : VEDetection {
	public:
		VMWare(const json_tiny &j) :
			VEDetection(j) {
			module_name = std::string("VMWARE");
		}
		virtual ~VMWare() {}

		static VEDetection* create_instance(const json_tiny &j);

		// overriden
		virtual void CheckAllCustom();

		// custom methods
		bool CheckHypervisorPort() const;
		bool CheckNDISFile() const;
		bool IsHypervisor() const;
	};

} // SandboxEvasion

#endif // ! _VMWARE_H

