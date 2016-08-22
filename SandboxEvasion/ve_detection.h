#ifndef _VE_DETECTION_H
#define _VE_DETECTION_H

namespace SandboxEvasion {
	class VEDetection {
	public:
		virtual ~VEDetection() = default;
		bool RegKeyEnumPci() const;
	};
}

#endif // !_VM_DETECTION_H

