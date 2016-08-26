#ifndef _VE_DETECTION_H
#define _VE_DETECTION_H

#include "json.h"

namespace SandboxEvasion {
	class VEDetection {
	public:
		VEDetection(const json_tiny &j) : conf(j) {}
		virtual ~VEDetection() {};

		std::pair<std::string, std::string> GenerateReportEntry(const std::string &name, json_tiny &j, bool detected) const;
		virtual void CheckAll() = 0;
		virtual std::string GetReport() const = 0;
	protected:
		json_tiny conf;
		std::string module_name;
		std::string report;
	};
}

#endif // !_VM_DETECTION_H

