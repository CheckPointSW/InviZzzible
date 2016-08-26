#include "ve_detection.h"

#include <iostream>
using std::cout;
using std::endl;

namespace SandboxEvasion {

	// return first: html information
	// return second: debug information
	std::pair<std::string, std::string> VEDetection::GenerateReportEntry(const std::string &name, json_tiny &j, bool detected) const {
		std::ostringstream ostream_debug;
		std::ostringstream ostream_html;

		std::string desc = j.get<std::string>("description", "");
		std::string wtd = j.get<std::string>("countermeasures", "");
		std::string dtype = j.get<std::string>("type", "");

		ostream_debug << name  << "> " << desc << ": " << detected << std::endl;
		
		// FIXME: generate HTML template stream


		return std::pair<std::string, std::string>(ostream_html.str(), ostream_debug.str());
	}

}
