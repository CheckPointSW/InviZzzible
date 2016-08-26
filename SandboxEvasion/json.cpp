#include "json.h"


json_tiny* json_tiny::load(const char *pfn) {
	pt::ptree jroot;

	try {
		pt::read_json(pfn, jroot);
		return new(std::nothrow) json_tiny(jroot);
	}
	catch (const pt::json_parser::json_parser_error &e) {
		return nullptr;
	}
}

bool json_tiny::dump(const json_tiny &, const char *pfn) {
	// FIXME: implement do we need it???

	return true;
}
