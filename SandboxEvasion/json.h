#ifndef  _JSON_H
#define  _JSON_H

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <type_traits>
#include "helper.h"

namespace pt = boost::property_tree;

// tiny json implementation
class json_tiny {
	pt::ptree root;		// root of JSON object 

public:
	json_tiny() {}
	json_tiny(const pt::ptree &_root) : root(_root) {}
	virtual ~json_tiny() {}

	static json_tiny* load(const char *pfn);
	static bool dump(const json_tiny &, const char *pfn);

	template <typename T>
	const T get(const std::string &field, const T &_def) const {
		try {
			return _get<T>(field);
		}
		catch (const pt::ptree_bad_path &e) {
			return _def;
		}
	}

	template <>
	const pt::ptree get(const std::string &field, const pt::ptree &_def) const {
		try {
			return _get_child(field);
		}
		catch (const pt::ptree_bad_path &e) {
			return _def;
		}
	}
	
	template <typename T>
	const T operator[](const std::string &) const {
		return _get(field);
	}

private:
	template <typename T>
	const T _get(const std::string &field) const {
		return root.get<T>(field);
	}

	const pt::ptree _get_child(const std::string &field) const {
		return root.get_child(field);
	}
};

#endif // ! _JSON_H
