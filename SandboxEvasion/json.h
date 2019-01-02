#ifndef  _JSON_H
#define  _JSON_H

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/foreach.hpp>
#include <type_traits>
#include <sstream>
#include "helper.h"

#include <iostream>

namespace pt = boost::property_tree;

// tiny json implementation
class json_tiny {
	pt::ptree root;		// root of JSON object 

public:
	json_tiny() {}
	json_tiny(const pt::ptree &_root) : root(_root) {}
	virtual ~json_tiny() {}

	static json_tiny* load(const char *pfn);
	static json_tiny* load(std::stringstream &ss);
	static bool dump(const json_tiny &, const char *pfn);

	template <typename T>
	const T get(const std::string &field, const T &_def) const {
		try {
			return _get<T>(field);
		}
		catch (const pt::ptree_bad_path &) {
			return _def;
		}
	}

	template <>
	const pt::ptree get(const std::string &field, const pt::ptree &_def) const {
		try {
			return _get_child(field);
		}
		catch (const pt::ptree_bad_path &) {
			return _def;
		}
	}

	/*
	template <typename T>
	const std::list<T> get_array(const std::string &field) const {
		std::list<T> jl;

		BOOST_FOREACH(const pt::ptree::value_type &obj, root) {
			jl.push_back(obj.second.data());
		}

		return jl;
	}
	*/

	const std::list<std::string> get_entries(const std::string &field) const {
		std::string fe = get<std::string>(field, "");
		if (fe.empty()) 
			return get_array(field);

		return { fe };
	}

	const std::list<std::string> get_array(const std::string &field) const {
		std::list<std::string> jl;
		pt::ptree r;
		try {
			r = root.get_child(field);
		}
		catch (const pt::ptree_bad_path &) {
			return jl;
		}

		BOOST_FOREACH(const pt::ptree::value_type &obj, r) {
			jl.push_back(obj.second.data());
		}

		return jl;
	}

	template <typename T>
	const T operator[](const std::string &) const {
		return _get(field);
	}

	const std::list<std::pair<std::string, json_tiny>> get_objects(const std::string &type_key, const std::string &type_value) const {
		std::list<std::pair<std::string, json_tiny>> jl;
		BOOST_FOREACH(const pt::ptree::value_type &obj, root) {
			if (obj.second.get<std::string>(type_key, "") == type_value) {
				jl.push_back(std::pair<std::string, json_tiny>(obj.first, obj.second));
			}
		}

		return jl;
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
