#ifndef  _JSON_H
#define  _JSON_H

#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include "helper.h"

namespace pt = boost::property_tree;

class JSON {
	pt::ptree root;		// root of JSON object 
	bool parsed;
public:
	JSON() {}
	~JSON() {}
	// TODO: add different operators and blabla, restrictions

	bool load(file_name_t &);
	bool dump(file_name_t &) const;
	template <typename T>
	const T& get(const std::string &, const T &) const;
	bool add();
	
	template <typename T>
	const T& operator[](const std::string &) const;

private:
	template <typename T>
	const T& _get(const std::string &) const;
};

#endif // ! _JSON_H
