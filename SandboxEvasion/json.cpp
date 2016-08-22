#include "json.h"

bool JSON::load(file_name_t &file_name) {
	parsed = false;

	try {
		pt::read_json(file_name.c_str(), root);
	}
	catch (const pt::json_parser::json_parser_error &) {
		return false;
	}

	parsed = true;

	return true;
}

bool JSON::dump(file_name_t &file_name) const {
	// FIXME: implement

	if (!parsed)
		return false;

	return true;
}

template <typename T>
const T& JSON::get(const std::string &field, const T &_def) const {
	if (!parsed)
		return _def;

	try {
		return _get(field);
	}
	catch (const pt::ptree_bad_path &e) {
		return _def;
	}
}

bool JSON::add() {
	// FIXME: implement

	if (!parsed)
		return false;

	return true;
}

template <typename T>
const T& JSON::operator[](const std::string &field) const {
	return _get(field);
}

template <typename T>
const T& JSON::_get(const std::string &field) const {
	return root.get<T>(field);
}