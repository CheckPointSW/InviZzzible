#include "report.h"
#include "helper.h"
#include <fstream>
#include <sstream>


bool Report::load() {
	// loading content of files
	std::ifstream ifsb(bootstrap_f);
	if (!ifsb.is_open()) {
		// load from the pre generated file
		#include "data_bootstrap_css.h"
		bootstrap_content = std::string(bootstrap_data);
	}
	else {
		bootstrap_content.assign((std::istreambuf_iterator<char>(ifsb)), (std::istreambuf_iterator<char>()));
	}

	std::ifstream ifsr(report_f);
	if (!ifsr.is_open()) {
		#include "data_report_html.h"
		report = std::string(report_data);
	}
	else {
		report.assign((std::istreambuf_iterator<char>(ifsr)), (std::istreambuf_iterator<char>()));
	}

	// find bootstrap expression
	return string_replace_substring(report, bootstrap_s, bootstrap_content);
}

bool Report::dump(const std::string &fname) const {
	std::ofstream ofs(fname);
	if (!ofs.is_open())
		return false;

	std::string freport = report;
	if (!string_replace_substring(freport, module_s, ""))
		return false;

	ofs << freport;
	ofs.close();

	return true;
}

bool Report::add_entry(const std::vector<std::string> &columns) {
	if (columns.size() != column_names.size() && columns.size() > 3)
		return false;

	std::stringstream table_entry;

	// FIXME: make entries instead of numbers
	if (columns[3] == "YES")
		table_entry << "<tr class = \"danger\">";
	else if (columns[3] == "NO")
		table_entry << "<tr class = \"success\">";
	else return false;

	// generate table report entry
	for (auto &c : columns) {
		table_entry << "\n<td>" << c << "</td>\n";
	}

	table_entry << "</tr>\n";
	table_entries.push_back(table_entry.str());

	return true;
}

bool Report::flush(const std::string &header_name) {
	std::stringstream s;

	// generate report for specific module
	s << "<h2 class = \"text-primary\">" << header_name << "</h2>\n";
	s << "<table class=\"table\">\n";
	s << "<thead>\n<tr>\n";
	
	for (auto &cn : column_names)
		s << "<th>" << cn << "</th>\n";

	s << "</tr>\n</thead>\n";

	s << "<tbody>\n";

	for (auto &te : table_entries)
		s << te << "\n";

	s << "</tbody>\n</table>\n";

	table_entries = {};

	// add to current report data
	return string_replace_substring(report, module_s, s.str() + module_s);
}
