#ifndef _REPORT_H
#define _REPORT_H

#include <string>
#include <vector>
#include <list>

class Report {
	std::string bootstrap_s;
	std::string module_s;
	std::string bootstrap_f;
	std::string report_f;
	std::string bootstrap_content;
	std::string report;
	std::list<std::string> table_entries;

	std::vector<std::string> column_names;

public:
	Report(const std::string &html_template = std::string("report.html"), std::string &_bootstrap = std::string("bootstrap.css")):
		bootstrap_f(_bootstrap), report_f(html_template), bootstrap_s("%BOOTSTRAP%"), module_s("%MODULE%") {
		column_names = { "Detection Name", "Type", "Description", "Detected", "Countermeasures", "Score" };
	}
	virtual ~Report() {}

	bool load();
	bool dump(const std::string &fname) const;
	bool add_entry(const std::vector<std::string> &columns);
	bool flush(const std::string &header_name);
};


#endif // !_BOOTSTRAP_H

