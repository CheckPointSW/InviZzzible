__author__ = 'arl'

import os
from json import load
from sys import argv
from os import path


REPORT = "report.html"
BOOTSTRAP = "bootstrap.css"
CONFIG_PATH = "../config/"

OUT_DEFAULT_CONFIG = "default_configs.h"
OUT_DATA_REPORT = "data_report_html.h"
OUT_DATA_BOOTSTRAP = "data_bootstrap_css.h"


def make_hex_array(data):
    return ",".join(
        [
            "0x%02x" % ord(x) + ("\n" if (i + 1) % 16 == 0 else "")
            for i, x in enumerate(data)
        ]
    )


def escape_file_data(data):
    data = data.replace("\\", "\\\\")
    data = data.replace('"', '\\"')
    return "\\\n".join(map(str.rstrip, data.split("\n")))


def read_data(fn):
    try:
        with open(fn, "r") as f:
            return f.read()
    except Exception as e:
        print("File Read Exception: %s" % e)
        return


def write_data(fn, data):
    try:
        with open(fn, "w") as f:
            f.write(data)
    except Exception as e:
        print("File Write Exception: %s" % e)
        return False

    return True


def get_file_data(conf, option):
    fn = conf.get(option, "")
    if not fn:
        print("Configuration parameter: `%s' is absent" % option)
        return False

    return read_data(fn)


def create_includes(sandboxes):
    report_d = read_data(REPORT)
    bootstrap_d = read_data(BOOTSTRAP)

    sandbox_file = "std::list<std::pair<std::string, const char *>> default_configs;\n"
    for sandbox in sandboxes:
        sandbox_d = read_data(path.join(CONFIG_PATH, sandbox + ".conf"))
        sandbox_file += f"""static const char {sandbox}_conf[] = %s;
        \ndefault_configs.push_back(std::pair<std::string, const char *>(std::string("{sandbox}"), {sandbox}_conf));
        """ % (
            "{" + make_hex_array(sandbox_d) + "}"
        )

    report_file = 'static const char *report_data = "%s";' % escape_file_data(report_d)
    bootstrap_file = "static const char bootstrap_data[] = {\n%s\n};" % make_hex_array(
        bootstrap_d
    )

    if not write_data(OUT_DEFAULT_CONFIG, sandbox_file):
        return False
    if not write_data(OUT_DATA_REPORT, report_file):
        return False
    if not write_data(OUT_DATA_BOOTSTRAP, bootstrap_file):
        return False

    return True


def read_conf(fn):
    try:
        with open(fn, "r") as f:
            return load(f)
    except Exception as e:
        print("Configuration Read Exception: %s" % e)
        return


def list_configs():
    return [
        x.split(".")[0]
        for x in filter(lambda x: x.endswith(".conf"), os.listdir(CONFIG_PATH))
    ]


def main():
    configs = list_configs()
    if len(argv) < 2:
        print(
            "GenDefaultData usage: %s [configuration_name1] [configuration_name2] [...]"
            % argv[0]
        )
        print("List of detection sets:\n" + "\n".join(configs))
        exit(1)

    for ds in argv[1:]:
        if ds not in configs:
            print(f"Invalid configuration name: {ds}")
            exit(2)

    if not create_includes(argv[1:]):
        exit(3)


if __name__ == "__main__":
    main()
