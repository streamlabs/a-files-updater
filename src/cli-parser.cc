
#include "argtable3.h"
#include "fmt/format.h"
#include "cli-parser.hpp"
#include "logger/log.h"
#include <clocale>
#include "utils.hpp"

/* Filesystem is implicitly included from cli-parser.h */
namespace fs = std::filesystem;

static bool validate_https_uri(struct uri_components *components)
{
	if (components->scheme.compare("https")) {
		log_debug("URL other than https isn't supported at this time");
		return false;
	}

	if (!components->scheme.empty())
		components->scheme = "443";

	return !components->scheme.empty() && !components->authority.empty();
}

enum arg_type { ARG_LITERAL, ARG_STRING, ARG_INTEGER, ARG_END };

template<typename Arg, typename Val> static void print_generic_arg(const Arg *arg, Val *values, size_t length)
{
	const char *null_string = "(null)";
	const char *short_names = arg->hdr.shortopts;
	const char *long_names = arg->hdr.longopts;

	if (!short_names)
		short_names = null_string;
	if (!long_names)
		long_names = null_string;

	for (int i = 0; i < length; ++i) {
		log_debug("%s,%s count: %s", short_names, long_names, fmt::format("{}", values[i]).c_str());
	}
}

static void print_literal_arg(const struct arg_lit *arg)
{
	print_generic_arg(arg, &arg->count, 1);
}

static void print_string_arg(const struct arg_str *arg)
{
	print_generic_arg(arg, arg->sval, arg->count);
}

static void print_integer_arg(const struct arg_int *arg)
{
	print_generic_arg(arg, arg->ival, arg->count);
}

static void print_end_arg(const struct arg_end *arg)
{
	log_debug("end of arguments");
}

static void print_arg(const void *arg, enum arg_type type)
{
	switch (type) {
	case ARG_LITERAL:
		print_literal_arg((struct arg_lit *)arg);
		break;
	case ARG_STRING:
		print_string_arg((struct arg_str *)arg);
		break;
	case ARG_INTEGER:
		print_integer_arg((struct arg_int *)arg);
		break;
	case ARG_END:
		print_end_arg((struct arg_end *)arg);
		break;
	}
}

static void print_arg_table(void **arg_table, enum arg_type *arg_types, const int table_size)
{
	for (int i = 0; i < table_size; ++i) {
		const arg_type type = arg_types[i];

		print_arg(arg_table[i], type);
	}
}

static std::vector<int> make_vector_from_arg(struct arg_int *arg)
{
	std::vector<int> result;

	for (int i = 0; i < arg->count; ++i) {
		result.push_back(arg->ival[i]);
	}

	return result;
}

static fs::path fetch_path(const char *str, size_t length)
{
	/* Use the utf8_facet here for anything provided from argtable */
	fs::path path = fs::u8path(str, str + length);

	log_debug("Given to fetch path: %.*s", length, str);

	fs::path result(fs::absolute(path).make_preferred());

	/* We use the utf8_facet here one more time to print-out UTF-8.
	 * Otherwise, it will print-out the system native which on Windows
	 * is wchar_t (encoded in UTF-16LE) */
	log_debug("Result of fetch path: %s", result.u8string().c_str());

	return result;
}

static fs::path fetch_default_temp_dir()
{
	std::error_code ec{};
	fs::path temp_dir = fs::temp_directory_path(ec);

	if (!ec) {
		temp_dir /= "slobs-updater";

		time_t t = time(nullptr);
		struct tm *lt = localtime(&t);

		std::srand(static_cast<unsigned int>(time(nullptr)));

		char buf[24];
		sprintf(buf, "%04i%03i%02i%02i%02i%c%c\0", lt->tm_year + 1900, lt->tm_yday, lt->tm_hour, lt->tm_min, lt->tm_sec, 'a' + rand() % 20,
			'a' + rand() % 20);

		temp_dir /= buf;

		fs::create_directories(temp_dir, ec);
	} else {
		log_info("Failed to get temporary directory from system: %d %s", ec.value(), ec.message().c_str());

		temp_dir = "";
	}
	return temp_dir;
}

bool su_parse_command_line(int argc, char **argv, struct update_parameters *params)
{
	std::error_code ec{};
	if (argc == 0 || argv == nullptr)
		return false;

	bool success = true;
	fs::path log_path;

	struct arg_lit *help_arg = arg_lit0("h", "help", "Print information about this program");

	struct arg_lit *dump_args_arg = arg_lit0(NULL, "dump-args", "Print all argument values, including this one");

	struct arg_lit *force_arg = arg_lit0(NULL, "force-temp", "Force use temporary directory even if it exists");

	struct arg_str *base_uri_arg = arg_str1("b", "base-url", "<url>", "The base URL to fetch updates from");

	struct arg_str *app_dir_arg = arg_str1("a", "app-dir", "<directory>", "The directory of which the application is located");

	struct arg_str *exec_arg = arg_str1("e", "exec", "<command line>", "The command-line used to start the application");

	struct arg_str *cwd_arg = arg_str0("c", "cwd", "<working directory>", "The working directory of which to start the application in");

	struct arg_str *temp_dir_arg = arg_str0("t", "temp-dir", "<directory>", "The directory to place temporary files to be deleted later");

	struct arg_str *version_arg = arg_str1("v", "version", "<version>", "The version of which to update to");

	struct arg_int *pids_arg = arg_intn("p", "pids", "<pid>", 0, 100, "The process ID's to wait on before starting the update");

	struct arg_int *interactive_arg = arg_intn("i", "interactive", "<interactive>", 0, 1, "Show user modal message boxes");

	struct arg_lit *restart_arg = arg_lit0(NULL, "restart-after-fail", "Start Streamlabs Desktop after update fail with option to skip update");

	struct arg_str *details_arg = arg_str1("d", "details", "<details>", "The details of the update");

	struct arg_end *end_arg = arg_end(255);

	void *arg_table[] = {help_arg,     dump_args_arg, force_arg, base_uri_arg,    app_dir_arg, exec_arg,    cwd_arg,
			     temp_dir_arg, version_arg,   pids_arg,  interactive_arg, restart_arg, details_arg, end_arg};

	const int arg_table_sz = sizeof(arg_table) / sizeof(arg_table[0]);

	int num_errors = arg_parse(argc, argv, arg_table);

	/* We need type information to dump parameters generically */
	enum arg_type arg_table_types[arg_table_sz] = {ARG_LITERAL, ARG_LITERAL, ARG_LITERAL, ARG_STRING,  ARG_STRING,  ARG_STRING, ARG_STRING,
						       ARG_STRING,  ARG_STRING,  ARG_INTEGER, ARG_INTEGER, ARG_LITERAL, ARG_STRING, ARG_END};

	/* Here we assume that stdout is setup correctly, otherwise --help is pointless */
	if (help_arg->count > 0) {
		fprintf(stdout, "Usage:");
		arg_print_syntaxv(stdout, arg_table, "\n\n");
		fprintf(stdout, "Options: \n");
		arg_print_glossary(stdout, arg_table, NULL);
		success = false;
		goto success;
	}

	if (temp_dir_arg->count > 0) {
		params->temp_dir = fetch_path(temp_dir_arg->sval[0], strlen(temp_dir_arg->sval[0]));
	} else {
		log_info("Temporary directory not provided.");

		params->temp_dir = fetch_default_temp_dir();

		if (params->temp_dir.empty()) {
			log_info("Generated temporary directory failed");
			success = false;
			goto parse_error;
		} else {
			log_info("Generated temporary directory: %s", params->temp_dir.c_str());
		}
	}

	log_path = params->temp_dir;
	log_path /= "slobs-updater.log";

	params->log_file_path = log_path.string();
	params->log_file = fopen(log_path.string().c_str(), "w+");

	/* If we fail, we just won't get a log file unfortunately */
	if (params->log_file)
		log_set_fp(params->log_file);

	if (dump_args_arg->count > 0)
		print_arg_table(arg_table, arg_table_types, arg_table_sz);

	if (num_errors > 0) {
		arg_print_errors(params->log_file, end_arg, argv[0]);
		goto parse_error;
	}

	/* We have all of the required parameters
	 * and should be able to assume they exist
	 * along with how many instances there are. */
	success = su_parse_uri(base_uri_arg->sval[0], strlen(base_uri_arg->sval[0]), &params->host);

	if (success)
		success = validate_https_uri(&params->host);

	if (!success) {
		log_fatal("Invalid uri given for base_uri");
	}

	params->app_dir = fetch_path(app_dir_arg->sval[0], strlen(app_dir_arg->sval[0]));

	if (params->app_dir.u8string().find("Program Files") != std::string::npos) {
		if (params->app_dir.u8string().find("Streamlabs OBS") != std::string::npos ||
		    params->app_dir.u8string().find("Streamlabs Desktop") != std::string::npos) {
			params->enable_removing_old_files = true;
		}
	}
	if (params->enable_removing_old_files)
		log_warn("The path does look like a default install path. Updater be able to remove files from old versions.");
	else
		log_warn("The path does look like a default install path. Updater will not be able to remove files from old versions.");

	params->exec.assign(std::string("\"") + std::string(exec_arg->sval[0]) + std::string("\""));
	params->exec_no_update.assign(std::string("\"") + std::string(exec_arg->sval[0]) + std::string("\"") + std::string(" --skip-update"));

	if (cwd_arg->count > 0) {
		params->exec_cwd.assign(cwd_arg->sval[0]);
	}

	if (params->app_dir.empty()) {
		log_fatal("Invalid path given for app_dir");
		success = false;
	} else if (!fs::exists(params->app_dir, ec)) {
		log_fatal("Application directory doesn't exist");
		success = false;
	} else {
		if (is_system_folder(params->app_dir)) {
			log_fatal("Application directory is a system directory");
			success = false;
		} else if (!fs::is_directory(params->app_dir, ec)) {
			log_fatal("Application directory is not a directory");
			success = false;
		}
	}

	if (params->temp_dir.empty()) {
		log_fatal("Invalid path given for temp_dir");
		success = false;
	} else if (fs::exists(params->temp_dir, ec)) {
		if (force_arg->count == 0) {
			log_fatal("Temporary directory already exists.");
			success = false;
		} else {
			log_warn("Forcing temporary directory!");
		}
	}

	params->pids = make_vector_from_arg(pids_arg);
	params->version.assign(version_arg->sval[0]);
	params->details.assign(details_arg->sval[0]);

	if (interactive_arg->count > 0) {
		params->interactive = interactive_arg->ival[0];
	}

	if (restart_arg->count > 0) {
		params->restart_on_fail = true;
	}

	if (!success)
		goto parse_error;

	fs::create_directory(params->temp_dir, ec);

	success = true;

	goto success;

parse_error:
	success = false;

success:
	arg_freetable(arg_table, arg_table_sz);

	return success;
}