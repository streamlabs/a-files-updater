
#include "argtable3.h"
#include "fmt/format.h"
#include "cli-parser.hpp"
#include "hook-permissions.hpp"
#include "logger/log.h"
#include "updater-storage.hpp"
#include <clocale>
#include <cwctype>
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

static std::wstring lowered(std::wstring text)
{
	for (wchar_t &c : text)
		c = towlower(c);

	return text;
}

/* True when `path` is `root` or sits below it, compared without case because
 * Windows paths are. */
static bool is_inside(const fs::path &path, const fs::path &root)
{
	const std::wstring prefix = lowered(root.wstring()) + L"\\";

	return lowered(path.wstring()).rfind(prefix, 0) == 0;
}

bool su_parse_command_line(int argc, char **argv, struct update_parameters *params)
{
	std::error_code ec{};
	if (argc == 0 || argv == nullptr)
		return false;

	bool success = true;
	fs::path log_path;
	UpdaterStorageDiagnostics storage_diagnostics;

	struct arg_lit *help_arg = arg_lit0("h", "help", "Print information about this program");

	struct arg_lit *dump_args_arg = arg_lit0(NULL, "dump-args", "Print all argument values, including this one");

	struct arg_lit *force_arg = arg_lit0(NULL, "force-temp", "Reuse an existing temporary directory after verifying its permissions");

	struct arg_str *base_uri_arg = arg_str1("b", "base-url", "<url>", "The base URL to fetch updates from");

	struct arg_str *app_dir_arg = arg_str1("a", "app-dir", "<directory>", "The directory of which the application is located");

	struct arg_str *exec_arg = arg_str1("e", "exec", "<command line>", "The command-line used to start the application");

	struct arg_str *cwd_arg = arg_str0("c", "cwd", "<working directory>", "The working directory of which to start the application in");

	struct arg_str *temp_dir_arg = arg_str0("t", "temp-dir", "<directory>", "A trusted directory for staged and backup files");

	struct arg_str *version_arg = arg_str1("v", "version", "<version>", "The version of which to update to");

	struct arg_int *pids_arg = arg_intn("p", "pids", "<pid>", 0, 100, "The process ID's to wait on before starting the update");

	struct arg_int *interactive_arg = arg_intn("i", "interactive", "<interactive>", 0, 1, "Show user modal message boxes");

	struct arg_int *hook_prompt_arg =
		arg_intn(NULL, "hook-prompt", "<hook-prompt>", 0, 1, "Ask the user to close whatever is holding the graphics hook directory open");

	struct arg_str *hook_dir_arg = arg_str0(NULL, "hook-dir", "<directory>", "Graphics hook directory to secure, for tests. Defaults to the shared one");

	struct arg_lit *restart_arg = arg_lit0(NULL, "restart-after-fail", "Start Streamlabs Desktop after update fail with option to skip update");

	struct arg_str *details_arg = arg_str1("d", "details", "<file>", "Path to the file containing details of the update");

	struct arg_end *end_arg = arg_end(255);

	void *arg_table[] = {help_arg,    dump_args_arg, force_arg,       base_uri_arg,    app_dir_arg,  exec_arg,    cwd_arg,     temp_dir_arg,
			     version_arg, pids_arg,      interactive_arg, hook_prompt_arg, hook_dir_arg, restart_arg, details_arg, end_arg};

	const int arg_table_sz = sizeof(arg_table) / sizeof(arg_table[0]);

	int num_errors = arg_parse(argc, argv, arg_table);

	/* We need type information to dump parameters generically */
	enum arg_type arg_table_types[arg_table_sz] = {ARG_LITERAL, ARG_LITERAL, ARG_LITERAL, ARG_STRING,  ARG_STRING, ARG_STRING,  ARG_STRING, ARG_STRING,
						       ARG_STRING,  ARG_INTEGER, ARG_INTEGER, ARG_INTEGER, ARG_STRING, ARG_LITERAL, ARG_STRING, ARG_END};

	/* Here we assume that stdout is setup correctly, otherwise --help is pointless */
	if (help_arg->count > 0) {
		fprintf(stdout, "Usage:");
		arg_print_syntaxv(stdout, arg_table, "\n\n");
		fprintf(stdout, "Options: \n");
		arg_print_glossary(stdout, arg_table, NULL);
		success = false;
		goto success;
	}

	//if missing 'details' param ignore it
	if (num_errors == 1 && end_arg->parent) {
		arg_hdr *parent = (arg_hdr *)end_arg->parent[0];
		if (parent && parent->shortopts && strcmp(parent->shortopts, "d") == 0)
			num_errors = 0;
	}

	if (num_errors > 0) {
		arg_dstr_t errors = arg_dstr_create();
		arg_print_errors_ds(errors, end_arg, argv[0]);
		params->startup_diagnostic = arg_dstr_cstr(errors);
		arg_dstr_destroy(errors);
		arg_print_errors(stderr, end_arg, argv[0]);
		goto parse_error;
	}

	/* Storage setup can fail before the normal log exists. Preserve enough of
	 * the valid command line to restart Desktop without attempting an update. */
	params->exec.assign(std::string("\"") + std::string(exec_arg->sval[0]) + std::string("\""));
	params->exec_no_update.assign(std::string("\"") + std::string(exec_arg->sval[0]) + std::string("\"") + std::string(" --skip-update"));
	if (cwd_arg->count > 0)
		params->exec_cwd.assign(cwd_arg->sval[0]);
	if (interactive_arg->count > 0)
		params->interactive = interactive_arg->ival[0];

	if (temp_dir_arg->count > 0) {
		params->temp_dir = fetch_path(temp_dir_arg->sval[0], strlen(temp_dir_arg->sval[0]));
		if (!prepare_updater_temp_dir(params->temp_dir, force_arg->count > 0, &storage_diagnostics)) {
			params->startup_error_category = storage_diagnostics.failure_category.empty() ? "UpdaterStorageFailure"
												      : storage_diagnostics.failure_category;
			params->startup_error_reason = ConvertToUtf8(storage_diagnostics.failure);
			params->startup_diagnostic = params->startup_error_reason;
			success = false;
			goto parse_error;
		}
		params->owns_temp_dir = storage_diagnostics.created;
		params->enforce_temp_ancestors = true;
	} else {
		log_info("Temporary directory not provided.");

		params->temp_dir = create_default_updater_temp_dir(&storage_diagnostics);

		if (params->temp_dir.empty()) {
			params->startup_error_category = storage_diagnostics.failure_category.empty() ? "UpdaterStorageFailure"
												      : storage_diagnostics.failure_category;
			params->startup_error_reason = ConvertToUtf8(storage_diagnostics.failure);
			params->startup_diagnostic = params->startup_error_reason;
			success = false;
			goto parse_error;
		}
		params->owns_temp_dir = true;
		params->enforce_temp_ancestors = false;
	}
	if (!acquire_updater_run_lock(params->temp_dir, &params->temp_dir_lock, &storage_diagnostics)) {
		params->startup_error_category = storage_diagnostics.failure_category.empty() ? "UpdaterStorageFailure" : storage_diagnostics.failure_category;
		params->startup_error_reason = ConvertToUtf8(storage_diagnostics.failure);
		params->startup_diagnostic = params->startup_error_reason;
		success = false;
		goto parse_error;
	}
	if (!storage_diagnostics.ancestor_warning.empty()) {
		params->storage_ancestor_warning = ConvertToUtf8(storage_diagnostics.ancestor_warning);
		params->startup_diagnostic = params->storage_ancestor_warning;
	}
	if (!storage_diagnostics.root_replaced_reason.empty())
		params->storage_root_replaced = ConvertToUtf8(storage_diagnostics.root_replaced_reason);
	if (!storage_diagnostics.cleanup_warning.empty())
		params->storage_prune_warning = ConvertToUtf8(storage_diagnostics.cleanup_warning);

	log_path = params->temp_dir;
	log_path /= "slobs-updater.log";

	params->log_file_path = log_path;
	params->log_file = _wfopen(log_path.c_str(), L"w+");

	/* If we fail, we just won't get a log file unfortunately */
	if (params->log_file)
		log_set_fp(params->log_file);
	wlog_info(L"Using updater storage directory: %s", params->temp_dir.c_str());

	if (dump_args_arg->count > 0)
		print_arg_table(arg_table, arg_table_types, arg_table_sz);

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
	}

	params->pids = make_vector_from_arg(pids_arg);
	params->version.assign(version_arg->sval[0]);
	params->details.assign(details_arg->sval[0]);

	if (interactive_arg->count > 0) {
		params->interactive = interactive_arg->ival[0];
	}

	if (hook_prompt_arg->count > 0) {
		params->hook_prompt = hook_prompt_arg->ival[0];
	}

	params->hook_dir = programdata_hook_dir();

	/* Only the tests pass this, and everything it points at gets renamed,
	 * scheduled for deletion at the next reboot, and replaced by a
	 * directory owned by Administrators - by a process running elevated,
	 * from a command line composed by one that is not. So it is resolved
	 * before it is judged, since ".." and a junction both spell a path that
	 * is not the one it looks like, and held to the shape of the thing it
	 * stands in for: the real leaf name, under the tests' own scratch root
	 * rather than anywhere the argument happens to point. The scratch root
	 * is read back through the same known-folder lookup programdata_hook_dir
	 * uses, not the %ProgramData% environment variable, which the same
	 * unelevated command line could have set to anything.
	 *
	 * Resolving early only catches a path dressed up to look like another
	 * one; it says nothing about a component swapped out after this check
	 * runs and before the elevated process acts on the string. Closing that
	 * needs the same guarantee the shared directory's own ancestors get:
	 * chain_trust demands every directory above the leaf is one only
	 * Administrators can rename or replace, which an unelevated caller who
	 * owns something under the scratch tree cannot arrange. Unlike the real
	 * hook directory, refusing costs nothing here, so an untrusted ancestor
	 * fails the argument outright rather than being reported and left. */
	if (hook_dir_arg->count > 0) {
		std::error_code hook_ec;
		const fs::path requested = fetch_path(hook_dir_arg->sval[0], strlen(hook_dir_arg->sval[0]));
		const fs::path candidate = fs::weakly_canonical(requested, hook_ec).make_preferred();
		const fs::path program_data = programdata_hook_dir().parent_path();
		const fs::path scratch_root = program_data / L"slobs-hook-tests";

		const bool resolvable = !hook_ec && !program_data.empty();
		const bool named_right = resolvable && candidate.filename() == L"obs-studio-hook";
		const bool below_root = resolvable && candidate.has_relative_path() && candidate.parent_path().has_relative_path();
		const bool in_scratch_tree = resolvable && is_inside(candidate, scratch_root);
		const bool ancestors_trusted = resolvable && chain_trust(candidate).ancestors;

		if (!resolvable || !named_right || !below_root || !in_scratch_tree || !ancestors_trusted || is_system_folder(candidate) ||
		    is_system_folder(candidate.parent_path())) {
			log_fatal("Refusing --hook-dir %s: it must be an obs-studio-hook directory under %%ProgramData%%\\slobs-hook-tests, reached only "
				  "through directories Administrators own",
				  candidate.u8string().c_str());
			success = false;
		} else {
			params->hook_dir = candidate;
			log_warn("Graphics hook directory overridden to %s", candidate.u8string().c_str());
		}
	}

	if (restart_arg->count > 0) {
		params->restart_on_fail = true;
	}

	if (!success)
		goto parse_error;

	success = true;

	goto success;

parse_error:
	success = false;

success:
	arg_freetable(arg_table, arg_table_sz);

	return success;
}
