#pragma once
#include "update-http-request.hpp"

#include <fstream>
#include "utils.hpp"
#include "checksum-filters.hpp"
#include "update-client.hpp"

/*##############################################
 *#
 *# Data definitions
 *#
 *############################################*/

struct update_file_t {
	fs::path file_path;
	std::ofstream file_stream;
	bio::gzip_decompressor decompress_filter;
	sha256_filter checksum_filter;

	bio::chain<bio::output> output_chain;

	explicit update_file_t(const fs::path &path);
};

struct update_client {
	struct pid;

	template<class Body> using manifest_request = update_http_request<Body, false>;

	template<class Body> using file_request = update_http_request<Body, true>;

	template<class Type> using executor_work_guard = asio::executor_work_guard<Type>;
	using io_context = asio::io_context;
	using work_guard_type = executor_work_guard<io_context::executor_type>;
	using resolver_type = tcp::resolver;

	update_client() = delete;
	update_client(const update_client &) = delete;
	update_client(update_client &&) = delete;
	update_client &operator=(update_client &&) = delete;
	update_client &operator=(const update_client &) = delete;

	explicit update_client(struct update_parameters *params);
	~update_client();

	void set_client_events(client_callbacks *cbs) { client_events = cbs; }

	void set_downloader_events(downloader_callbacks *cbs) { downloader_events = cbs; }

	void set_updater_events(updater_callbacks *cbs) { updater_events = cbs; }

	void set_pid_events(pid_callbacks *cbs) { pid_events = cbs; }

	void set_blocker_events(blocker_callbacks *cbs) { blocker_events = cbs; }

	void set_disk_space_events(disk_space_callbacks *cbs) { disk_space_events = cbs; }

	void set_installer_events(install_callbacks *cbs) { installer_events = cbs; }

	void register_install_package(const std::string &packageName, const std::string &url, const std::string &startParams)
	{
		install_packages[packageName] = {url, startParams};
	}

	void do_stuff();
	void flush();

	/* These two are explicitly initialized in constructor */
	io_context io_ctx;
	update_parameters *params;

	work_guard_type *work_thread_guard{nullptr};
	fs::path new_files_dir;

	client_callbacks *client_events{nullptr};
	downloader_callbacks *downloader_events{nullptr};
	updater_callbacks *updater_events{nullptr};
	pid_callbacks *pid_events{nullptr};
	blocker_callbacks *blocker_events{nullptr};
	disk_space_callbacks *disk_space_events{nullptr};
	install_callbacks *installer_events{nullptr};

	int active_workers{0};
	std::atomic_size_t active_pids{0};
	std::list<update_client::pid *> pids_waiters;

	local_manifest_t local_manifest;
	manifest_map_t manifest;
	std::mutex manifest_mutex;
	manifest_map_t::const_iterator manifest_iterator;

	resolver_type resolver;
	ssl::context ssl_context{ssl::context::method::sslv23_client};

	resolver_type::results_type endpoints;
	std::map<std::string, std::pair<int, int>> endpoint_fails_counts;
	resolver_type::results_type::iterator get_endpoint();
	const std::string get_endpoint_address_string(resolver_type::results_type::iterator &iter);
	void set_endpoint_fail(const std::string &used_cdn_node_address);

	std::vector<std::thread> thread_pool;

	boost::asio::deadline_timer wait_for_blockers;
	bool show_user_blockers_list;
	std::wstring process_list_text;

	enum class blocker_phase { virtualcam, generic };
	blocker_phase current_blocker_phase{blocker_phase::virtualcam};

	bool update_download_aborted = false;
	std::string download_abort_message;
	boost::system::error_code download_abort_error;

	boost::asio::deadline_timer domain_resolve_timeout;
	void check_resolve_timeout_callback_err(const boost::system::error_code &error);
	std::mutex handle_error_mutex;

private:
	// [packageName] = { url, params }
	std::map<std::string, std::pair<std::string, std::string>> install_packages;

public:
	void handle_network_error(const boost::system::error_code &error, const std::string &str);
	void handle_file_download_error(file_request<http::dynamic_body> *request_ctx, const boost::system::error_code &error, const std::string &str);
	void handle_file_download_canceled(file_request<http::dynamic_body> *request_ctx);

	void handle_manifest_download_error(manifest_request<manifest_body> *request_ctx, const boost::system::error_code &error, const std::string &str);
	void handle_manifest_download_canceled(manifest_request<manifest_body> *request_ctx);

	//manifest
	void handle_resolve(const boost::system::error_code &error, resolver_type::results_type results);
	void handle_manifest_result(manifest_request<manifest_body> *request_ctx);
	void process_manifest_results();
	void checkup_files(struct blockers_map_t &blockers, struct blockers_map_t &virtualcam_blockers, int from, int to);
	void checkup_manifest(struct blockers_map_t &blockers, struct blockers_map_t &virtualcam_blockers);

	//files
	void start_downloading_files();
	void handle_file_result(file_request<http::dynamic_body> *request_ctx, update_file_t *file_ctx, int index);
	void next_manifest_entry(int index);
	void install_package(const std::string &packageName, std::string url, const std::string &startParams);
	bool check_disk_space();

	//wait for slobs close
	void handle_pids();
	void handle_pid(const boost::system::error_code &error, int pid_id);

	//update
	void start_file_update();

	void create_work_threads_guards();
	void reset_work_threads_guards();
};
