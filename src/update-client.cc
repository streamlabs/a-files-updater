#include <atomic>
#include <algorithm>
#include <mutex>
#include <thread>
#include <regex>



#include <fmt/format.h>
#include <aclapi.h>

#include <fstream>
#include <iostream>


using std::regex;
using std::cmatch;
using std::regex_search;

const size_t file_buffer_size = 4096;

#include "update-blockers.hpp"

#include "update-client.hpp"
#include "checksum-filters.hpp"
#include "update-parameters.hpp"
#include "logger/log.h"

#include "update-client-internal.hpp"

#include "utils.hpp"
#include "file-updater.h"

/*##############################################
 *#
 *# Class Implementation
 *#
 *############################################*/

void update_client::start_file_update()
{
	log_info("Files downloaded and ready to start update.");

	reset_work_threads_guards();

	FileUpdater updater(params->temp_dir, params->app_dir, new_files_dir, manifest, local_manifest, this);
	bool updated = false;

	try {
		if (updater.backup()) {
			updater.update();

			log_info("Finished updating files without errors.");
			client_events->success();
			updated = true;
		}
	} catch (std::exception &e) {
		log_error("Got error while updating files: %s.", e.what());
	} catch (...) {
		log_error("Got error while updating files.");
	}

	if (!updated) {
		bool reverted = false;
		log_info("Going to revert.");
		try {
			updater.revert();
			reverted = true;
			log_info("Revert completed.");
		} catch (std::exception &e) {
			log_error("Revert failed: %s.", e.what());
		} catch (...) {
			log_error("Revert failed.");
		}

		if (reverted) {
			client_events->error(
				boost::locale::translate("Failed to move files.\nPlease make sure the application files are not in use and try again."),
				"Failed to update");
		} else {
			client_events->error(
				boost::locale::translate(
					"The automatic update failed to perform successfully.\nPlease install the latest version of Streamlabs Desktop from https://streamlabs.com/"),
				"Failed to revert on fail");
		}
	}
}

struct update_client::pid {
	uint64_t id{0};
	asio::windows::object_handle wrapper;

	pid(asio::io_context &ctx, HANDLE hProcess);
	~pid();
};

update_client::pid::pid(asio::io_context &io_ctx, HANDLE hProcess) : wrapper(io_ctx, hProcess) {}

update_client::pid::~pid()
{
	wrapper.cancel();
}

void update_client::handle_pid(const boost::system::error_code &error, int pid_id)
{
	pid_events->pid_wait_finished(pid_id);

	if (--active_pids == 0) {
		pid_events->pid_wait_complete();
		process_manifest_results();
	}
}

void update_client::handle_pids()
{
	active_pids = params->pids.size();

	if (active_pids == 0) {
		process_manifest_results();
	}

	for (auto iter = params->pids.begin(); iter != params->pids.end(); ++iter) {
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, (DWORD)*iter);
		if (hProcess) {
			pid_events->pid_waiting_for(*iter);

			update_client::pid *pid_ctx = new update_client::pid(io_ctx, hProcess);
			// todo have to save them to be able to cancel
			pid_ctx->id = *iter;
			pid_ctx->wrapper.async_wait([this, pid_ctx](auto ec) { this->handle_pid(ec, pid_ctx->id); });

			pids_waiters.push_back(pid_ctx);
		}
	}
}

void update_client::handle_network_error(const boost::system::error_code &error, const std::string &str)
{
	std::lock_guard<std::mutex> lock(handle_error_mutex);

	update_download_aborted = true;

	char error_buf[256]{0};
	std::string error_str = boost::locale::translate(
		"Streamlabs Desktop was unable to download the update and will launch the current version instead.\n\nThe update will try again later. If this issue persists then please download a new installer from www.streamlabs.com");
	snprintf(error_buf, sizeof(error_buf), "%s\0", error_str.c_str());
	client_events->error(error_buf, "Network error");

	snprintf(error_buf, sizeof(error_buf), "%s - %s\0", str.c_str(), error.message().c_str());
	log_error(error_buf);

	reset_work_threads_guards();
}

void update_client::handle_file_download_error(file_request<http::dynamic_body> *request_ctx, const boost::system::error_code &error, const std::string &str)
{
	set_endpoint_fail(request_ctx->used_cdn_node_address);

	if (request_ctx->retries > 5) {
		boost::system::error_code ec = error;
		if (error == boost::asio::error::basic_errors::operation_aborted && request_ctx->deadline_reached) {
			ec = boost::asio::error::basic_errors::timed_out;
		}

		{
			std::lock_guard<std::mutex> lock(handle_error_mutex);
			if (!update_download_aborted) {
				update_download_aborted = true;

				download_abort_message = str;
				download_abort_error = error;
			}
		}

		handle_file_download_canceled(request_ctx);
		return;
	} else {
		auto new_request_ctx = new file_request<http::dynamic_body>{this, request_ctx->target, request_ctx->worker_id};
		new_request_ctx->retries = request_ctx->retries + 1;

		delete request_ctx;

		Sleep(new_request_ctx->retries * 100);

		new_request_ctx->start_connect();
	}
}

void update_client::handle_file_download_canceled(file_request<http::dynamic_body> *request_ctx)
{
	auto index = request_ctx->worker_id;
	delete request_ctx;

	next_manifest_entry(index);
}

void update_client::handle_manifest_download_error(manifest_request<manifest_body> *request_ctx, const boost::system::error_code &error, const std::string &str)
{
	set_endpoint_fail(request_ctx->used_cdn_node_address);

	if (request_ctx->retries > 5) {
		boost::system::error_code ec = error;
		if (error == boost::asio::error::basic_errors::operation_aborted && request_ctx->deadline_reached) {
			ec = boost::asio::error::basic_errors::timed_out;
		}

		{
			std::lock_guard<std::mutex> lock(handle_error_mutex);
			if (!update_download_aborted) {
				update_download_aborted = true;

				download_abort_message = str;
				download_abort_error = error;
			}
		}

		handle_manifest_download_canceled(request_ctx);
		return;
	} else {
		auto new_request_ctx = new manifest_request<manifest_body>{this, request_ctx->target, request_ctx->worker_id};
		new_request_ctx->retries = request_ctx->retries + 1;

		delete request_ctx;

		Sleep(new_request_ctx->retries * 100);

		new_request_ctx->start_connect();
	}
}

void update_client::handle_manifest_download_canceled(manifest_request<manifest_body> *request_ctx)
{
	auto index = request_ctx->worker_id;
	delete request_ctx;

	handle_network_error(download_abort_error, download_abort_message);
}

void update_client::handle_resolve(const boost::system::error_code &error, resolver_type::results_type results)
{
	domain_resolve_timeout.cancel();

	if (error) {
		handle_network_error(error, boost::locale::translate("Failed to connect to update server."));
		return;
	}

	log_info("Successfuly resolved update server domain name. Continue to download update manifest.");
	endpoints = results;

	auto first_ip = endpoints.cbegin();
	while (first_ip != endpoints.cend()) {
		log_info("Resolved cdn node address - %s", get_endpoint_address_string(first_ip).c_str());
		endpoint_fails_counts.emplace(get_endpoint_address_string(first_ip), std::make_pair<int, int>(0, 0));
		first_ip++;
	}

	std::string manifest_target{params->version + ".sha256"};

	auto *request_ctx = new manifest_request<manifest_body>(this, manifest_target, 0);

	request_ctx->start_connect();
}

update_client::update_client(struct update_parameters *params)
	: params(params), wait_for_blockers(io_ctx), show_user_blockers_list(true), active_workers(0), resolver(io_ctx), domain_resolve_timeout(io_ctx)
{
	new_files_dir = params->temp_dir;
	new_files_dir /= "new-files";

	this->ssl_context.set_verify_mode(ssl::verify_none);
	this->ssl_context.set_default_verify_paths();

	fs::create_directories(new_files_dir);

	const unsigned num_workers = std::thread::hardware_concurrency();

	create_work_threads_guards();

	for (unsigned i = 0; i < num_workers; ++i) {
		thread_pool.emplace_back(std::thread([=]() { io_ctx.run(); }));
	}
}

update_client::~update_client()
{
	reset_work_threads_guards();
}

void update_client::create_work_threads_guards()
{
	work_thread_guard = new work_guard_type(asio::make_work_guard(io_ctx));
}

void update_client::reset_work_threads_guards()
{
	if (work_thread_guard == nullptr)
		return;

	work_thread_guard->reset();
	delete work_thread_guard;
	work_thread_guard = nullptr;
}

void update_client::flush()
{
	for (std::thread &thrd : thread_pool) {
		thrd.join();
	}
}

bool update_client::check_disk_space()
{
	size_t MIN_FREE_SPACE = 2*1000000000; //2GB
	std::error_code ec{};
	bool notified = false;

	uintmax_t app_dir_free_space_prev = 0;
	uintmax_t temp_dir_free_space_prev = 0;
	while (true) {
		uintmax_t app_dir_free_space = fs::space(params->app_dir, ec).available;
		uintmax_t temp_dir_free_space = fs::space(params->temp_dir, ec).available;

		if (app_dir_free_space < MIN_FREE_SPACE || temp_dir_free_space < MIN_FREE_SPACE) {
			if (!notified) {
				log_fatal("Not enough free space on disk %zu, %zu", app_dir_free_space, temp_dir_free_space);
				notified = true;
				disk_space_events->disk_space_check_start();
			} else {
				bool skip_update = false;
				if (app_dir_free_space_prev - app_dir_free_space < MIN_FREE_SPACE &&
				    (app_dir_free_space_prev - app_dir_free_space) / static_cast<double>(app_dir_free_space) < 0.01 &&
				    temp_dir_free_space_prev - temp_dir_free_space < MIN_FREE_SPACE &&
				    (temp_dir_free_space_prev - temp_dir_free_space) / static_cast<double>(temp_dir_free_space) < 0.01) {
					skip_update = true;
				} else {
					app_dir_free_space_prev = app_dir_free_space;
					temp_dir_free_space_prev = temp_dir_free_space;
				}

				int command = disk_space_events->disk_space_waiting_for(params->app_dir.c_str(), app_dir_free_space, params->temp_dir.c_str(),
											temp_dir_free_space, skip_update);
				switch (command) {
				case 0:
					break;
				case 1:
					disk_space_events->disk_space_wait_complete();
					return true;
				case 2:
					disk_space_events->disk_space_wait_complete();
					return false;
				};
			}

			std::this_thread::sleep_for(std::chrono::microseconds(300));
		} else {
			if (notified) {
				disk_space_events->disk_space_wait_complete();
			}
			break;
		}
	}
	return true;
}

void update_client::do_stuff()
{
	auto cb = [=](auto e, auto i) { this->handle_resolve(e, i); };

	if (!check_disk_space()) {
		log_fatal("Update canceled during disk space check.");
		client_events->error(boost::locale::translate("Update canceled during disk space check."), "Canceled");
		reset_work_threads_guards();
		return;
	}

	// [packageName] = { url, params }
	for (auto &itr : install_packages)
		install_package(itr.first, itr.second.first, itr.second.second);

	domain_resolve_timeout.expires_from_now(boost::posix_time::seconds(10));
	check_resolve_timeout_callback_err({});

	log_info("Ready to resolve cdn address \"%s\" and \"%s\" ", params->host.authority.c_str(), params->host.scheme.c_str());

	downloader_events->downloader_preparing(false);

	resolver.async_resolve(params->host.authority, params->host.scheme, cb);
}

void update_client::install_package(const std::string &packageName, std::string url, const std::string &startParams)
{
	installer_events->installer_download_start(packageName);

	boost::system::error_code error;
	boost::asio::io_service io_service;

	// Deduce domain from url
	std::string domainName;
	boost::replace_all(url, "https://", "");
	boost::replace_all(url, "http://", "");

	for (size_t itr = 0; itr < url.size(); ++itr) {
		if (url[itr] == '/' || url[itr] == '\\')
			break;

		domainName.push_back(url[itr]);
	}

	// Resolve domain to IP
	tcp::resolver local_resolver(io_service);
	tcp::resolver::iterator endpoint_iterator = local_resolver.resolve(
		tcp::resolver::query{
			domainName,
			"443",
		},
		error);

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(1) " + error.message());
		return;
	}

	// Try connect each endpoint until success
	ssl::stream<tcp::socket> local_ssl_socket(io_ctx, ssl_context);

	do {
		local_ssl_socket.lowest_layer().close();
		local_ssl_socket.lowest_layer().connect(*endpoint_iterator++, error);
	} while (error && endpoint_iterator != tcp::resolver::iterator{});

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(2) " + error.message());
		return;
	}

	// Timeout - Not 3 seconds to get everything, the max duration to go without back/forth activity
	int32_t timeout = 3000;
	::setsockopt(local_ssl_socket.lowest_layer().native_handle(), SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout, sizeof(timeout));
	::setsockopt(local_ssl_socket.lowest_layer().native_handle(), SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout, sizeof(timeout));

	// Set SNI hostname for TLS - required for CloudFlare and other CDNs
	if (!SSL_set_tlsext_host_name(local_ssl_socket.native_handle(), domainName.c_str())) {
		installer_events->installer_package_failed(packageName, "HTTP(2.5) Failed to set SNI hostname");
		return;
	}

	// Handshake
	local_ssl_socket.handshake(ssl::stream_base::handshake_type::client, error);

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(3) " + error.message());
		return;
	}

	// Send the first request
	http::request<http::empty_body> local_request;
	std::string target = url.substr(domainName.length());
	if (target.empty())
		target = "/";

	local_request = {http::verb::get, target, 11};
	local_request.set(http::field::host, domainName);
	local_request.set(http::field::user_agent, "Streamlabs Desktop updater application/1.0," BOOST_BEAST_VERSION_STRING);
	local_request.set(http::field::accept, "*/*");

	http::write(local_ssl_socket, local_request, error);

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(4) " + error.message());
		return;
	}

	// Check that response is OK
	beast::multi_buffer local_response_buf;
	http::response_parser<http::dynamic_body> local_response_parser;
	local_response_parser.body_limit(std::numeric_limits<unsigned long long>::max());
	http::read_header(local_ssl_socket, local_response_buf, local_response_parser, error);

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(5) " + error.message());
		return;
	}

	if (local_response_parser.get().result_int() != 200) {
		installer_events->installer_package_failed(packageName, "HTTP Status Code " + std::to_string(local_response_parser.get().result_int()));
		return;
	}

	size_t content_length = 0;
	try {
		content_length = local_response_parser.content_length().value();
	} catch (...) {
	}

	if (content_length == 0)
		return;

	do {
		try {
			http::read_some(local_ssl_socket, local_response_buf, local_response_parser, error);
		} catch (const boost::system::system_error &ex) {
			installer_events->installer_package_failed(packageName, "HTTP(6) " + ex.code().message());
			return;
		}

		installer_events->installer_download_progress(double(local_response_parser.get().body().size()) / double(content_length));
	} while (!error.failed() && !local_response_parser.is_done());

	if (error.failed()) {
		installer_events->installer_package_failed(packageName, "HTTP(7) " + error.message());
		return;
	}

	try {
		installer_events->installer_run_file(packageName, startParams, beast::buffers_to_string(local_response_parser.get().body().data()));
	} catch (...) {
		// local_response_parser throws
		installer_events->installer_package_failed(packageName, "Unknown Error");
	}
}

void update_client::set_endpoint_fail(const std::string &used_cdn_node_address)
{
	auto counters = endpoint_fails_counts.find(used_cdn_node_address);
	if (counters != endpoint_fails_counts.end()) {
		(*counters).second.first++;
		log_error("CDN node fail: \"%s\". fails: %d , gets: %d", used_cdn_node_address.c_str(), (*counters).second.first, (*counters).second.second);
	} else {
		log_error("CDN node fail: \"%s\". ", used_cdn_node_address.c_str());
	}
}

const std::string update_client::get_endpoint_address_string(resolver_type::results_type::iterator &iter)
{
	std::string ret = "";
	if (iter != endpoints.end()) {
		boost::system::error_code ec;
		ret = (*iter).endpoint().address().to_string(ec);
	}
	return ret;
}

tcp::resolver::results_type::iterator update_client::get_endpoint()
{
	auto iter = endpoints.begin();
	auto ret = endpoints.end();
	int ret_fails = -1;
	int ret_gets = -1;

	while (iter != endpoints.end()) {
		auto counters = endpoint_fails_counts.find(get_endpoint_address_string(iter));
		if (counters != endpoint_fails_counts.end() && (*counters).second.first <= 24) //ignore nodes with count of fails more than limit
		{
			if (ret_fails < 0 || ret_fails > (*counters).second.first ||
			    (ret_fails == (*counters).second.first && ret_gets > (*counters).second.second)) {
				ret = iter;
				ret_fails = (*counters).second.first;
				ret_gets = (*counters).second.second;
			}
		}
		iter++;
	}

	if (ret != endpoints.end()) {
		auto counters = endpoint_fails_counts.find(get_endpoint_address_string(ret));
		if (counters != endpoint_fails_counts.end())
			(*counters).second.second++;
	}

	return ret;
}

void update_client::check_resolve_timeout_callback_err(const boost::system::error_code &error)
{
	if (error) {
		if (error == boost::asio::error::operation_aborted) {
			return;
		} else {
			return;
		}
	}

	if (domain_resolve_timeout.expires_at() <= boost::asio::deadline_timer::traits_type::now()) {
		resolver.cancel();
		log_info("Timeout for cdn resolve triggered.");
		handle_network_error(error, boost::locale::translate("Failed to connect to update server."));
	} else {
		domain_resolve_timeout.async_wait(bind(&update_client::check_resolve_timeout_callback_err, this, std::placeholders::_1));
	}
}

/*##############################################
 *#
 *# Manifest Handlers
 *#
 *############################################*/

void update_client::checkup_files(struct blockers_map_t &blockers, int from, int to)
{
	for (int i = from; i < to; i++) {
		fs::path entry = local_manifest.at(i).first;
		fs::path key_path(fs::relative(entry, params->app_dir));

		fs::path cleaned_file_name = key_path.make_preferred();
		std::string key = cleaned_file_name.u8string();

		std::string checksum;
		bool is_updatable = check_file_updatable(entry, true, blockers);
		if (is_updatable) {
			checksum = calculate_files_checksum_safe(entry);
		}

		{
			std::lock_guard<std::mutex> lock(manifest_mutex);
			auto manifest_iter = manifest.find(key);

			if (manifest_iter == manifest.end()) {
				if (params->enable_removing_old_files) {
					auto entry_update_info = manifest_entry_t(std::string(""));
					entry_update_info.compared_to_local = true;
					entry_update_info.remove_at_update = true;

					if (key.find("Uninstall") == 0 || key.find("installername") == 0) {
						entry_update_info.remove_at_update = false;
						entry_update_info.skip_update = true;
					}

					manifest.emplace(std::make_pair(key, entry_update_info));
				} else {
					std::string lower_key = key;
					std::transform(lower_key.begin(), lower_key.end(), lower_key.begin(), ::tolower);
					bool mark_remove = false;

					if (lower_key.find("resources/app.asar.unpacked/node_modules") == 0) {
						mark_remove = true;
					} else {
						fs::path kpath(key);
						std::string fname = kpath.filename().u8string();
						std::transform(fname.begin(), fname.end(), fname.begin(), ::tolower);
						if (fname == "msvcp140.dll" || fname == "vcruntime140.dll" || fname == "vcruntime140_1.dll") {
							mark_remove = true;
						}
					}

					if (mark_remove) {
						auto entry_update_info = manifest_entry_t(std::string(""));
						entry_update_info.compared_to_local = true;
						entry_update_info.remove_at_update = true;
						manifest.emplace(std::make_pair(key, entry_update_info));
					}
				}

				local_manifest.at(i).second = checksum.empty() ? calculate_files_checksum_safe(entry) : checksum;
				continue;
			}

			if (is_updatable && !manifest_iter->second.compared_to_local) {
				manifest_iter->second.compared_to_local = true;
				local_manifest.at(i).second = checksum;

				if (checksum.compare(manifest_iter->second.hash_sum) == 0) {
					manifest_iter->second.skip_update = true;
					continue;
				}
			}
		}

		if (is_updatable) {
			check_file_updatable(entry, false, blockers);
		}
	}
}

void update_client::checkup_manifest(blockers_map_t &blockers)
{
	int max_threads = std::thread::hardware_concurrency();

	/* Generate the manifest for the current application directory */
	fs::recursive_directory_iterator app_dir_iter(params->app_dir);
	fs::recursive_directory_iterator end_iter{};

	for (; app_dir_iter != end_iter; ++app_dir_iter) {
		fs::path entry = app_dir_iter->path();
		std::error_code ec;

		auto entry_status = fs::status(entry, ec);
		if (ec)
			continue;

		if (fs::is_directory(entry_status))
			continue;

		if (std::find_if(local_manifest.begin(), local_manifest.end(),
				 [&](std::pair<fs::path, std::string> &entry_pair) { return entry_pair.first == entry; }) != local_manifest.end())
			continue;

		local_manifest.emplace_back(entry, std::string(""));
	}

	std::vector<std::thread *> workers;

	if (max_threads > local_manifest.size())
		max_threads = static_cast<int>(local_manifest.size());

	size_t from = 0;
	size_t to = 0;
	for (int i = 0; i < max_threads; i++) {
		if (i + 1 != max_threads)
			to = local_manifest.size() * (i + 1) / max_threads;
		else
			to = local_manifest.size();
		workers.push_back(new std::thread(&update_client::checkup_files, this, std::ref(blockers), static_cast<int>(from), static_cast<int>(to)));
		from = to;
	}

	for (auto worker : workers) {
		if (worker->joinable())
			worker->join();
	}

	return;
}

std::mutex manifest_result_mutex;

void update_client::process_manifest_results()
{
	std::unique_lock<std::mutex> lock(manifest_result_mutex, std::try_to_lock);
	if (!lock.owns_lock()) {
		return;
	}

	wait_for_blockers.cancel();
	wait_for_blockers.expires_from_now(boost::posix_time::pos_infin);

	for (auto pid_context : pids_waiters) {
		delete pid_context;
	}
	pids_waiters.clear();

	try {
		blockers_map_t blockers;
		checkup_manifest(blockers);

		if (blockers.list.size() > 0) {
			std::wstring new_process_list_text;
			for (auto it = blockers.list.begin(); it != blockers.list.end(); it++) {
				//log_debug("Got blocker process info %i %ls", (*it).second.Process.dwProcessId, (*it).second.strAppName);

				new_process_list_text += (*it).second.strAppName;
				new_process_list_text += L" (";
				new_process_list_text += std::to_wstring((*it).second.Process.dwProcessId);
				new_process_list_text += L")";
				new_process_list_text += L"\r\n";
			}

			if (show_user_blockers_list) {
				show_user_blockers_list = false;
				this->blocker_events->blocker_start();
			}

			bool list_changed = process_list_text.compare(new_process_list_text) != 0;

			process_list_text = new_process_list_text;
			int command = this->blocker_events->blocker_waiting_for(process_list_text, list_changed);

			switch (command) {
			case 1:
				log_info("Got kill all command from ui");
				for (auto it = blockers.list.begin(); it != blockers.list.end(); it++) {
					if ((*it).second.Process.dwProcessId != 0) {
						HANDLE explorer = NULL;
						explorer = OpenProcess(PROCESS_TERMINATE, false, (*it).second.Process.dwProcessId);
						if (explorer == NULL) {
							log_error("Cannot open process %i to terminate it with error: %d", (*it).second.Process.dwProcessId,
								  GetLastError());
						} else {
							if (TerminateProcess(explorer, 1)) {
							} else {
								log_error("Failed to terminate process %i with error: %d", (*it).second.Process.dwProcessId,
									  GetLastError());
							}
						}
					}
				}
				break;
			case 2: {
				log_info("Got cancel command from ui on blocker");
				client_events->error(boost::locale::translate("Update was canceled."), "Canceled");
				reset_work_threads_guards();
				return;
			} break;
			};

			wait_for_blockers.expires_from_now(boost::posix_time::seconds(1));

			wait_for_blockers.async_wait(boost::bind(&update_client::process_manifest_results, this));
			return;
		} else {
			this->blocker_events->blocker_wait_complete();
			show_user_blockers_list = true;
			process_list_text = L"";
		}

	} catch (update_exception_blocked &) {
		client_events->error(
			boost::locale::translate(
				"Failed to move files.\nSome files may be blocked by other program. Please restart your PC and try to update again."),
			"File access error");
		return;
	} catch (update_exception_failed &) {
		client_events->error(
			boost::locale::translate(
				"Failed to move files.\nSome files could not be updated. Please download Streamlabs Desktop installer from our site and run full installation."),
			"File access error");
		return;
	} catch (std::exception &) {
		client_events->error(
			boost::locale::translate(
				"Failed to move files.\nSome files could not be updated. Please download Streamlabs Desktop installer from our site and run full installation."),
			"File operation error");
		return;
	} catch (...) {
		client_events->error(
			boost::locale::translate(
				"Failed to move files.\nSome files could not be updated. Please download Streamlabs Desktop installer from our site and run full installation."),
			"File operation error");
		return;
	}

	start_downloading_files();
}

void update_client::start_downloading_files()
{
	int max_threads = 4;

	this->manifest_iterator = this->manifest.cbegin();
	auto to_download = std::count_if(this->manifest.cbegin(), this->manifest.cend(),
					 [](const auto &entry) { return !entry.second.remove_at_update && !entry.second.skip_update; });
	log_info("Manifest cleaned and ready to download files. Files to download %d", to_download);
	this->downloader_events->downloader_preparing(true);
	this->downloader_events->downloader_start(max_threads, to_download);

	/* To make sure we only have `max` number of
	 * of requests at any given time, we hold the
	 * mutex for the duration of this for loop.
	 * Otherwise a request could finish too fast
	 * and we would have `n` extra requests at once
	 * where n is the request that finished too fast. */
	std::unique_lock<std::mutex> manifest_lock(this->manifest_mutex);

	for (int i = 0; this->manifest_iterator != this->manifest.end() && i < max_threads; ++this->manifest_iterator) {
		if ((*this->manifest_iterator).second.remove_at_update || (*this->manifest_iterator).second.skip_update)
			continue;

		++this->active_workers;

		auto request_ctx = new file_request<http::dynamic_body>{this, fixup_uri((*this->manifest_iterator).first) + ".gz", i};

		request_ctx->start_connect();

		++i;
	}

	if (this->active_workers == 0) {
		manifest_lock.unlock();
		this->start_file_update();
	}
}

template<class ConstBuffer> static size_t handle_manifest_read_buffer(manifest_map_t &map, const ConstBuffer &buffer)
{
	/* TODO: Hardcoded for SHA-256 checksums. */
	static const regex manifest_regex("([A-Fa-f0-9]{64}) ([^\r\n]+)\r?\n");

	size_t accum = 0;

	for (;;) {
		const char *buf;
		std::string checksum;
		std::string file;
		cmatch matches;
		size_t buf_size = buffer.size() - accum;

		/* Technically, this for loop will
		 * always iterate once and then hit this
		 * the second time around. */
		if (buf_size == 0)
			break;

		buf = (const char *)buffer.data() + accum;

		bool regex_result = regex_search(&buf[0], &buf[buf_size], matches, manifest_regex);

		if (!regex_result) {
			/* FIXME TODO
			 * This should never ever happen the way
			 * the code is currently formatted. If
			 * this happens, either the buffers are
			 * given incorrectly or the manifest is
			 * malformed. This should be a fatal error.
			 * That said, if we ever go back to dynamic
			 * buffers, we should instead figure out
			 * a way to store the section of the previous
			 * buffer that we weren't able to fully parse.
			 * Right now, we assume a singular contiguous
			 * buffer (usually around 20kB total for a
			 * 1000+ line manifest). */
			break;
		}

		file.assign(matches[2].first, matches[2].length());
		checksum.assign(matches[1].first, matches[1].length());
		map.emplace(std::make_pair(file, manifest_entry_t(checksum)));

		accum += matches.length();
	}

	return accum;
}

void update_client::handle_manifest_result(manifest_request<manifest_body> *request_ctx)
{
	delete request_ctx;

	log_info("Successfuly downloaded manifest. It has info about %d files", manifest.size());

	this->downloader_events->downloader_preparing(true);

	wait_for_blockers.expires_from_now(boost::posix_time::seconds(3));
	wait_for_blockers.async_wait(boost::bind(&update_client::process_manifest_results, this));

	/* let time for Streamlabs Desktop process to quit and make files available for update */
	handle_pids();
};

/*
 *##############################################
 *#
 *# File Handlers
 *#
 *############################################*/

static constexpr std::ios_base::openmode file_flags = std::ios_base::out | std::ios_base::binary | std::ios_base::trunc;

update_file_t::update_file_t(const fs::path &file_path) : file_path(file_path), file_stream(file_path, file_flags)
{
	if (this->file_stream.bad()) {
		log_info("Failed to create file output stream\n");
		/* TODO File failed to open here */
	}

	this->output_chain.push(boost::reference_wrapper<bio::gzip_decompressor>(this->decompress_filter), file_buffer_size);

	this->output_chain.push(boost::reference_wrapper<sha256_filter>(this->checksum_filter), file_buffer_size);

	this->output_chain.push(boost::reference_wrapper<std::ofstream>(this->file_stream), file_buffer_size);
}

void update_client::handle_file_result(file_request<http::dynamic_body> *request_ctx, update_file_t *file_ctx, int index)
{
	auto &filter = file_ctx->checksum_filter;

	try {
		file_ctx->output_chain.reset();

		std::ostringstream hex_digest;

		hex_digest << std::nouppercase << std::setfill('0') << std::hex;

		for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i) {
			hex_digest << std::setw(2) << static_cast<unsigned int>(filter.digest[i]);
		}
	} catch (...) {
	}

	delete file_ctx;
	delete request_ctx;

	next_manifest_entry(index);
}

void update_client::next_manifest_entry(int index)
{
	std::unique_lock<std::mutex> manifest_lock(this->manifest_mutex);

	while (true) {
		if (this->manifest_iterator == this->manifest.end() || update_download_aborted) {
			--this->active_workers;

			this->downloader_events->download_worker_finished(index);

			if (this->active_workers == 0) {
				this->downloader_events->downloader_complete(!update_download_aborted);
				if (update_download_aborted) {
					handle_network_error(download_abort_error, download_abort_message);
				} else {
					this->start_file_update();
				}
			}

			return;
		} else {
			auto entry = *this->manifest_iterator;

			++this->manifest_iterator;

			if (entry.second.remove_at_update || entry.second.skip_update) {
				continue;
			} else {
				/* Only hold the lock until we can get a reference to
				* the entry. We are guaranteed that the entry and
				* manifest are no longer modified at this point so
				* the reference will stay valid */
				manifest_lock.unlock();

				auto request_ctx = new file_request<http::dynamic_body>{this, fixup_uri(entry.first) + ".gz", index};

				request_ctx->start_connect();
			}
		}
		break;
	}
}

/*##############################################
 *#
 *# Template instances 
 *#
 *############################################*/

template<> void update_http_request<manifest_body, false>::handle_download_canceled()
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_manifest_download_canceled, client_ctx, this));
}

template<> void update_http_request<http::dynamic_body, true>::handle_download_canceled()
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_file_download_canceled, client_ctx, this));
}

template<> void update_http_request<manifest_body, false>::handle_download_error(const boost::system::error_code &error, const std::string &str)
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_manifest_download_error, client_ctx, this, error, str));
}

template<> void update_http_request<http::dynamic_body, true>::handle_download_error(const boost::system::error_code &error, const std::string &str)
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_file_download_error, client_ctx, this, error, str));
}

template<> void update_http_request<manifest_body, false>::handle_result(update_file_t *file_ctx)
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_manifest_result, client_ctx, this));
}

template<> void update_http_request<http::dynamic_body, true>::handle_result(update_file_t *file_ctx)
{
	client_ctx->io_ctx.post(boost::bind(&update_client::handle_file_result, client_ctx, this, file_ctx, this->worker_id));
}

template<> void update_http_request<http::dynamic_body, true>::start_reading()
{
	client_ctx->downloader_events->download_file(worker_id, target, content_length);

	fs::path file_path = prepare_file_path(client_ctx->new_files_dir, target);

	if (file_path.empty()) {
		std::string msg = std::string("Failed to create file path for: ") + target;
		handle_download_error({}, msg);
		return;
	}

	auto file_ctx = new update_file_t(file_path);

	auto read_handler = [this, file_ctx](auto i, auto e) { this->handle_response_body(i, e, file_ctx); };

	switch_deadline_on();

	http::async_read_some(ssl_socket, response_buf, response_parser, read_handler);
}

template<> void update_http_request<manifest_body, false>::start_reading()
{
	auto read_handler = [this](auto i, auto e) { this->handle_response_body(i, e, nullptr); };

	switch_deadline_on();

	http::async_read(ssl_socket, response_buf, response_parser, read_handler);
}

template<>
void update_http_request<http::dynamic_body, true>::handle_response_body(boost::system::error_code &error, size_t bytes_read, update_file_t *file_ctx)
{
	if (handle_callback_precheck(error, "get response body")) {
		delete file_ctx;
		return;
	}

	size_t consumed = 0;
	try {
		auto &body = response_parser.get().body();

		for (auto iter = asio::buffer_sequence_begin(body.data()); iter != asio::buffer_sequence_end(body.data()); ++iter) {
			if ((*iter).size() > asio::buffer_size(body.data())) {
				delete file_ctx;
				std::string msg = std::string("Failed to recieve file body correctly. for : ") + target;
				handle_download_error(boost::asio::error::basic_errors::connection_aborted, msg);
				return;
			}
			file_ctx->output_chain.write((const char *)(*iter).data(), (*iter).size());
		}

		consumed = asio::buffer_size(body.data());
		body.consume(consumed);
		download_accum += consumed;
	} catch (...) {
		delete file_ctx;

		std::string msg = std::string("Failed to recieve file body correctly. for : ") + target;

		handle_download_error(boost::asio::error::basic_errors::connection_aborted, msg);

		return;
	}

	client_ctx->downloader_events->download_progress(worker_id, consumed, download_accum);

	if (response_parser.is_done()) {
		handle_result(file_ctx);
		return;
	}

	auto read_handler = [this, file_ctx](auto i, auto e) { this->handle_response_body(i, e, file_ctx); };

	switch_deadline_on();

	http::async_read_some(ssl_socket, response_buf, response_parser, read_handler);
}

template<> void update_http_request<manifest_body, false>::handle_response_body(boost::system::error_code &error, size_t bytes_read, update_file_t *file_ctx)
{
	if (handle_callback_precheck(error, "get response body")) {
		return;
	}

	auto &buffer = response_parser.get().body();

	handle_manifest_read_buffer(client_ctx->manifest, buffer.data());

	handle_result(nullptr);
}

/*##############################################
 *#
 *# C interface functionality
 *#
 *############################################*/
extern "C" {

struct update_client *create_update_client(struct update_parameters *params)
{
	update_client *client = new update_client(params);

	return client;
}

void destroy_update_client(struct update_client *client)
{
	delete client;
}

void update_client_set_client_events(struct update_client *client, struct client_callbacks *events)
{
	client->set_client_events(events);
}

void update_client_set_downloader_events(struct update_client *client, struct downloader_callbacks *events)
{
	client->set_downloader_events(events);
}

void update_client_set_updater_events(struct update_client *client, struct updater_callbacks *events)
{
	client->set_updater_events(events);
}

void update_client_set_pid_events(struct update_client *client, struct pid_callbacks *events)
{
	client->set_pid_events(events);
}

void update_client_set_blocker_events(struct update_client *client, struct blocker_callbacks *events)
{
	client->set_blocker_events(events);
}

void update_client_set_disk_space_events(struct update_client *client, struct disk_space_callbacks *events)
{
	client->set_disk_space_events(events);
}

void update_client_set_installer_events(struct update_client *client, struct install_callbacks *events)
{
	client->set_installer_events(events);
}

void register_install_package(struct update_client *client, const std::string &packageName, const std::string &url, const std::string &startParams)
{
	client->register_install_package(packageName, url, startParams);
}

void update_client_start(struct update_client *client)
{
	client->do_stuff();
}

void update_client_flush(struct update_client *client)
{
	client->flush();
}
}