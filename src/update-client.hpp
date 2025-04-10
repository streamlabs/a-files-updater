#pragma once

#include "update-parameters.hpp"

struct client_callbacks {
	virtual void initialize(struct update_client *client) = 0;
	virtual void success() = 0;
	virtual void error(const std::string &error, const std::string &error_type) = 0;
};

/* Sequence of events:
*
* installer_download_start ────┐
* installer_run_file ──────────┘
*         ↓ 
*/
struct install_callbacks {
	virtual void installer_download_start(const std::string &packageName) = 0;
	virtual void installer_download_progress(const double pct) = 0;
	virtual void installer_run_file(const std::string &packageName, const std::string &startParams, const std::string &rawFileBin) = 0;
	virtual void installer_package_failed(const std::string &packageName, const std::string &message) = 0;
};

/*
 * downloader_preparing       ┌────More─files───┐
 *         ↓                  ↓                 ↑
 * downloader_start -> download_file -> download_progress
 *            ┌───────────No─more─files─────────┘
 *            ↓
 * download_worker_finished -> downloader_complete */
struct downloader_callbacks {
	virtual void downloader_preparing(bool connected) = 0;

	virtual void downloader_start(int concurrent_requests, size_t num_files) = 0;

	virtual void download_file(int thread_index, std::string &filename, size_t size) = 0;

	virtual void download_progress(int thread_index, size_t consumed, size_t accum) = 0;

	virtual void download_worker_finished(int thread_index) = 0;
	virtual void downloader_complete(const bool) = 0;
};

/* Sequence of events:
 *                        ┌──More─files──┐
 *                        ↓              ↑
 * updater_start -> update_file -> update_finished ─┐
 * updater_complete<-───────No─more─files───────────┘
 */
struct updater_callbacks {
	virtual void updater_start() = 0;
	virtual void update_file(std::string &filename) = 0;
	virtual void update_finished(std::string &filename) = 0;
	virtual void updater_complete() = 0;
};

/* Sequence of events:
 *
 * pid_start -> pid_waiting_for -> pid_wait_finished -> pid_wait_complete
 */

struct pid_callbacks {
	virtual void pid_start() = 0;
	virtual void pid_waiting_for(uint64_t pid) = 0;
	virtual void pid_wait_finished(uint64_t pid) = 0;
	virtual void pid_wait_complete() = 0;
};

/* Sequence of events:
 *
 * blocker_start -> blocker_waiting_for -> blocker_wait_complete
 */

struct blocker_callbacks {
	virtual void blocker_start() = 0;
	virtual int blocker_waiting_for(const std::wstring &processes_list, bool list_changed) = 0;
	virtual void blocker_wait_complete() = 0;
};

/* Sequence of events:
 *
 * disk_space_check_start -> disk_space_waiting_for -> disk_space_wait_complete
 */

struct disk_space_callbacks {
	virtual void disk_space_check_start() = 0;
	virtual int disk_space_waiting_for(const std::wstring &app_dir, size_t app_dir_free_space, const std::wstring &temp_dir, size_t temp_dir_free_space,
					   bool skip_update) = 0;
	virtual void disk_space_wait_complete() = 0;
};

extern "C" {

struct update_client;

struct update_client *create_update_client(struct update_parameters *);
void destroy_update_client(struct update_client *);

void update_client_set_client_events(struct update_client *, struct client_callbacks *);

void update_client_set_downloader_events(struct update_client *, struct downloader_callbacks *);

void update_client_set_updater_events(struct update_client *, struct updater_callbacks *);

void update_client_set_pid_events(struct update_client *, struct pid_callbacks *);

void update_client_set_blocker_events(struct update_client *, struct blocker_callbacks *);

void update_client_set_disk_space_events(struct update_client *, struct disk_space_callbacks *);

void update_client_set_installer_events(struct update_client *, struct install_callbacks *);

void update_client_start(struct update_client *);
void update_client_flush(struct update_client *);

void register_install_package(struct update_client *client, const std::string &packageName, const std::string &url, const std::string &startParams);
}