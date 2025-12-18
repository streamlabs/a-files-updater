#include <chrono>

#include <windows.h>
#include <CommCtrl.h>
#include <functional>
#include <numeric>

#include <fmt/format.h>

#include "cli-parser.hpp"
#include "update-client.hpp"
#include "logger/log.h"
#include "crash-reporter.hpp"
#include "utils.hpp"
#include <atomic>
#include <thread>
#include <fstream>

#include <boost/algorithm/string.hpp>
#include <boost/locale.hpp>

#include <json.hpp>

namespace fs = std::filesystem;
namespace chrono = std::chrono;

using chrono::high_resolution_clock;
using chrono::duration_cast;

struct update_parameters params;

/* Some basic constants that are adjustable at compile time */
const double average_bw_time_span = 250;
const int max_bandwidth_in_average = 8;

const int ui_padding = 10;
const int ui_basic_height = 40;
const int ui_min_width = 400;

const COLORREF dlg_bg_color = RGB(23, 36, 45);
const COLORREF edit_bg_color = RGB(12, 17, 22);
const COLORREF gray_btn_color = RGB(100, 100, 110);
const COLORREF kev_color = RGB(128, 245, 210);
const COLORREF disabled_gray_color = RGB(175, 175, 190);
const COLORREF white_color = RGB(255, 255, 255);
const COLORREF black_color = RGB(0, 0, 0);

bool update_completed = false;

std::string getDefaultErrorMessage()
{
	return boost::locale::translate(
		"The automatic update failed to perform successfully.\nPlease install the latest version of Streamlabs Desktop from https://streamlabs.com/");
}

void ShowError(const std::string &message)
{
	std::wstring wmessage = ConvertToUtf16WS(message);
	if (wmessage.size()) {
		if (params.interactive) {
			MessageBoxW(NULL, wmessage.c_str(), TEXT("Error while updating"), MB_ICONEXCLAMATION | MB_OK);
		}
	}
}

void ShowInfo(const std::string &message)
{
	std::wstring wmessage = ConvertToUtf16WS(message);
	if (wmessage.size()) {
		if (params.interactive) {
			MessageBoxW(NULL, wmessage.c_str(), TEXT("Info"), MB_ICONINFORMATION | MB_OK);
		}
	}
}

static inline void trim_trailing_nuls(std::wstring &s)
{
	while (!s.empty() && s.back() == L'\0')
		s.pop_back();
}

struct bandwidth_chunk {
	high_resolution_clock::time_point time_point;
	size_t chunk_size;
};

static LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);

static LRESULT CALLBACK ProgressLabelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
static LRESULT CALLBACK BlockersListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);

static BOOL HasInstalled_VC_redistx64();

struct callbacks_impl : public install_callbacks,
			client_callbacks,
			downloader_callbacks,
			updater_callbacks,
			pid_callbacks,
			blocker_callbacks,
			disk_space_callbacks {
	int screen_width{0};
	int screen_height{0};
	int width{500};
	int height{ui_basic_height * 4 + ui_padding * 2};

	HWND frame{NULL}; /* Toplevel window */
	HWND progress_worker{NULL};
	HWND progress_label{NULL};
	HWND blockers_list{NULL};
	HWND kill_button{NULL};
	HWND continue_button{NULL};
	HWND cancel_button{NULL};
	std::wstring update_btn_label;
	std::wstring remind_btn_label;
	std::wstring continue_label;
	std::wstring cancel_label;
	std::wstring stop_all_label;

	HBRUSH edit_bg_brush{NULL};
	HBRUSH dlg_bg_brush{NULL};
	HBRUSH gray_btn_brush{NULL};
	HBRUSH kev_btn_brush{NULL};

	HFONT main_font{NULL};
	RECT progress_label_rect{0};
	RECT blockers_list_rect{0};

	std::atomic_uint files_done{0};
	std::vector<size_t> file_sizes{0};
	size_t num_files{0};
	int num_workers{0};
	int package_dl_pct100{0};
	high_resolution_clock::time_point start_time;
	size_t total_consumed{0};
	size_t total_consumed_last_tick{0};
	std::list<double> last_bandwidths;
	std::atomic<double> last_calculated_bandwidth{0.0};
	std::string error_buf{};
	bool should_start{false};
	bool should_cancel{false};
	bool should_kill_blockers{false};
	bool should_continue{false};
	bool notify_restart{false};
	bool finished_downloading{false};
	bool prompting{false};
	LPCWSTR label_format{L"Downloading {} of {} - {:.2f} MB/s"};

	callbacks_impl(const callbacks_impl &) = delete;
	callbacks_impl(const callbacks_impl &&) = delete;
	callbacks_impl &operator=(const callbacks_impl &) = delete;
	callbacks_impl &operator=(callbacks_impl &&) = delete;

	explicit callbacks_impl(HINSTANCE hInstance, int nCmdShow);
	~callbacks_impl();

	void setupFont();
	void repostionUI();

	void initialize(struct update_client *client) final;
	void success() final;
	void error(const std::string &error, const std::string &error_type) final;

	void downloader_preparing(bool connected) final;
	void downloader_start(int num_threads, size_t num_files_) final;
	void download_file(int thread_index, std::string &relative_path, size_t size);
	void download_progress(int thread_index, size_t consumed, size_t accum) final;
	void download_worker_finished(int thread_index) final {}
	void downloader_complete(const bool success) final;
	static void bandwidth_tick(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime);

	void installer_download_start(const std::string &packageName) final;
	void installer_download_progress(const double pct) final;
	void installer_run_file(const std::string &packageName, const std::string &startParams, const std::string &rawFileBin) final;
	void installer_package_failed(const std::string &packageName, const std::string &message) final;

	void pid_start() final {}
	void pid_waiting_for(uint64_t pid) final {}
	void pid_wait_finished(uint64_t pid) final {}
	void pid_wait_complete() final {}

	void blocker_start() final;
	int blocker_waiting_for(const std::wstring &processes_list, bool list_changed) final;
	void blocker_wait_complete() final;

	void disk_space_check_start() final;
	int disk_space_waiting_for(const std::wstring &app_dir, size_t app_dir_free_space, const std::wstring &temp_dir, size_t temp_dir_free_space,
				   bool skip_update) final;
	void disk_space_wait_complete() final;

	void updater_start() final;
	void update_file(std::string &filename) final {}
	void update_finished(std::string &filename) final {}
	void updater_complete() final {}

	bool prompt_user(const char *pVersion, const char *pDetails);
	bool prompt_file_removal();

private:
	struct DialogState {
		bool should_accept = false;
		std::wstring title;
		std::wstring content;
		std::wstring accept_label;
		std::wstring decline_label;
		bool show_decline_button = true;
	};

	bool show_dialog(const DialogState &state);
	void calculate_text_dimensions(const std::wstring &title, const std::wstring &content, RECT &title_rect, RECT &content_rect);
	void show_ui_elements(bool show_buttons = true, bool show_kill = false);
	void hide_ui_elements();
	void reset_ui_labels();
	bool run_message_loop();
	std::wstring format_update_details(const std::string &detailsStr);
};

callbacks_impl::callbacks_impl(HINSTANCE hInstance, int nCmdShow)
{
	BOOL success = false;
	WNDCLASSEX wc;
	RECT rcParent;

	HICON app_icon = LoadIcon(GetModuleHandle(NULL), TEXT("AppIcon"));

	wc.cbSize = sizeof(WNDCLASSEX);
	wc.style = CS_NOCLOSE;
	wc.lpfnWndProc = FrameWndProc;
	wc.cbClsExtra = 0;
	wc.cbWndExtra = 0;
	wc.hInstance = hInstance;
	wc.hIcon = app_icon;
	wc.hCursor = LoadCursor(NULL, IDC_ARROW);
	wc.hbrBackground = CreateSolidBrush(dlg_bg_color);
	wc.lpszMenuName = NULL;
	wc.lpszClassName = TEXT("UpdaterFrame");
	wc.hIconSm = app_icon;

	if (!RegisterClassEx(&wc)) {
		ShowError(getDefaultErrorMessage());
		LogLastError(L"RegisterClassEx");

		throw std::runtime_error("window registration failed");
	}

	kev_btn_brush = CreateSolidBrush(kev_color);
	gray_btn_brush = CreateSolidBrush(gray_btn_color);
	dlg_bg_brush = CreateSolidBrush(dlg_bg_color);
	edit_bg_brush = CreateSolidBrush(edit_bg_color);

	/* We only care about the main display */
	screen_width = GetSystemMetrics(SM_CXSCREEN);
	screen_height = GetSystemMetrics(SM_CYSCREEN);

	/* FIXME: This feels a little dirty */
	auto do_fail = [this](const std::string &user_msg, LPCWSTR context_msg) {
		if (this->frame)
			DestroyWindow(this->frame);
		ShowError(user_msg);
		LogLastError(context_msg);
		throw std::runtime_error("");
	};

	frame = CreateWindowEx(WS_EX_CLIENTEDGE, TEXT("UpdaterFrame"), TEXT("Streamlabs Desktop Updater"),
			       WS_OVERLAPPED | WS_MINIMIZEBOX | WS_SYSMENU | WS_CLIPCHILDREN, (screen_width - width) / 2, (screen_height - height) / 2, width,
			       height, NULL, NULL, hInstance, NULL);

	SetWindowLongPtr(frame, GWLP_USERDATA, (LONG_PTR)this);

	if (!frame) {
		do_fail(getDefaultErrorMessage(), L"CreateWindowEx");
	}

	GetClientRect(frame, &rcParent);

	int x_pos = ui_padding;
	int y_size = ui_basic_height;
	int x_size = (rcParent.right - rcParent.left) - (x_pos * 2);
	int y_pos = ((rcParent.bottom - rcParent.top) / 2) - (y_size / 2);

	progress_worker =
		CreateWindow(PROGRESS_CLASS, TEXT("ProgressWorker"), WS_CHILD | WS_VISIBLE | PBS_SMOOTH, x_pos, y_pos, x_size, y_size, frame, NULL, NULL, NULL);

	if (!progress_worker) {
		do_fail(getDefaultErrorMessage(), L"CreateWindow");
	}

	std::wstring checking_packages_label = ConvertToUtf16WS(boost::locale::translate("Checking packages..."));
	std::wstring blockers_list_label = ConvertToUtf16WS(boost::locale::translate("Blockers list"));
	stop_all_label = ConvertToUtf16WS(boost::locale::translate("Stop all"));
	continue_label = ConvertToUtf16WS(boost::locale::translate("Continue"));
	cancel_label = ConvertToUtf16WS(boost::locale::translate("Cancel"));
	update_btn_label = ConvertToUtf16WS(boost::locale::translate("Upgrade"));
	remind_btn_label = ConvertToUtf16WS(boost::locale::translate("Later"));

	progress_label = CreateWindow(WC_STATIC, checking_packages_label.c_str(), WS_CHILD | WS_VISIBLE, x_pos, ui_padding, x_size, ui_basic_height, frame,
				      NULL, NULL, NULL);

	if (!progress_label) {
		do_fail(getDefaultErrorMessage(), L"CreateWindow");
	}

	success = SetWindowSubclass(progress_label, ProgressLabelWndProc, CLS_PROGRESS_LABEL, (DWORD_PTR)this);

	if (!success) {
		do_fail(getDefaultErrorMessage(), L"SetWindowSubclass");
	}

	blockers_list = CreateWindow(WC_EDIT, blockers_list_label.c_str(),
				     WS_CHILD | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL | WS_BORDER | ES_READONLY, x_pos, y_pos,
				     x_size, ui_basic_height * 2, frame, NULL, NULL, NULL);

	success = SetWindowSubclass(blockers_list, BlockersListWndProc, CLS_BLOCKERS_LIST, (DWORD_PTR)this);

	if (!success) {
		do_fail(getDefaultErrorMessage(), L"SetWindowSubclass");
	}

	kill_button = CreateWindow(WC_BUTTON, stop_all_label.c_str(), WS_TABSTOP | WS_CHILD | BS_DEFPUSHBUTTON | BS_OWNERDRAW, x_size + ui_padding - 100,
				   rcParent.bottom - rcParent.top, 100, ui_basic_height, frame, NULL, NULL, NULL);

	continue_button = CreateWindow(WC_BUTTON, continue_label.c_str(), WS_TABSTOP | WS_CHILD | BS_DEFPUSHBUTTON | BS_OWNERDRAW, x_size + ui_padding - 100,
				       rcParent.bottom - rcParent.top, 100, ui_basic_height, frame, NULL, NULL, NULL);

	cancel_button = CreateWindow(WC_BUTTON, cancel_label.c_str(), WS_TABSTOP | WS_CHILD | BS_DEFPUSHBUTTON | BS_OWNERDRAW,
				     x_size + ui_padding - 100 - ui_padding - 100, rcParent.bottom - rcParent.top, 100, ui_basic_height, frame, NULL, NULL,
				     NULL);

	//make the buttons rounded - after SetWindowRgn, window owns HRGNs and will destroy them
	RECT btnRect = {0};
	int cRounding = 4;
	GetClientRect(kill_button, &btnRect);
	HRGN rgn = CreateRoundRectRgn(0, 0, btnRect.right, btnRect.bottom, cRounding, cRounding);
	SetWindowRgn(kill_button, rgn, true);
	GetClientRect(continue_button, &btnRect);
	rgn = CreateRoundRectRgn(0, 0, btnRect.right, btnRect.bottom, cRounding, cRounding);
	SetWindowRgn(continue_button, rgn, true);
	GetClientRect(cancel_button, &btnRect);
	rgn = CreateRoundRectRgn(0, 0, btnRect.right, btnRect.bottom, cRounding, cRounding);
	SetWindowRgn(cancel_button, rgn, true);

	SendMessage(progress_worker, PBM_SETBARCOLOR, 0, kev_color);
	SendMessage(progress_worker, PBM_SETRANGE32, 0, INT_MAX);

	setupFont();
}

void callbacks_impl::setupFont()
{
	LOGFONT lf = {0};
	lf.lfHeight = 22;
	lf.lfWidth = 0;
	lf.lfEscapement = 0;
	lf.lfOrientation = 0;
	lf.lfWeight = FW_DONTCARE;
	lf.lfItalic = FALSE;
	lf.lfUnderline = FALSE;
	lf.lfStrikeOut = FALSE;
	lf.lfCharSet = DEFAULT_CHARSET;
	lf.lfOutPrecision = OUT_DEFAULT_PRECIS;
	lf.lfClipPrecision = CLIP_DEFAULT_PRECIS;
	lf.lfQuality = CLEARTYPE_QUALITY;
	lf.lfPitchAndFamily = DEFAULT_PITCH | FF_SWISS;
	lstrcpy(lf.lfFaceName, L"SEGOE UI");

	main_font = CreateFontIndirect(&lf);

	SendMessage(frame, WM_SETFONT, WPARAM(main_font), TRUE);
	SendMessage(progress_label, WM_SETFONT, WPARAM(main_font), TRUE);
	SendMessage(kill_button, WM_SETFONT, WPARAM(main_font), TRUE);
	SendMessage(continue_button, WM_SETFONT, WPARAM(main_font), TRUE);
	SendMessage(cancel_button, WM_SETFONT, WPARAM(main_font), TRUE);
	SendMessage(blockers_list, WM_SETFONT, WPARAM(main_font), TRUE);
}

void callbacks_impl::repostionUI()
{
	int frame_h = ui_padding;
	int main_w = progress_label_rect.right;

	if (main_w < ui_min_width)
		main_w = ui_min_width;

	SetWindowPos(progress_label, 0, ui_padding, ui_padding, main_w, progress_label_rect.bottom, SWP_ASYNCWINDOWPOS);

	int frame_w = main_w + ui_padding * 2;
	frame_h += progress_label_rect.bottom + ui_padding;

	if (IsWindowVisible(blockers_list)) {
		//if blockers_list has so much text that it exceeds screen height, readjust so it's not more than 75% of screen height
		if ((frame_h + blockers_list_rect.bottom) > screen_height) {
			blockers_list_rect.bottom -= ((frame_h + blockers_list_rect.bottom) - static_cast<int>(ceil(screen_height * 0.75)));
		}
		//if right is larger than 75% width (75% to make it look better than using full size), add some height so aren't scrolling 1 line at a time
		if (blockers_list_rect.right > (main_w * .75)) {
			blockers_list_rect.bottom += ui_padding * 5;
		}
		SetWindowPos(blockers_list, 0, ui_padding, frame_h, main_w, blockers_list_rect.bottom, SWP_ASYNCWINDOWPOS);
		frame_h += blockers_list_rect.bottom + ui_padding;
	}

	if (IsWindowVisible(progress_worker)) {
		SetWindowPos(progress_worker, 0, ui_padding, frame_h, main_w, ui_basic_height, SWP_ASYNCWINDOWPOS);
		frame_h += ui_basic_height + ui_padding;
	}

	if (IsWindowVisible(continue_button) || IsWindowVisible(kill_button) || IsWindowVisible(cancel_button)) {
		int button_left = main_w + ui_padding - 100;
		SetWindowPos(continue_button, 0, button_left, frame_h, 0, 0, SWP_ASYNCWINDOWPOS | SWP_NOSIZE);
		SetWindowPos(kill_button, 0, button_left, frame_h, 0, 0, SWP_ASYNCWINDOWPOS | SWP_NOSIZE);
		SetWindowPos(cancel_button, 0, button_left - 100 - ui_padding, frame_h, 0, 0, SWP_ASYNCWINDOWPOS | SWP_NOSIZE);
		frame_h += ui_basic_height + ui_padding;
	} else {
		frame_h += ui_basic_height;
	}

	RECT winRect = {0};
	RECT clientRect = {0};
	GetWindowRect(frame, &winRect);
	GetClientRect(frame, &clientRect);

	frame_h += (winRect.bottom - winRect.top) - clientRect.bottom;
	frame_w += (winRect.right - winRect.left) - clientRect.right;
	//adjust window to the middle of the screen
	SetWindowPos(frame, 0, (screen_width - frame_w) / 2, (screen_height - frame_h) / 2, frame_w, frame_h, SWP_NOREPOSITION | SWP_ASYNCWINDOWPOS);
}

callbacks_impl::~callbacks_impl()
{
	if (edit_bg_brush != NULL) {
		DeleteObject(edit_bg_brush);
	}
	if (dlg_bg_brush != NULL) {
		DeleteObject(dlg_bg_brush);
	}
	if (gray_btn_brush != NULL) {
		DeleteObject(gray_btn_brush);
	}
	if (kev_btn_brush != NULL) {
		DeleteObject(kev_btn_brush);
	}
}

void callbacks_impl::initialize(struct update_client *client)
{
	ShowWindow(frame, SW_SHOWNORMAL);

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	std::wstring label(fmt::format(label_format, 9999, 9999, 100.00));

	RECT progress_label_rect = {0};
	DrawText(hdc, label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);
	progress_label_rect.right -= progress_label_rect.left;

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	repostionUI();

	UpdateWindow(frame);

	// ; todo, maybe more msi/exe packages?
	if (!HasInstalled_VC_redistx64())
		register_install_package(client, "Visual C++ Redistributable", "https://slobs-cdn.streamlabs.com/VC_redist.x64.exe", "/passive /norestart");
}

void callbacks_impl::success()
{
	should_start = true;
	PostMessage(frame, CUSTOM_CLOSE_MSG, NULL, NULL);
}

void callbacks_impl::error(const std::string &error, const std::string &error_type)
{
	this->error_buf = error;
	save_exit_error(error_type);

	PostMessage(frame, CUSTOM_ERROR_MSG, NULL, NULL);
}

void callbacks_impl::downloader_preparing(bool connected)
{
	LONG_PTR data = GetWindowLongPtr(frame, GWLP_USERDATA);
	auto ctx = reinterpret_cast<callbacks_impl *>(data);

	if (ctx->prompting) {
		return;
	}

	std::wstring checking_label;
	if (connected) {
		checking_label = ConvertToUtf16WS(boost::locale::translate("Checking local files..."));
	} else {
		checking_label = ConvertToUtf16WS(boost::locale::translate("Connecting to server..."));
	}
	trim_trailing_nuls(checking_label);

	ShowWindow(ctx->continue_button, SW_HIDE);
	ShowWindow(ctx->cancel_button, SW_HIDE);
	ShowWindow(ctx->kill_button, SW_HIDE);

	EnableWindow(ctx->continue_button, TRUE);
	EnableWindow(ctx->cancel_button, TRUE);
	EnableWindow(ctx->kill_button, TRUE);

	ctx->update_btn_label = ConvertToUtf16WS(boost::locale::translate("Upgrade"));
	ctx->remind_btn_label = ConvertToUtf16WS(boost::locale::translate("Later"));
	trim_trailing_nuls(ctx->update_btn_label);
	trim_trailing_nuls(ctx->remind_btn_label);

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	DrawTextW(hdc, checking_label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);
	progress_label_rect.right -= progress_label_rect.left;

	std::wstring label(fmt::format(ctx->label_format, 9999, 9999, 100.00));

	RECT progress_with_numbers = {0};
	DrawTextW(hdc, label.c_str(), -1, &progress_with_numbers, DT_CALCRECT | DT_NOCLIP);
	progress_with_numbers.right -= progress_with_numbers.left;

	if (progress_label_rect.right < progress_with_numbers.right)
		progress_label_rect = progress_with_numbers;

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	ShowWindow(ctx->blockers_list, SW_HIDE);
	ShowWindow(ctx->progress_label, SW_SHOW);
	ShowWindow(ctx->progress_worker, SW_SHOW);

	repostionUI();
	SetWindowTextW(ctx->progress_label, checking_label.c_str());
}

void callbacks_impl::downloader_start(int num_threads, size_t num_files_)
{
	file_sizes.resize(num_threads, 0);
	this->num_files = num_files_;
	start_time = high_resolution_clock::now();

	SetTimer(frame, 1, static_cast<unsigned int>(average_bw_time_span), &bandwidth_tick);
}

void callbacks_impl::download_file(int thread_index, std::string &relative_path, size_t size)
{
	/* Our specific UI doesn't care when we start, we only
	 * care when we're finished. A more technical UI could show
	 * what each thread is doing if they so wanted. */
	file_sizes[thread_index] = size;
}

void callbacks_impl::bandwidth_tick(HWND hwnd, UINT uMsg, UINT_PTR idEvent, DWORD dwTime)
{
	LONG_PTR data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
	auto ctx = reinterpret_cast<callbacks_impl *>(data);

	/* Compare current total to last previous total,
	 * then divide by timeout time */
	double bandwidth = (double)(ctx->total_consumed - ctx->total_consumed_last_tick);
	ctx->total_consumed_last_tick = ctx->total_consumed;

	ctx->last_bandwidths.push_back(bandwidth);
	while (ctx->last_bandwidths.size() > max_bandwidth_in_average) {
		ctx->last_bandwidths.pop_front();
	}

	double average_bandwidth = std::accumulate(ctx->last_bandwidths.begin(), ctx->last_bandwidths.end(), 0.0);
	//std::for_each(ctx->last_bandwidths.begin(), ctx->last_bandwidths.end(), [&average_bandwidth](double &n) { average_bandwidth+=n; });
	if (ctx->last_bandwidths.size() > 0) {
		average_bandwidth /= ctx->last_bandwidths.size();
	}

	/* Average over a set period of time */
	average_bandwidth /= average_bw_time_span / 1000;

	/* Convert from bytes to megabytes */
	/* Note that it's important to have only one place where
	 * we atomically assign to last_calculated_bandwidth */

	ctx->last_calculated_bandwidth = average_bandwidth * 0.000001;

	std::wstring label(fmt::format(ctx->label_format, ctx->files_done, ctx->num_files, ctx->last_calculated_bandwidth));

	SetWindowTextW(ctx->progress_label, label.c_str());
	SetTimer(hwnd, idEvent, static_cast<unsigned int>(average_bw_time_span), &bandwidth_tick);
}

void callbacks_impl::download_progress(int thread_index, size_t consumed, size_t accum)
{
	total_consumed += consumed;
	/* We don't currently show per-file progress but we could
	 * progress the bar based on files_done + remainder of
	 * all in-progress files done. */

	if (accum != file_sizes[thread_index]) {
		return;
	}

	++files_done;

	double percent = (double)files_done / (double)num_files;

	std::wstring label(fmt::format(label_format, files_done, num_files, last_calculated_bandwidth));

	int pos = lround(percent * INT_MAX);
	PostMessage(progress_worker, PBM_SETPOS, pos, 0);
	SetWindowTextW(progress_label, label.c_str());
}

void callbacks_impl::installer_download_start(const std::string &packageName)
{
	package_dl_pct100 = 0;
	installer_download_progress(0);
	std::wstring downloading_label = ConvertToUtf16WS(boost::locale::translate("Downloading"));
	downloading_label += fmt::to_wstring(packageName) + L"...";

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	DrawText(hdc, downloading_label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);

	progress_label_rect.right -= progress_label_rect.left;

	std::wstring processes_list = L"C: \r\nD: \r\nE: \r\nF: \r\nG: \r\nI: ";
	blockers_list_rect = {0};
	DrawText(hdc, processes_list.c_str(), -1, &blockers_list_rect, DT_CALCRECT | DT_NOCLIP);

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	repostionUI();

	SetWindowTextW(progress_label, downloading_label.c_str());
}

void callbacks_impl::installer_download_progress(const double percent)
{
	// Too many PostMessage per/sec overwhelm gui refresh rate
	int pct100 = int(percent * 100.0);

	if (pct100 > package_dl_pct100) {
		package_dl_pct100 = pct100;
		PostMessage(progress_worker, PBM_SETPOS, static_cast<int>(percent * double(INT_MAX)), 0);
	}
}

void callbacks_impl::installer_package_failed(const std::string &packageName, const std::string &message)
{
	if (message.empty())
		MessageBoxA(frame, ("WARNING: Streamlabs Desktop was unable to download/install the required '" + packageName + "' package.").c_str(),
			    "Package Installation", MB_OK | MB_ICONWARNING);
	else
		MessageBoxA(
			frame,
			("WARNING: Streamlabs Desktop was unable to download/install the required '" + packageName + "' package.\nError: " + message).c_str(),
			"Package Installation", MB_OK | MB_ICONWARNING);

	log_info(("installer_package_failed, message = " + message).c_str());
}

void callbacks_impl::installer_run_file(const std::string &packageName, const std::string &startParams, const std::string &rawFileBin)
{
	DWORD dwExitCode = ERROR_SUCCESS;

	const std::string filename = "tempstreamlabspackage.exe";
	std::ofstream outFile(filename, std::ios::out | std::ios::binary);

	if (outFile.is_open()) {
		outFile.write(&rawFileBin[0], rawFileBin.size());
		outFile.close();
	} else {
		dwExitCode = GetLastError();
	}

	if (dwExitCode == ERROR_SUCCESS) {
		STARTUPINFOA si;
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);

		PROCESS_INFORMATION pi;
		ZeroMemory(&pi, sizeof(pi));

		if (CreateProcessA(filename.c_str(), LPSTR((filename + " " + startParams).c_str()), NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si,
				   &pi)) {
			WaitForSingleObject(pi.hProcess, INFINITE);
			GetExitCodeProcess(pi.hProcess, &dwExitCode);

			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
		} else {
			dwExitCode = GetLastError();
		}
	}

	std::error_code ec;
	fs::remove(filename, ec);

	if (dwExitCode != ERROR_SUCCESS) {
		switch (dwExitCode) {
		case ERROR_SUCCESS_REBOOT_INITIATED:
		case ERROR_SUCCESS_REBOOT_REQUIRED:
			if (!notify_restart && (notify_restart = true)) {
				// Silenced for now, needs to be raised again when the package(s) are factually required to run the application
				//MessageBoxA(frame, "A restart is required to complete the update.", "Package Installation", MB_OK | MB_ICONWARNING);
			}
			break;
		default:
			installer_package_failed(packageName, "");
			break;
		}

		log_info("installer_run_file failed with error %d", dwExitCode);
	}
}

void callbacks_impl::downloader_complete(const bool success)
{
	KillTimer(frame, 1);
	finished_downloading = success;
}

void callbacks_impl::blocker_start()
{
	ShowWindow(progress_worker, SW_HIDE);

	std::wstring blocking_app_label =
		ConvertToUtf16WS(boost::locale::translate("The following programs are preventing Streamlabs Desktop from updating :"));

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	DrawText(hdc, blocking_app_label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);

	progress_label_rect.right -= progress_label_rect.left;

	std::wstring processes_list = L"C: \r\nD: \r\nE: \r\nF: \r\nG: \r\nI: ";
	blockers_list_rect = {0};
	DrawText(hdc, processes_list.c_str(), -1, &blockers_list_rect, DT_CALCRECT | DT_NOCLIP);

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	ShowWindow(blockers_list, SW_SHOW);
	ShowWindow(kill_button, SW_SHOW);
	ShowWindow(cancel_button, SW_SHOW);

	repostionUI();

	SetWindowTextW(progress_label, blocking_app_label.c_str());
	SetWindowTextW(blockers_list, L"");
}

int callbacks_impl::blocker_waiting_for(const std::wstring &processes_list, bool list_changed)
{
	int ret = 0;
	if (should_cancel) {
		should_cancel = false;
		ret = 2;
	} else if (should_kill_blockers) {
		should_kill_blockers = false;
		ret = 1;
	} else {
		if (list_changed) {
			SetWindowTextW(blockers_list, processes_list.c_str());
		}
	}
	return ret;
}

void callbacks_impl::blocker_wait_complete()
{
	ShowWindow(blockers_list, SW_HIDE);
	ShowWindow(kill_button, SW_HIDE);
	ShowWindow(cancel_button, SW_HIDE);
	SetWindowTextW(blockers_list, L"");
	SetWindowTextW(progress_label, L"");

	ShowWindow(progress_worker, SW_SHOW);
}

void callbacks_impl::disk_space_check_start()
{
	ShowWindow(progress_worker, SW_HIDE);

	std::wstring disk_space_label =
		ConvertToUtf16WS(boost::locale::translate("Streamlabs Desktop requires at least 2GB of free disk space to update safely,\n"
							  "updates may fail without this space. If you want to ensure safe updates,\n"
							  "please reinstall Streamlabs Desktop to a drive with available space:"));
	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	DrawText(hdc, disk_space_label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);

	progress_label_rect.right -= progress_label_rect.left;

	std::wstring processes_list = L"C: 100Mb\nD: 100Mb\nE: 100Mb";
	blockers_list_rect = {0};
	DrawText(hdc, processes_list.c_str(), -1, &blockers_list_rect, DT_CALCRECT | DT_NOCLIP);

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	ShowWindow(blockers_list, SW_SHOW);
	ShowWindow(continue_button, SW_SHOW);
	ShowWindow(cancel_button, SW_SHOW);

	repostionUI();
	SetWindowTextW(progress_label, disk_space_label.c_str());
}

int callbacks_impl::disk_space_waiting_for(const std::wstring &app_dir, size_t app_dir_free_space, const std::wstring &temp_dir, size_t temp_dir_free_space,
					   bool skip_update)
{
	int ret = 0;

	if (should_cancel) {
		should_cancel = false;
		ret = 2;
	} else if (should_continue) {
		should_continue = false;
		ret = 1;
	} else if (!skip_update) {
		std::wstring app_disk_name = app_dir.substr(0, app_dir.find_first_of(L"\\"));
		std::wstring temp_disk_name = temp_dir.substr(0, temp_dir.find_first_of(L"\\"));

		std::transform(app_disk_name.begin(), app_disk_name.end(), app_disk_name.begin(), ::toupper);
		std::transform(temp_disk_name.begin(), temp_disk_name.end(), temp_disk_name.begin(), ::toupper);
		std::wostringstream processes_list;
		processes_list.precision(2);
		processes_list << std::fixed;

		if (app_disk_name != temp_disk_name) {
			processes_list << L"" << app_disk_name << L"[APP] " << app_dir_free_space / 1024.0 / 1024.0 << L" Mb free";
			processes_list << L"\r\n" << L"" << temp_disk_name << L"[TEMP]" << temp_dir_free_space / 1024.0 / 1024.0 << L" Mb free";
		} else {
			processes_list << L"" << app_disk_name << L" " << app_dir_free_space / 1024.0 / 1024.0 << L" Mb free";
		}
		SetWindowTextW(blockers_list, processes_list.str().c_str());
	}
	return ret;
}

void callbacks_impl::disk_space_wait_complete()
{
	ShowWindow(blockers_list, SW_HIDE);
	ShowWindow(continue_button, SW_HIDE);
	ShowWindow(cancel_button, SW_HIDE);
	SetWindowTextW(blockers_list, L"");
	SetWindowTextW(progress_label, L"");
}

void callbacks_impl::updater_start()
{
	std::wstring copying_label = ConvertToUtf16WS(boost::locale::translate("Copying files..."));

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	progress_label_rect = {0};
	DrawText(hdc, copying_label.c_str(), -1, &progress_label_rect, DT_CALCRECT | DT_NOCLIP);

	progress_label_rect.right -= progress_label_rect.left;

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);

	repostionUI();

	SetWindowTextW(progress_label, copying_label.c_str());
}

void callbacks_impl::calculate_text_dimensions(const std::wstring &title, const std::wstring &content, RECT &title_rect, RECT &content_rect)
{
	RECT rcClient{};
	GetClientRect(frame, &rcClient);

	int calc_w = (rcClient.right - rcClient.left) - (ui_padding * 2);
	if (calc_w < ui_min_width)
		calc_w = ui_min_width;

	HDC hdc = GetDC(frame);
	HFONT hfontOld = (HFONT)SelectObject(hdc, main_font);

	title_rect = {0};
	DrawTextW(hdc, title.c_str(), -1, &title_rect, DT_CALCRECT | DT_NOCLIP);
	title_rect.right -= title_rect.left;

	RECT rcCalc = {0, 0, calc_w, 0};
	DrawTextW(hdc, content.c_str(), -1, &rcCalc, DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL);

	content_rect = {0};
	content_rect.right = calc_w;
	content_rect.bottom = rcCalc.bottom - rcCalc.top;

	if (title_rect.right < calc_w)
		title_rect.right = calc_w;

	SelectObject(hdc, hfontOld);
	ReleaseDC(frame, hdc);
}

void callbacks_impl::show_ui_elements(bool show_buttons, bool show_kill)
{
	ShowWindow(frame, SW_SHOWNORMAL);
	ShowWindow(progress_worker, SW_HIDE);
	ShowWindow(blockers_list, SW_SHOW);

	if (show_buttons) {
		ShowWindow(continue_button, SW_SHOW);
		ShowWindow(cancel_button, SW_SHOW);
	}

	if (show_kill) {
		ShowWindow(kill_button, SW_SHOW);
	} else {
		ShowWindow(kill_button, SW_HIDE);
	}

	EnableWindow(continue_button, TRUE);
	EnableWindow(cancel_button, TRUE);
	EnableWindow(kill_button, TRUE);
}

void callbacks_impl::hide_ui_elements()
{
	ShowWindow(frame, SW_HIDE);
	ShowWindow(blockers_list, SW_HIDE);
	ShowWindow(continue_button, SW_HIDE);
	ShowWindow(cancel_button, SW_HIDE);
	ShowWindow(kill_button, SW_HIDE);

	SetWindowTextW(blockers_list, L"");
	SetWindowTextW(progress_label, L"");
}

void callbacks_impl::reset_ui_labels()
{
	SetWindowTextW(continue_button, continue_label.c_str());
	SetWindowTextW(cancel_button, cancel_label.c_str());

	update_btn_label = ConvertToUtf16WS(boost::locale::translate("Upgrade"));
	remind_btn_label = ConvertToUtf16WS(boost::locale::translate("Later"));
	trim_trailing_nuls(update_btn_label);
	trim_trailing_nuls(remind_btn_label);
}

bool callbacks_impl::run_message_loop()
{
	MSG msg;
	bool user_accepted = false;

	while (GetMessage(&msg, NULL, 0, 0) > 0) {
		if (!IsDialogMessage(frame, &msg)) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}

		if (should_cancel) {
			should_cancel = false;
			user_accepted = false;
			break;
		}
		if (should_continue) {
			should_continue = false;
			user_accepted = true;
			break;
		}
	}

	return user_accepted;
}

bool callbacks_impl::show_dialog(const DialogState &state)
{
	should_cancel = false;
	should_continue = false;
	should_kill_blockers = false;

	prompting = true;

	calculate_text_dimensions(state.title, state.content, progress_label_rect, blockers_list_rect);
	show_ui_elements(true, false);

	repostionUI();

	SetWindowTextW(progress_label, state.title.c_str());
	SetWindowTextW(blockers_list, state.content.c_str());
	SendMessageW(blockers_list, EM_SETSEL, 0, 0);

	SetWindowTextW(continue_button, state.accept_label.c_str());
	SetWindowTextW(cancel_button, state.decline_label.c_str());

	if (!state.show_decline_button) {
		ShowWindow(cancel_button, SW_HIDE);
	}

	RedrawWindow(continue_button, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);
	RedrawWindow(cancel_button, NULL, NULL, RDW_INVALIDATE | RDW_UPDATENOW);

	bool result = run_message_loop();

	hide_ui_elements();
	reset_ui_labels();

	prompting = false;
	return result;
}

std::wstring callbacks_impl::format_update_details(const std::string &detailsStr)
{
	const wchar_t *wc_dash = L"-";
	const wchar_t *wc_hash = L"#";
	const wchar_t *wc_bullet = L"\r\n    \u2022 ";
	const wchar_t *wc_break = L"\r\n";

	std::wstring wc_details = ConvertToUtf16WS(boost::locale::translate(detailsStr.c_str()));

	std::list<std::pair<std::wstring, std::wstring>> tagsToHeadings;
	tagsToHeadings.push_back(std::make_pair(L"#hotfixes", L"Hotfix Changes"));
	tagsToHeadings.push_back(std::make_pair(L"#features", L"New Features"));
	tagsToHeadings.push_back(std::make_pair(L"#generalfixes", L"General Fixes"));

	size_t replacePos = 0;
	for (const auto &tagHeadingPair : tagsToHeadings) {
		replacePos = wc_details.find(tagHeadingPair.first);
		if (replacePos != std::wstring::npos) {
			wc_details.replace(replacePos, tagHeadingPair.first.size(), tagHeadingPair.second);
			if (replacePos != 0) {
				wc_details.insert(replacePos, wc_break);
				wc_details.insert(replacePos, wc_break);
				replacePos += (wcslen(wc_break) * 2);
			}
		}
	}

	replacePos = wc_details.find(wc_hash);
	while (replacePos != std::wstring::npos) {
		if (replacePos != 0) {
			wc_details.insert(replacePos, wc_break);
			wc_details.insert(replacePos, wc_break);
			replacePos += (wcslen(wc_break) * 2);
		}
		wc_details.replace(replacePos, 1, L"");
		replacePos = wc_details.find(wc_hash, replacePos + 1);
	}

	replacePos = wc_details.find(wc_dash);
	while (replacePos != std::wstring::npos) {
		wc_details.replace(replacePos, wcslen(wc_dash), wc_bullet);
		replacePos = wc_details.find(wc_dash, replacePos + wcslen(wc_bullet));
	}

	wc_details.insert(wc_details.length() - 1, wc_break);

	return wc_details;
}

bool callbacks_impl::prompt_user(const char *pVersion, const char *pDetails)
{
	std::wstring wc_version = ConvertToUtf16WS(boost::locale::translate(pVersion));

	std::string detailsStr;
	bool forceUpdate = false;
	if (pDetails && *pDetails) {
		try {
			std::ifstream jfile{pDetails, std::ios::in};
			if (jfile) {
				nlohmann::json j;
				jfile >> j;
				if (j.contains("details") && j["details"].is_string())
					detailsStr = j["details"].get<std::string>();
				if (j.contains("forceUpdate") && j["forceUpdate"].is_boolean())
					forceUpdate = j["forceUpdate"].get<bool>();
			}
		} catch (...) {
			log_error("Failed to read details file: %s", pDetails);
		}
	}

	DialogState state;
	
	if (detailsStr.empty()) {
		state.title = ConvertToUtf16WS(boost::locale::translate("There's an update available. Would you like to install?"));
		state.content = L"New version: " + wc_version;
	} else {
		state.title = ConvertToUtf16WS(boost::locale::translate("There's an update available to install: "));
		state.title.insert(state.title.size() - 1, wc_version);
		state.content = format_update_details(detailsStr);
	}

	state.accept_label = update_btn_label;
	state.decline_label = remind_btn_label;
	state.show_decline_button = !forceUpdate;

	return show_dialog(state);
}
bool callbacks_impl::prompt_file_removal()
{
	std::wstring wc_title = ConvertToUtf16WS(boost::locale::translate("Old File Removal"));
	trim_trailing_nuls(wc_title);

	std::wstring s_install = ConvertToUtf16WS(boost::locale::translate("Install location:\r\n"));
	trim_trailing_nuls(s_install);

	std::wstring s_body = ConvertToUtf16WS(boost::locale::translate(
		"Streamlabs Desktop is installed in a custom folder:\r\n\r\n"
		"To complete this update, Streamlabs needs to remove outdated app files from that folder.\r\n\r\n"
		"If this folder also contains your own files (recordings, exports, scene backups, etc.).\r\n"
		"Choose Keep to do update without removing any files."));
	trim_trailing_nuls(s_body);

	const std::wstring appdir = params.app_dir.native();
	std::wstring wc_details;
	wc_details.reserve(s_install.size() + appdir.size() + 4 + s_body.size() + 8);
	wc_details += s_install;
	wc_details += appdir;
	wc_details += L"\r\n\r\n";
	wc_details += s_body;

	std::wstring allow = ConvertToUtf16WS(boost::locale::translate("Allow"));
	std::wstring keep = ConvertToUtf16WS(boost::locale::translate("Keep"));
	trim_trailing_nuls(allow);
	trim_trailing_nuls(keep);

	DialogState state;
	state.title = wc_title;
	state.content = wc_details;
	state.accept_label = allow;
	state.decline_label = keep;
	state.show_decline_button = true;

	update_btn_label = allow;
	remind_btn_label = keep;

	bool result = show_dialog(state);

	update_btn_label = ConvertToUtf16WS(boost::locale::translate("Upgrade"));
	remind_btn_label = ConvertToUtf16WS(boost::locale::translate("Later"));
	trim_trailing_nuls(update_btn_label);
	trim_trailing_nuls(remind_btn_label);

	return result;
}

LRESULT CALLBACK ProgressLabelWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	switch (msg) {
	case WM_SETTEXT: {
		RECT rect;
		HWND parent = GetParent(hwnd);

		GetWindowRect(hwnd, &rect);
		MapWindowPoints(HWND_DESKTOP, parent, (LPPOINT)&rect, 2);

		RedrawWindow(parent, &rect, NULL, RDW_ERASE | RDW_INVALIDATE);
	} break;
	}

	return DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK BlockersListWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	switch (msg) {
	case WM_PAINT: {
		//redraw on scroll so text doesn't overwrite itself - parent is now WS_CLIPCHILDREN so have to manually invalidate
		InvalidateRect(hwnd, NULL, true);
	} break;
	case WM_HSCROLL:
	case WM_VSCROLL:
	case WM_SETTEXT: {
		RECT rect;
		HWND parent = GetParent(hwnd);

		GetWindowRect(hwnd, &rect);
		MapWindowPoints(HWND_DESKTOP, parent, (LPPOINT)&rect, 2);

		RedrawWindow(parent, &rect, NULL, RDW_ERASE | RDW_INVALIDATE);
	} break;
	}

	return DefSubclassProc(hwnd, msg, wParam, lParam);
}

LRESULT CALLBACK FrameWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
	switch (msg) {
	case WM_CLOSE:
		/* Prevent closing in a normal manner. */
		return 0;
	case WM_DESTROY:
		PostQuitMessage(0);
		break;
	case CUSTOM_CLOSE_MSG:
		DestroyWindow(hwnd);
		break;
	case CUSTOM_ERROR_MSG: {
		LONG_PTR user_data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
		auto ctx = reinterpret_cast<callbacks_impl *>(user_data);

		ShowError(ctx->error_buf);
		ctx->error_buf = "";

		DestroyWindow(hwnd);

		break;
	}
	case WM_COMMAND: {
		LONG_PTR user_data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
		auto ctx = reinterpret_cast<callbacks_impl *>(user_data);

		if ((HWND)lParam == ctx->kill_button) {
			EnableWindow(ctx->kill_button, false);
			ctx->should_kill_blockers = true;
			break;
		}
		if ((HWND)lParam == ctx->continue_button) {
			EnableWindow(ctx->continue_button, false);
			ctx->should_continue = true;
			break;
		}
		if ((HWND)lParam == ctx->cancel_button) {
			EnableWindow(ctx->kill_button, false);
			EnableWindow(ctx->continue_button, false);
			EnableWindow(ctx->cancel_button, false);
			ctx->should_kill_blockers = false;
			ctx->should_continue = false;
			ctx->should_cancel = true;
			break;
		}
	} break;
	case WM_CTLCOLORSTATIC: {
		LONG_PTR user_data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
		auto ctx = reinterpret_cast<callbacks_impl *>(user_data);

		SetBkMode((HDC)wParam, TRANSPARENT);
		if (((HWND)lParam == ctx->progress_label) && ctx->prompting) {
			SetTextColor((HDC)wParam, kev_color);
			SetBkColor((HDC)wParam, dlg_bg_color);
			return (LRESULT)ctx->dlg_bg_brush;
		} else if ((HWND)lParam == ctx->blockers_list) {
			SetBkColor((HDC)wParam, edit_bg_color);
			SetTextColor((HDC)wParam, white_color);
			return (LRESULT)ctx->edit_bg_brush;
		} else {
			SetTextColor((HDC)wParam, white_color);
			SetBkColor((HDC)wParam, dlg_bg_color);
			return (LRESULT)ctx->dlg_bg_brush;
		}
	} break;
	case WM_CTLCOLORBTN: {
		LONG_PTR user_data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
		auto ctx = reinterpret_cast<callbacks_impl *>(user_data);

		SetBkMode((HDC)wParam, OPAQUE);
		if (((HWND)lParam == ctx->continue_button) && ctx->prompting) {
			if (!IsWindowEnabled((HWND)lParam)) {
				SetTextColor((HDC)wParam, disabled_gray_color);
			} else {
				SetTextColor((HDC)wParam, black_color);
			}
			SetBkColor((HDC)wParam, kev_color);
			return (LRESULT)ctx->kev_btn_brush;
		} else {
			if (!IsWindowEnabled((HWND)lParam)) {
				SetTextColor((HDC)wParam, disabled_gray_color);
			} else {
				SetTextColor((HDC)wParam, white_color);
			}
			SetBkColor((HDC)wParam, gray_btn_color);
			return (LRESULT)ctx->gray_btn_brush;
		}
	} break;
	case WM_DRAWITEM: {
		LONG_PTR user_data = GetWindowLongPtr(hwnd, GWLP_USERDATA);
		LPDRAWITEMSTRUCT dis = (LPDRAWITEMSTRUCT)lParam;
		auto ctx = reinterpret_cast<callbacks_impl *>(user_data);

		if (dis->hwndItem == ctx->continue_button) {
			if (ctx->prompting) {
				DrawText(dis->hDC, ctx->update_btn_label.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			} else {
				DrawText(dis->hDC, ctx->continue_label.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			}
		}
		if (dis->hwndItem == ctx->cancel_button) {
			if (ctx->prompting) {
				DrawText(dis->hDC, ctx->remind_btn_label.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

			} else {
				DrawText(dis->hDC, ctx->cancel_label.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
			}
		}
		if (dis->hwndItem == ctx->kill_button) {
			DrawText(dis->hDC, ctx->stop_all_label.c_str(), -1, &dis->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);
		}
	} break;
	}

	return DefWindowProc(hwnd, msg, wParam, lParam);
}

LSTATUS GetStringRegKey(HKEY baseKey, const std::wstring &path, const std::wstring &strValueName, std::wstring &strValue)
{
	HKEY hKey = nullptr;
	LSTATUS ret = RegOpenKeyExW(baseKey, path.c_str(), 0, KEY_READ, &hKey);

	if (ret != ERROR_SUCCESS)
		return ret;

	WCHAR szBuffer[512];
	DWORD dwBufferSize = sizeof(szBuffer);

	ret = RegQueryValueExW(hKey, strValueName.c_str(), 0, NULL, (LPBYTE)szBuffer, &dwBufferSize);

	if (ret == ERROR_SUCCESS)
		strValue = szBuffer;

	return ret;
}

BOOL HasInstalled_VC_redistx64()
{
	std::wstring version;
	LSTATUS ret = GetStringRegKey(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Classes\\Installer\\Dependencies\\Microsoft.VS.VC_RuntimeAdditionalVSU_amd64,v14",
				      L"Version", version);

	if (ret == ERROR_SUCCESS) {
		std::vector<std::wstring> versions;
		boost::split(versions, version, boost::is_any_of("."));

		// "Version"="14.30.30704"
		if (versions.size() == 3) {
			if (_wtoi(versions[0].c_str()) < 14)
				return FALSE;

			if (_wtoi(versions[0].c_str()) > 14)
				return TRUE;

			if (_wtoi(versions[1].c_str()) < 30)
				return FALSE;

			if (_wtoi(versions[1].c_str()) > 30)
				return TRUE;

			// 14.30.X
			if (_wtoi(versions[2].c_str()) >= 30704)
				return TRUE;
		}
	} else {
		log_error("HasInstalledVcRedist GetStringRegKey, error %d", ret);
	}

	return FALSE;
}

void exit_on_init_fail(MultiByteCommandLine &command_line)
{
	if (command_line.argc() == 1 && is_launched_by_explorer()) {
		ShowInfo(boost::locale::translate(
			"You have launched the updater for Streamlabs Desktop, which can't work on its own. Please launch the Desktop App and it will check for updates automatically.\nIf you're having issues you can download the latest version from https://streamlabs.com/."));
		save_exit_error("Launched manually");
	} else if (is_system_folder(params.app_dir)) {
		ShowInfo(boost::locale::translate(
			"Streamlabs Desktop installed in a system folder. Automatic updated has been disabled to prevent changes to a system folder. \nPlease install the latest version of Streamlabs Desktop from https://streamlabs.com/"));
		save_exit_error("App installed in a system folder. Skip update.");
	} else {
		ShowError(getDefaultErrorMessage());
		save_exit_error("Failed parsing arguments");
	}
	handle_exit();
}

extern "C" int wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPWSTR lpCmdLineUnused, int nCmdShow)
{
	try {
		setup_locale();
	} catch (...) {
		// translation failed, continue without it
	}

	setup_crash_reporting();

	callbacks_impl cb_impl(hInstance, nCmdShow);

	MultiByteCommandLine command_line;

	update_completed = su_parse_command_line(command_line.argc(), command_line.argv(), &params);

	if (!update_completed) {
		exit_on_init_fail(command_line);
		return 0;
	}

	if (!cb_impl.prompt_user(params.version.c_str(), params.details.c_str())) {
		//act as if we updated so app will be launched
		cb_impl.success();
	} else {
		if (!params.enable_removing_old_files) {
			if (cb_impl.prompt_file_removal()) {
				params.enable_removing_old_files = true;
				log_warn("User allowed file removal for this update.");
			} else {
				log_warn("User declined file removal. Old files will not be removed during update.");
			}
		}

		auto client_deleter = [](struct update_client *client) { destroy_update_client(client); };

		std::unique_ptr<struct update_client, decltype(client_deleter)> client(create_update_client(&params), client_deleter);

		update_client_set_client_events(client.get(), &cb_impl);
		update_client_set_downloader_events(client.get(), &cb_impl);
		update_client_set_updater_events(client.get(), &cb_impl);
		update_client_set_pid_events(client.get(), &cb_impl);
		update_client_set_blocker_events(client.get(), &cb_impl);
		update_client_set_disk_space_events(client.get(), &cb_impl);
		update_client_set_installer_events(client.get(), &cb_impl);

		cb_impl.initialize(client.get());

		std::thread workerThread([&]() {
			// Threaded because package installations come first which is blocking from the perspective of the file updater
			update_client_start(client.get());
		});

		MSG msg;

		while (GetMessage(&msg, NULL, 0, 0) > 0) {
			TranslateMessage(&msg);
			DispatchMessage(&msg);
		}

		workerThread.join();
		update_client_flush(client.get());
	}

	/* Don't attempt start if application failed to update */
	if (cb_impl.should_start || params.restart_on_fail || !cb_impl.finished_downloading) {
		bool app_started = false;
		if (params.restart_on_fail || !cb_impl.finished_downloading)
			app_started = StartApplication(params.exec_no_update.c_str(), params.exec_cwd.c_str());
		else
			app_started = StartApplication(params.exec.c_str(), params.exec_cwd.c_str());

		// If failed to launch desktop app...
		if (!app_started) {
			if (cb_impl.finished_downloading) {
				ShowInfo(boost::locale::translate("The application has finished updating.\nPlease manually start Streamlabs Desktop."));
			} else {
				ShowError(boost::locale::translate(
					"There was an issue launching the application.\nPlease start Streamlabs Desktop and try again."));
			}

			if (cb_impl.should_start)
				save_exit_error("Failed to autorestart");
			handle_exit();
		} else if (!cb_impl.should_start)
			handle_exit();
	} else {
		handle_exit();

		return 1;
	}

	return 0;
}
