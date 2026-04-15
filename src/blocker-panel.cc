#include "blocker-panel.hpp"
#include "utils.hpp"
#include "logger/log.h"

#include <shellapi.h>
#include <windowsx.h>
#include <commctrl.h>
#include <tlhelp32.h>

#pragma comment(lib, "Shell32.lib")

#define CLS_BLOCKER_LIST (3)

static const int COL_NAME = 0;
static const int COL_POPUP = 1;
static const int POPUP_COL_WIDTH = 65;

static const COLORREF link_color = RGB(128, 245, 210);
static const COLORREF link_hover_color = RGB(180, 255, 235);
static const COLORREF bg_color = RGB(12, 17, 22);

blocker_panel::blocker_panel(HWND parent, int x, int y, int w, int h, UINT dpi) : dpi_(dpi)
{
	hwnd_ = CreateWindowEx(0, WC_LISTVIEW, L"",
			       WS_CHILD | WS_BORDER | LVS_REPORT | LVS_NOCOLUMNHEADER | LVS_SINGLESEL | LVS_NOSORTHEADER, x, y, w, h, parent, NULL, NULL,
			       NULL);

	if (!hwnd_) {
		LogLastError(L"blocker_panel CreateWindowEx");
		return;
	}

	ListView_SetExtendedListViewStyle(hwnd_, LVS_EX_FULLROWSELECT | LVS_EX_DOUBLEBUFFER);

	ListView_SetBkColor(hwnd_, bg_color);
	ListView_SetTextBkColor(hwnd_, bg_color);
	ListView_SetTextColor(hwnd_, RGB(255, 255, 255));

	int s_popup_col = ScaleDPI(POPUP_COL_WIDTH, dpi_);
	int s_scrollbar = GetSystemMetricsForDpi(SM_CXVSCROLL, dpi_);

	LVCOLUMN col = {0};
	col.mask = LVCF_WIDTH | LVCF_SUBITEM;
	col.cx = w - s_popup_col - s_scrollbar - ScaleDPI(4, dpi_);
	col.iSubItem = COL_NAME;
	ListView_InsertColumn(hwnd_, COL_NAME, &col);

	col.cx = s_popup_col;
	col.iSubItem = COL_POPUP;
	ListView_InsertColumn(hwnd_, COL_POPUP, &col);

	int icon_size = ScaleDPI(16, dpi_);
	image_list_ = ImageList_Create(icon_size, icon_size, ILC_COLOR32 | ILC_MASK, 4, 4);
	ListView_SetImageList(hwnd_, image_list_, LVSIL_SMALL);

	hand_cursor_ = LoadCursor(NULL, IDC_HAND);

	SetWindowSubclass(hwnd_, subclass_proc, CLS_BLOCKER_LIST, (DWORD_PTR)this);
}

blocker_panel::~blocker_panel()
{
	if (link_font_)
		DeleteObject(link_font_);
	if (hwnd_) {
		RemoveWindowSubclass(hwnd_, subclass_proc, CLS_BLOCKER_LIST);
		DestroyWindow(hwnd_);
	}
	if (image_list_)
		ImageList_Destroy(image_list_);
}

void blocker_panel::show()
{
	ShowWindow(hwnd_, SW_SHOW);
}

void blocker_panel::hide()
{
	ShowWindow(hwnd_, SW_HIDE);
}

bool blocker_panel::is_visible() const
{
	return IsWindowVisible(hwnd_) != FALSE;
}

void blocker_panel::set_text(const wchar_t *)
{
}

void blocker_panel::clear()
{
	ListView_DeleteAllItems(hwnd_);
	ImageList_RemoveAll(image_list_);
	blockers_.clear();
}

void blocker_panel::measure(HDC hdc, int max_width)
{
	int item_count = ListView_GetItemCount(hwnd_);
	if (item_count <= 0)
		item_count = 1;

	int item_height = ScaleDPI(24, dpi_);
	if (ListView_GetItemCount(hwnd_) > 0) {
		RECT rc = {0};
		ListView_GetItemRect(hwnd_, 0, &rc, LVIR_BOUNDS);
		if (rc.bottom - rc.top > 0)
			item_height = rc.bottom - rc.top;
	}

	rect_ = {0, 0, max_width, item_count * item_height + ScaleDPI(4, dpi_)};
}

void blocker_panel::set_position(int x, int y, int w, int h)
{
	SetWindowPos(hwnd_, 0, x, y, w, h, SWP_ASYNCWINDOWPOS);

	int s_popup_col = ScaleDPI(POPUP_COL_WIDTH, dpi_);
	int s_scrollbar = GetSystemMetricsForDpi(SM_CXVSCROLL, dpi_);
	int name_col_width = w - s_popup_col - s_scrollbar - ScaleDPI(4, dpi_);
	if (name_col_width < ScaleDPI(50, dpi_))
		name_col_width = ScaleDPI(50, dpi_);
	ListView_SetColumnWidth(hwnd_, COL_NAME, name_col_width);
}

void blocker_panel::set_font(HFONT font)
{
	SendMessage(hwnd_, WM_SETFONT, WPARAM(font), TRUE);

	// Create underlined version for the link
	if (link_font_)
		DeleteObject(link_font_);

	LOGFONT lf = {0};
	GetObject(font, sizeof(lf), &lf);
	lf.lfUnderline = TRUE;
	link_font_ = CreateFontIndirect(&lf);
}

int blocker_panel::extract_icon(const std::wstring &exe_path)
{
	HICON hIcon = NULL;
	int icon_size = ScaleDPI(16, dpi_);

	if (!exe_path.empty()) {
		SHFILEINFO sfi = {0};
		if (SHGetFileInfo(exe_path.c_str(), 0, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON)) {
			hIcon = sfi.hIcon;
		}
	}

	if (!hIcon) {
		SHFILEINFO sfi = {0};
		if (SHGetFileInfo(L".exe", FILE_ATTRIBUTE_NORMAL, &sfi, sizeof(sfi), SHGFI_ICON | SHGFI_SMALLICON | SHGFI_USEFILEATTRIBUTES)) {
			hIcon = sfi.hIcon;
		}
	}

	if (hIcon) {
		/* Resize icon to match ImageList dimensions so it aligns with text */
		HICON hResized = (HICON)CopyImage(hIcon, IMAGE_ICON, icon_size, icon_size, 0);
		if (hResized) {
			DestroyIcon(hIcon);
			hIcon = hResized;
		}

		int idx = ImageList_AddIcon(image_list_, hIcon);
		DestroyIcon(hIcon);
		return idx;
	}
	return -1;
}

void blocker_panel::set_blockers(const std::vector<blocker_info> &blockers)
{
	clear();
	blockers_ = blockers;

	for (int i = 0; i < (int)blockers.size(); i++) {
		const auto &info = blockers[i];

		int icon_index = extract_icon(info.exe_path);

		LVITEM lvi = {0};
		lvi.mask = LVIF_TEXT | LVIF_PARAM | LVIF_IMAGE;
		lvi.iItem = i;
		lvi.iSubItem = COL_NAME;
		lvi.pszText = const_cast<LPWSTR>(info.app_name.c_str());
		lvi.lParam = (LPARAM)info.pid;
		lvi.iImage = icon_index;
		ListView_InsertItem(hwnd_, &lvi);
	}
}

int blocker_panel::hit_test_popup(LPARAM mouse_lParam)
{
	LVHITTESTINFO ht = {0};
	ht.pt.x = GET_X_LPARAM(mouse_lParam);
	ht.pt.y = GET_Y_LPARAM(mouse_lParam);
	ListView_SubItemHitTest(hwnd_, &ht);

	if (ht.iItem >= 0 && ht.iSubItem == COL_POPUP && ht.iItem < (int)blockers_.size() && blockers_[ht.iItem].has_window)
		return ht.iItem;
	return -1;
}

LRESULT blocker_panel::handle_custom_draw(LPNMLVCUSTOMDRAW lvcd)
{
	switch (lvcd->nmcd.dwDrawStage) {
	case CDDS_PREPAINT:
		return CDRF_NOTIFYITEMDRAW;

	case CDDS_ITEMPREPAINT:
		lvcd->clrText = RGB(255, 255, 255);
		lvcd->clrTextBk = bg_color;
		return CDRF_NOTIFYSUBITEMDRAW | CDRF_NEWFONT;

	case CDDS_ITEMPREPAINT | CDDS_SUBITEM:
		if (lvcd->iSubItem == COL_POPUP) {
			int item = (int)lvcd->nmcd.dwItemSpec;
			RECT rc = {0};
			ListView_GetSubItemRect(hwnd_, item, COL_POPUP, LVIR_BOUNDS, &rc);

			// Fill background
			HBRUSH bgb = CreateSolidBrush(bg_color);
			FillRect(lvcd->nmcd.hdc, &rc, bgb);
			DeleteObject(bgb);

			// Only draw link if process has a visible window
			if (item < (int)blockers_.size() && blockers_[item].has_window) {
				HFONT old_font = NULL;
				if (link_font_)
					old_font = (HFONT)SelectObject(lvcd->nmcd.hdc, link_font_);

				bool hovered = (item == hover_item_);
				SetBkMode(lvcd->nmcd.hdc, TRANSPARENT);
				SetTextColor(lvcd->nmcd.hdc, hovered ? link_hover_color : link_color);
				DrawTextW(lvcd->nmcd.hdc, L"Bring up", -1, &rc, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

				if (old_font)
					SelectObject(lvcd->nmcd.hdc, old_font);
			}

			return CDRF_SKIPDEFAULT;
		}
		lvcd->clrText = RGB(255, 255, 255);
		lvcd->clrTextBk = bg_color;
		return CDRF_NEWFONT;
	}

	return CDRF_DODEFAULT;
}

struct enum_best_wnd_data {
	std::vector<DWORD> pids;
	HWND result;
	int best_area;
};

static BOOL CALLBACK find_best_window_cb(HWND hwnd, LPARAM lParam)
{
	auto *data = reinterpret_cast<enum_best_wnd_data *>(lParam);
	DWORD pid = 0;
	GetWindowThreadProcessId(hwnd, &pid);

	bool pid_match = false;
	for (DWORD p : data->pids) {
		if (p == pid) {
			pid_match = true;
			break;
		}
	}

	if (pid_match && IsWindowVisible(hwnd) && GetWindow(hwnd, GW_OWNER) == NULL) {
		RECT rc;
		if (GetWindowRect(hwnd, &rc)) {
			int area = (rc.right - rc.left) * (rc.bottom - rc.top);
			if (area > data->best_area) {
				data->best_area = area;
				data->result = hwnd;
			}
		}
	}
	return TRUE;
}

static std::vector<DWORD> find_pids_for_exe(const std::wstring &exe_path)
{
	std::vector<DWORD> pids;
	if (exe_path.empty())
		return pids;

	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE)
		return pids;

	PROCESSENTRY32W pe = {sizeof(pe)};
	if (Process32FirstW(snap, &pe)) {
		do {
			HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
			if (hProc) {
				WCHAR sz[MAX_PATH];
				DWORD cch = MAX_PATH;
				if (QueryFullProcessImageNameW(hProc, 0, sz, &cch) && cch <= MAX_PATH) {
					if (_wcsicmp(sz, exe_path.c_str()) == 0) {
						pids.push_back(pe.th32ProcessID);
					}
				}
				CloseHandle(hProc);
			}
		} while (Process32NextW(snap, &pe));
	}
	CloseHandle(snap);
	return pids;
}

void blocker_panel::bring_to_front(DWORD pid, const std::wstring &exe_path)
{
	if (pid == 0)
		return;

	/* Collect all PIDs running the same executable so we can find the main
	 * window even when the DLL-locking process is a worker/child. */
	std::vector<DWORD> pids = find_pids_for_exe(exe_path);
	if (pids.empty())
		pids.push_back(pid);

	/* Pick the largest visible top-level window — most likely the main
	 * application window rather than a small overlay or notification. */
	enum_best_wnd_data data = {std::move(pids), NULL, 0};
	EnumWindows(find_best_window_cb, (LPARAM)&data);

	if (data.result) {
		if (IsIconic(data.result)) {
			ShowWindow(data.result, SW_RESTORE);
		}
		SetForegroundWindow(data.result);
	}
}

bool blocker_panel::handle_click(LPARAM lParam)
{
	LPNMITEMACTIVATE pnm = (LPNMITEMACTIVATE)lParam;
	if (!pnm || pnm->hdr.hwndFrom != hwnd_)
		return false;

	if (pnm->iSubItem == COL_POPUP && pnm->iItem >= 0 && pnm->iItem < (int)blockers_.size()) {
		const auto &info = blockers_[pnm->iItem];
		bring_to_front(info.pid, info.exe_path);
		return true;
	}
	return false;
}

void blocker_panel::update_dpi(UINT dpi)
{
	dpi_ = dpi;

	/* Recreate image list at new icon size; swap before destroying
	 * so the list view never references a destroyed image list. */
	int icon_size = ScaleDPI(16, dpi_);
	HIMAGELIST new_list = ImageList_Create(icon_size, icon_size, ILC_COLOR32 | ILC_MASK, 4, 4);
	HIMAGELIST old_list = ListView_SetImageList(hwnd_, new_list, LVSIL_SMALL);
	if (old_list)
		ImageList_Destroy(old_list);
	image_list_ = new_list;

	/* Re-extract icons for existing blockers at new size */
	for (int i = 0; i < (int)blockers_.size(); i++) {
		int icon_index = extract_icon(blockers_[i].exe_path);
		LVITEM lvi = {0};
		lvi.mask = LVIF_IMAGE;
		lvi.iItem = i;
		lvi.iImage = icon_index;
		ListView_SetItem(hwnd_, &lvi);
	}

	/* Update column widths */
	int s_popup_col = ScaleDPI(POPUP_COL_WIDTH, dpi_);
	ListView_SetColumnWidth(hwnd_, COL_POPUP, s_popup_col);
}

LRESULT CALLBACK blocker_panel::subclass_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	auto *self = reinterpret_cast<blocker_panel *>(dwRefData);

	switch (msg) {
	case WM_MOUSEMOVE: {
		int item = self->hit_test_popup(lParam);
		if (item != self->hover_item_) {
			int old_hover = self->hover_item_;
			self->hover_item_ = item;
			// Redraw affected rows
			if (old_hover >= 0)
				ListView_RedrawItems(hwnd, old_hover, old_hover);
			if (item >= 0)
				ListView_RedrawItems(hwnd, item, item);
			UpdateWindow(hwnd);
		}

		// Request WM_MOUSELEAVE
		TRACKMOUSEEVENT tme = {sizeof(tme), TME_LEAVE, hwnd, 0};
		TrackMouseEvent(&tme);
	} break;

	case WM_MOUSELEAVE: {
		if (self->hover_item_ >= 0) {
			int old = self->hover_item_;
			self->hover_item_ = -1;
			ListView_RedrawItems(hwnd, old, old);
			UpdateWindow(hwnd);
		}
	} break;

	case WM_SETCURSOR: {
		if (LOWORD(lParam) == HTCLIENT && self->hover_item_ >= 0) {
			SetCursor(self->hand_cursor_);
			return TRUE;
		}
	} break;
	}

	return DefSubclassProc(hwnd, msg, wParam, lParam);
}
