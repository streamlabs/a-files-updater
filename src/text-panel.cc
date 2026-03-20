#include "text-panel.hpp"
#include "utils.hpp"

text_panel::text_panel(HWND parent, int x, int y, int w, int h, const wchar_t *label)
{
	hwnd_ = CreateWindow(WC_EDIT, label,
			     WS_CHILD | WS_VSCROLL | ES_LEFT | ES_MULTILINE | ES_WANTRETURN | ES_AUTOVSCROLL | WS_BORDER | ES_READONLY, x, y, w, h,
			     parent, NULL, NULL, NULL);

	if (!hwnd_) {
		LogLastError(L"text_panel CreateWindow");
		return;
	}

	BOOL success = SetWindowSubclass(hwnd_, subclass_proc, CLS_BLOCKERS_LIST, 0);
	if (!success) {
		LogLastError(L"text_panel SetWindowSubclass");
	}
}

text_panel::~text_panel()
{
	if (hwnd_) {
		RemoveWindowSubclass(hwnd_, subclass_proc, CLS_BLOCKERS_LIST);
		DestroyWindow(hwnd_);
	}
}

void text_panel::show()
{
	ShowWindow(hwnd_, SW_SHOW);
}

void text_panel::hide()
{
	ShowWindow(hwnd_, SW_HIDE);
}

bool text_panel::is_visible() const
{
	return IsWindowVisible(hwnd_) != FALSE;
}

void text_panel::set_text(const wchar_t *text)
{
	SetWindowTextW(hwnd_, text);
	SendMessageW(hwnd_, EM_SETSEL, 0, 0);
}

void text_panel::clear()
{
	SetWindowTextW(hwnd_, L"");
}

void text_panel::measure(HDC hdc, int max_width)
{
	int text_len = GetWindowTextLength(hwnd_);
	if (text_len <= 0) {
		rect_ = {0};
		return;
	}

	std::wstring text(text_len + 1, L'\0');
	GetWindowTextW(hwnd_, &text[0], text_len + 1);

	rect_ = {0, 0, max_width, 0};
	DrawText(hdc, text.c_str(), -1, &rect_, DT_CALCRECT | DT_WORDBREAK | DT_EDITCONTROL);
}

void text_panel::set_position(int x, int y, int w, int h)
{
	SetWindowPos(hwnd_, 0, x, y, w, h, SWP_ASYNCWINDOWPOS);
}

void text_panel::set_font(HFONT font)
{
	SendMessage(hwnd_, WM_SETFONT, WPARAM(font), TRUE);
}

LRESULT CALLBACK text_panel::subclass_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData)
{
	switch (msg) {
	case WM_PAINT: {
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
