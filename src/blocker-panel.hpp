#pragma once

#include "content-panel.hpp"
#include "update-blockers.hpp"
#include "utils.hpp"
#include <commctrl.h>
#include <vector>

struct blocker_panel : public content_panel {
	blocker_panel(HWND parent, int x, int y, int w, int h, UINT dpi = USER_DEFAULT_SCREEN_DPI);
	~blocker_panel() override;

	blocker_panel(const blocker_panel &) = delete;
	blocker_panel &operator=(const blocker_panel &) = delete;

	HWND hwnd() const override { return hwnd_; }

	void show() override;
	void hide() override;
	bool is_visible() const override;

	void set_text(const wchar_t *text) override;
	void clear() override;

	void measure(HDC hdc, int max_width) override;
	RECT desired_rect() const override { return rect_; }
	void set_position(int x, int y, int w, int h) override;

	void set_font(HFONT font) override;

	void set_blockers(const std::vector<blocker_info> &blockers);

	static void bring_to_front(DWORD pid);

	bool handle_click(LPARAM lParam);

	LRESULT handle_custom_draw(LPNMLVCUSTOMDRAW lvcd);

	void update_dpi(UINT dpi);

private:
	HWND hwnd_{NULL};
	RECT rect_{0};
	HIMAGELIST image_list_{NULL};
	HFONT link_font_{NULL};
	HCURSOR hand_cursor_{NULL};
	int hover_item_{-1};
	UINT dpi_{USER_DEFAULT_SCREEN_DPI};
	std::vector<blocker_info> blockers_;

	int extract_icon(const std::wstring &exe_path);
	int hit_test_popup(LPARAM mouse_lParam);

	static LRESULT CALLBACK subclass_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
};
