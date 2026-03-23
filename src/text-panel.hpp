#pragma once

#include "content-panel.hpp"
#include <commctrl.h>

struct text_panel : public content_panel {
	text_panel(HWND parent, int x, int y, int w, int h, const wchar_t *label);
	~text_panel() override;

	text_panel(const text_panel &) = delete;
	text_panel &operator=(const text_panel &) = delete;

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

private:
	HWND hwnd_{NULL};
	RECT rect_{0};

	static LRESULT CALLBACK subclass_proc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam, UINT_PTR uIdSubclass, DWORD_PTR dwRefData);
};
