#pragma once

#include <windows.h>

struct content_panel {
	virtual ~content_panel() = default;

	virtual HWND hwnd() const = 0;

	virtual void show() = 0;
	virtual void hide() = 0;
	virtual bool is_visible() const = 0;

	virtual void set_text(const wchar_t *text) = 0;
	virtual void clear() = 0;

	virtual void measure(HDC hdc, int max_width) = 0;
	virtual RECT desired_rect() const = 0;
	virtual void set_position(int x, int y, int w, int h) = 0;

	virtual void set_font(HFONT font) = 0;
};
