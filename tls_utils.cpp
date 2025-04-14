#include "tls_utils.h"

WORD set_console_color(WORD color)
{
	HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
	WORD wOldColorAttrs;
	CONSOLE_SCREEN_BUFFER_INFO csbiInfo;

	// Save the current color
	GetConsoleScreenBufferInfo(h, &csbiInfo);
	wOldColorAttrs = csbiInfo.wAttributes;

	// Set the new color
	SetConsoleTextAttribute(h, color | FOREGROUND_INTENSITY);
	return wOldColorAttrs;
}

void restore_console_color(WORD attri)
{
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), attri);
}

