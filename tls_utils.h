#pragma once
#include <Windows.h>

enum RECORD_TYPE : unsigned char
{
    recordTypeChangeCipherSpec = 20,
    recordTypeAlert            = 21,
    recordTypeHandshake        = 22,
    recordTypeApplicationData  = 23,
};

enum RECORD_VERSION : unsigned short
{
    VersionTLS10 = 0x0301,
    VersionTLS11 = 0x0302,
    VersionTLS12 = 0x0303,
    VersionTLS13 = 0x0304,
 
    // Deprecated: SSLv3 is cryptographically broken
    VersionSSL30 = 0x0300
};

#pragma pack(push, 1)
struct record_layer
{
	RECORD_TYPE content_type;
	RECORD_VERSION version;
	unsigned short len;
};
#pragma pack(pop)

WORD set_console_color(WORD color = FOREGROUND_GREEN);
void restore_console_color(WORD attri);
