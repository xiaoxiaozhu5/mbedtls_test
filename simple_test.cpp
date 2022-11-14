#include <iostream>
#include <Windows.h>
#include <mbedtls/net.h>
#include <mbedtls/gcm.h>

void close_handle(HANDLE handle)
{
	if (handle && handle != INVALID_HANDLE_VALUE)
	{
		::CloseHandle(handle);
	}
}
BOOL WriteBufferToFile(const std::wstring& path, const PBYTE content, DWORD content_len)
{
    std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&close_handle)> file_handle{ CreateFile(path.c_str(), GENERIC_WRITE, FILE_SHARE_READ, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr), &close_handle };
    if (file_handle.get() == INVALID_HANDLE_VALUE)
    {
		printf("%S open failed:%d\n", path.c_str(), GetLastError());
        return false;
    }
    DWORD dwWrite = 0;
    return WriteFile(file_handle.get(), content, content_len, &dwWrite, nullptr);
}
std::string ReadFileToBuffer(const std::wstring& path)
{
    std::string file_content;
	std::unique_ptr<std::remove_pointer_t<HANDLE>, decltype(&close_handle)> file_handle{ CreateFile(path.c_str(), GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr), &close_handle };
	if (file_handle.get() == INVALID_HANDLE_VALUE)
	{
		printf("%S open failed:%d\n", path.c_str(), GetLastError());
        return file_content;
	}
	DWORD file_size = 0;
	file_size = GetFileSize(file_handle.get(), nullptr);
	if (file_size == INVALID_FILE_SIZE)
	{
		printf("%S invalid size:%d\n", path.c_str(), GetLastError());
        return file_content;
	}
	file_content.resize(file_size);
	DWORD file_read = 0;
	if (!ReadFile(file_handle.get(), (char*)file_content.data(), file_size, &file_read, nullptr))
	{
		printf("%S read failed:%d\n", path.c_str(), GetLastError());
        return file_content;
	}
    return file_content;
}

void aes_gcm_test()
{
	auto key = ReadFileToBuffer(L"key.bin");
	auto iv = ReadFileToBuffer(L"iv.bin");
	auto add = ReadFileToBuffer(L"add.bin");
	auto tag = ReadFileToBuffer(L"stag.bin");
	auto input = ReadFileToBuffer(L"msg.bin");
	if(key.empty() || iv.empty() || add.empty() || tag.empty() || input.empty())
	{
		printf("not all file exists\n");
		return;
	}
	size_t input_len = input.size();
	char* output = new char[input_len];
	memset(output, 0, input_len);

	int ret = 0;
	mbedtls_gcm_context aes;	
	mbedtls_gcm_init( &aes );
	ret = mbedtls_gcm_setkey(&aes, MBEDTLS_CIPHER_ID_AES, (const unsigned char*)key.c_str(), 128);
	if(ret != 0)
	{
		printf("set key failed:%x\n", 0 - ret);
		return;
	}
	ret = mbedtls_gcm_auth_decrypt(&aes, input_len, (const unsigned char*)iv.c_str(), 12, (const unsigned char*)add.c_str(), 5, (const unsigned char*)tag.c_str(), 16, (const unsigned char*)input.c_str(), (unsigned char*)output);
	if(ret != 0)
	{
		printf("decrypt failed:%x\n", 0 - ret);
		return;
	}
	WriteBufferToFile(L"output.bin", (PBYTE)output, input_len);
	mbedtls_gcm_free(&aes);
}


int main(int argc, char* argv[])
{
	aes_gcm_test();
	if(argc != 3)
	{
		std::cout << argv[0] << " server port\n";
		return 1;
	}

	int ret = 0;
	mbedtls_net_context net_ctx;
	mbedtls_net_init(&net_ctx);

	ret = mbedtls_net_connect(&net_ctx, argv[1], argv[2], MBEDTLS_NET_PROTO_TCP);
	if(0 != ret)
	{
		std::cout << "connect to " << argv[1] << " failed:" << std::hex << ret << std::endl;
		return 1;
	}

	do
	{
		ret = mbedtls_net_poll(&net_ctx, MBEDTLS_NET_POLL_READ, 10000);
		if(ret <= 0)
		{
			std::cout << "poll failed:" << std::hex << ret << std::endl; 
			break;
		}
		char tmp[2048] = {0};
		ret = mbedtls_net_recv(&net_ctx, (unsigned char*)tmp, sizeof(tmp));
		if(0 > ret)
		{
			std::cout << "recv failed:" << std::hex << ret << std::endl;
			break;
		}
		std::cout << tmp << std::endl;
	}while (true);

	mbedtls_net_close(&net_ctx);
	mbedtls_net_free(&net_ctx);
	return 0;
}
