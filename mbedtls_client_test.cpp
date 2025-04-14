// mbedtls_test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <Windows.h>

#include <iostream>

#include <mbedtls/error.h>
#include <mbedtls/ssl.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/net.h>

#include "tls_utils.h"

#define HOST_TO_CONNECT "github.com"

int handle_data(char* data, size_t sz)
{
	printf("%.*s\n", sz, data);
	return 0;
}

static int my_send(void *ctx, const unsigned char* buf, size_t len)
{
	if(len >= 5)
	{
		auto record = reinterpret_cast<record_layer*>(const_cast<unsigned char*>(buf));
		WORD attri = set_console_color();
		printf("[send]content_type:%2d ver:0x%04x len:%d\n", record->content_type, record->version, record->len);
		restore_console_color(attri);
	}
	return	mbedtls_net_send(ctx, buf, len);
}

static int my_recv(void *ctx, unsigned char* buf, size_t len)
{
	if(len >= 5)
	{
		auto record = reinterpret_cast<record_layer*>(buf);
		WORD attri = set_console_color(FOREGROUND_BLUE);
		printf("[recv]content_type:%2d ver:0x%04x len:%d\n", record->content_type, record->version, record->len);
		restore_console_color(attri);
	}
	return mbedtls_net_recv(ctx, buf, len);
}

int main1()
{
	bool use_ca = false;

	//step 1. initialize random generator
	mbedtls_ctr_drbg_context drbg_ctx;
	mbedtls_entropy_context entropy_ctx;

	mbedtls_ctr_drbg_init(&drbg_ctx);
	mbedtls_entropy_init(&entropy_ctx);

	auto rc = mbedtls_ctr_drbg_seed(&drbg_ctx, mbedtls_entropy_func, &entropy_ctx, nullptr, 0);
	if (0 != rc)
	{
		std::cout << "mbedtls_ctr_drbg_seed failed:" << rc << std::endl;
		exit(1);
	}

	//step 2. initialize net, ssl and crt context
	mbedtls_net_context net_ctx;
	mbedtls_ssl_context ssl_ctx;
	mbedtls_ssl_config ssl_config;
	mbedtls_x509_crt crt_ctx;
	mbedtls_net_init(&net_ctx);
	mbedtls_ssl_init(&ssl_ctx);
	mbedtls_x509_crt_init(&crt_ctx);
	mbedtls_ssl_config_init(&ssl_config);

	//step 2.1 ssl configuration
	rc = mbedtls_ssl_config_defaults(&ssl_config, MBEDTLS_SSL_IS_CLIENT, MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
	if (0 != rc)
	{
		std::cout << "mbedtls_ssl_config_defaults failed:" << rc << std::endl;
		exit(1);
	}
	mbedtls_ssl_conf_authmode(&ssl_config, MBEDTLS_SSL_VERIFY_NONE);
	mbedtls_ssl_conf_rng(&ssl_config, mbedtls_ctr_drbg_random, &drbg_ctx);
	mbedtls_ssl_conf_min_version(&ssl_config, MBEDTLS_SSL_MAJOR_VERSION_3, MBEDTLS_SSL_MINOR_VERSION_3);

	//step 3. make a connection
	rc = mbedtls_net_connect(&net_ctx, HOST_TO_CONNECT, "443", MBEDTLS_NET_PROTO_TCP);
	if (0 != rc)
	{
		std::cout << "mbedtls_net_connect failed:" << rc << std::endl;
		exit(1);
	}

	if (use_ca)
	{
		mbedtls_ssl_conf_authmode(&ssl_config, MBEDTLS_SSL_VERIFY_REQUIRED);
	}

	rc = mbedtls_ssl_setup(&ssl_ctx, &ssl_config);
	if (0 != rc)
	{
		std::cout << "mbedtls_ssl_setup failed:" << rc << std::endl;
		exit(1);
	}

	if (use_ca)
	{
		mbedtls_ssl_set_hostname(&ssl_ctx, HOST_TO_CONNECT);
	}

	//mbedtls_ssl_set_bio(&ssl_ctx, &net_ctx, mbedtls_net_send, mbedtls_net_recv, nullptr);
	mbedtls_ssl_set_bio(&ssl_ctx, &net_ctx, my_send, my_recv, nullptr);

	//setp 3.1 handshake
	bool handshake_result = true;
	while ((rc = mbedtls_ssl_handshake(&ssl_ctx)) != 0)
	{
		if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE)
		{
			std::cout << "handshake failed:" << rc << std::endl;
			handshake_result = false;
			if (use_ca)
			{
				rc = mbedtls_ssl_get_verify_result(&ssl_ctx);
				if (0 != rc)
				{
					char szInfo[250];
					mbedtls_x509_crt_verify_info(szInfo, sizeof(szInfo), nullptr, rc);
					std::cout << "server cert: " << szInfo << std::endl;
				}
			}
			break;
		}

	}

	if (!handshake_result)
	{
		exit(1);
	}

	std::string get_hdr = "GET / HTTP/1.1\r\n"
		"Host: " HOST_TO_CONNECT "\r\n"
		"User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36\r\n"
		"Accept: */*\r\n\r\n";
	rc = mbedtls_ssl_write(&ssl_ctx, (const unsigned char*)get_hdr.c_str(), get_hdr.size());
	if (0 > rc)
	{
		std::cout << "write error: " << rc << std::endl;
	}

	char buf[65535] = { 0 };
	while (true)
	{
		rc = mbedtls_net_poll(&net_ctx, MBEDTLS_NET_POLL_READ, 300);
		if (0 == rc)
			continue;
		if (0 > rc)
		{
			std::cout << "net poll eror:" << rc << std::endl;
			break;
		}

		if (MBEDTLS_NET_POLL_READ == rc)
		{
			rc = mbedtls_ssl_read(&ssl_ctx, (unsigned char*)buf, sizeof(buf));
			if (rc == MBEDTLS_ERR_SSL_WANT_READ || rc == MBEDTLS_ERR_SSL_WANT_WRITE)
				continue;
			if (0 == rc)
			{
				std::cout << "server close link\n";
				break;
			}
			if (0 > rc)
			{
				std::cout << "ssl_read failed:" << rc << std::endl;
				break;
			}

			rc = handle_data(buf, rc);
		}
	}

	mbedtls_net_free(&net_ctx);
	mbedtls_x509_crt_free(&crt_ctx);
	mbedtls_ssl_free(&ssl_ctx);
	mbedtls_ssl_config_free(&ssl_config);

	mbedtls_ctr_drbg_free(&drbg_ctx);
	mbedtls_entropy_free(&entropy_ctx);
}

// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
