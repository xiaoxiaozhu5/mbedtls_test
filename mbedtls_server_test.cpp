/*
 *  SSL server demonstration program using pthread for handling multiple
 *  clients.
 *
 *  Copyright The Mbed TLS Contributors
 *  SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

//curl -vv -Sk https://localhost:4433


#include <mbedtls/platform.h>

#if !defined(MBEDTLS_ENTROPY_C) || !defined(MBEDTLS_CTR_DRBG_C) ||      \
    !defined(MBEDTLS_NET_C) || !defined(MBEDTLS_SSL_SRV_C) ||           \
    !defined(MBEDTLS_PEM_PARSE_C) || !defined(MBEDTLS_X509_CRT_PARSE_C)
int main(void)
{
    mbedtls_printf("MBEDTLS_ENTROPY_C and/or MBEDTLS_CTR_DRBG_C and/or "
                   "MBEDTLS_NET_C and/or MBEDTLS_SSL_SRV_C and/or "
                   "MBEDTLS_PEM_PARSE_C and/or MBEDTLS_X509_CRT_PARSE_C "
                   "not defined.\n");
    mbedtls_exit(0);
}
#else

#include <stdlib.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <process.h>
#include <io.h>
#endif

#include <mbedtls/entropy.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/x509.h>
#include <mbedtls/ssl.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/error.h>

#if defined(MBEDTLS_SSL_CACHE_C)
#include <mbedtls/ssl_cache.h>
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
#include <mbedtls/memory_buffer_alloc.h>
#endif

#include "memmem.h"
#include "tls_utils.h"


#define HTTP_RESPONSE \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>Mbed TLS Test Server</h2>\r\n" \
    "<p>Successful connection using: %s</p>\r\n"

#define DEBUG_LEVEL 0

#define MAX_NUM_THREADS 5

#define TLS_HEADER_LEN 5
#define TLS_HANDSHAKE_CONTENT_TYPE 0x16
#define TLS_HANDSHAKE_TYPE_CLIENT_HELLO 0x01

#define TLS_MATCH       1
#define TLS_NOMATCH     0

#define TLS_EINVAL      -1 /* Invalid parameter (NULL data pointer) */
#define TLS_ELENGTH     -2 /* Incomplete request */
#define TLS_EVERSION    -3 /* TLS version that cannot be parsed */
#define TLS_ENOEXT      -4 /* No ALPN or SNI extension found */
#define TLS_EPROTOCOL   -5 /* Protocol error */

#ifndef MIN
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
#endif

enum 
{
    PROBE_HTTP = 0,
    PROBE_HTTPS,
    PROBE_MAX
};

typedef enum {
    PROBE_NEXT,  /* Enough data, probe failed -- it's some other protocol */
    PROBE_MATCH, /* Enough data, probe successful -- it's the current protocol */
    PROBE_AGAIN, /* Not enough data for this probe, try again with more data */
} probe_result;

struct queue {
    struct mbedtls_net_context fd;
    unsigned char *begin_deferred_data;
    unsigned char *deferred_data;
    int deferred_data_size;
};

struct connection {

    /* q[0]: queue for external connection (client);
     * q[1]: queue for internal connection (httpd or sshd);
     * */
    struct queue q[2];
    struct probe_info *probe;
    void* data;
};

#if defined(_WIN32)
CRITICAL_SECTION debug_mutex;
#else
mbedtls_threading_mutex_t debug_mutex;
#endif

static void my_mutexed_debug(void *ctx, int level,
                             const char *file, int line,
                             const char *str)
{
#if defined(_WIN32)
    DWORD thread_id = GetCurrentThreadId();
#else
    long int thread_id = (long int) pthread_self();
#endif

#if defined(_WIN32)
    EnterCriticalSection(&debug_mutex);
#else
    mbedtls_mutex_lock(&debug_mutex);
#endif

    ((void) level);
    mbedtls_fprintf((FILE *) ctx, "%s:%04d: [ #%ld ] %s",
                    file, line, thread_id, str);
    fflush((FILE *) ctx);

#if defined(_WIN32)
    LeaveCriticalSection(&debug_mutex);
#else
    mbedtls_mutex_unlock(&debug_mutex);
#endif
}

typedef int (* pfn_probe)(const char* buf, int len);

static int probe_http_method(const char *p, int len, const char *opt)
{
    if (len < strlen(opt))
        return PROBE_AGAIN;

    return !strncmp(p, opt, strlen(opt));
}

static int is_http_protocol(const char* buf, int len)
{
    int res;
    /* If it's got HTTP in the request (HTTP/1.1) then it's HTTP */
    if (memmem(buf, len, "HTTP", 4))
        return PROBE_MATCH;

#define PROBE_HTTP_METHOD(opt) if ((res = probe_http_method(buf, len, opt)) != PROBE_NEXT) return res

    /* Otherwise it could be HTTP/1.0 without version: check if it's got an
     * HTTP method (RFC2616 5.1.1) */
    PROBE_HTTP_METHOD("OPTIONS");
    PROBE_HTTP_METHOD("GET");
    PROBE_HTTP_METHOD("HEAD");
    PROBE_HTTP_METHOD("POST");
    PROBE_HTTP_METHOD("PUT");
    PROBE_HTTP_METHOD("DELETE");
    PROBE_HTTP_METHOD("TRACE");
    PROBE_HTTP_METHOD("CONNECT");

#undef PROBE_HTTP_METHOD

    return PROBE_NEXT;
}

int parse_tls_header(const char *data, size_t data_len)
{
    char tls_content_type;
    char tls_version_major;
    char tls_version_minor;
    size_t pos = TLS_HEADER_LEN;
    size_t len;

    /* Check that our TCP payload is at least large enough for a TLS header */
    if (data_len < TLS_HEADER_LEN)
        return TLS_ELENGTH;

    tls_content_type = data[0];
    if (tls_content_type != TLS_HANDSHAKE_CONTENT_TYPE) {
        mbedtls_printf("Request did not begin with TLS handshake.");
        return TLS_EPROTOCOL;
    }

    tls_version_major = data[1];
    tls_version_minor = data[2];
    if (tls_version_major < 3) {
        mbedtls_printf("Received SSL %d.%d handshake which cannot be parsed.", tls_version_major, tls_version_minor);
        return TLS_EVERSION;
    }

    /* TLS record length */
    len = ((unsigned char)data[3] << 8) +
          (unsigned char)data[4] + TLS_HEADER_LEN;
    data_len = MIN(data_len, len);

    /* Check we received entire TLS record length */
    if (data_len < len)
        return TLS_ELENGTH;

    /*
     * Handshake
     */
    if (pos + 1 > data_len) {
        return TLS_EPROTOCOL;
    }
    if (data[pos] != TLS_HANDSHAKE_TYPE_CLIENT_HELLO) {
        mbedtls_printf("Not a client hello\n");
        return TLS_EPROTOCOL;
    }

    /* Skip past fixed length records:
       1	Handshake Type
       3	Length
       2	Version (again)
       32	Random
       to	Session ID Length
     */
    pos += 38;

    /* Session ID */
    if (pos + 1 > data_len)
        return TLS_EPROTOCOL;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    /* Cipher Suites */
    if (pos + 2 > data_len)
        return TLS_EPROTOCOL;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2 + len;

    /* Compression Methods */
    if (pos + 1 > data_len)
        return TLS_EPROTOCOL;
    len = (unsigned char)data[pos];
    pos += 1 + len;

    if (pos == data_len && tls_version_major == 3 && tls_version_minor == 0) {
        mbedtls_printf("Received SSL 3.0 handshake without extensions\n");
        return TLS_EVERSION;
    }

    /* Extensions */
    if (pos + 2 > data_len)
        return TLS_EPROTOCOL;
    len = ((unsigned char)data[pos] << 8) + (unsigned char)data[pos + 1];
    pos += 2;

    if (pos + len > data_len)
        return TLS_EPROTOCOL;

	return TLS_MATCH;
}

static int is_https_protocol(const char* buf, int len)
{
    switch (parse_tls_header(buf, len)) {
    case TLS_MATCH: return PROBE_MATCH;
    case TLS_NOMATCH: return PROBE_NEXT;
    case TLS_ELENGTH: return PROBE_AGAIN;
    default: return PROBE_NEXT;
    }
}

struct probe_info
{
    const char* name;
    pfn_probe probe;
    struct addrinfo* saddr;
}probes[] = 
{
    {"http", is_http_protocol, NULL},
    {"https", is_https_protocol, NULL},
    {NULL, NULL, NULL}
};

static int defer_write(struct queue *q, void* data, int data_size)
{
    unsigned char *p;
    ptrdiff_t data_offset = q->deferred_data - q->begin_deferred_data;

    p = (unsigned char*)realloc(q->begin_deferred_data, data_offset + q->deferred_data_size + data_size);
	if(p == NULL)
	{
		return -1;
	}

    q->begin_deferred_data = p;
    q->deferred_data = p + data_offset;
    p += data_offset + q->deferred_data_size;
    q->deferred_data_size += data_size;
    memcpy(p, data, data_size);

    return 0;
}

static int flush_deferred(struct queue *q)
{
    int n;

    n = mbedtls_net_send(&q->fd, (const unsigned char*)q->deferred_data, q->deferred_data_size);
    if (n == -1)
        return n;

    if (n == q->deferred_data_size) {
        free(q->begin_deferred_data);
        q->begin_deferred_data = NULL;
        q->deferred_data = NULL;
        q->deferred_data_size = 0;
    } else {
        q->deferred_data += n;
        q->deferred_data_size -= n;
    }

    return n;
}

typedef struct {
    struct connection* cnx;
    int thread_complete;
    const mbedtls_ssl_config *config;
} thread_info_t;

typedef struct {
    int active;
    thread_info_t   data;
#if defined(_WIN32)
    HANDLE          thread;
#else
    pthread_t       thread;
#endif
} pthread_info_t;

#if defined(_WIN32)
static int my_send(void *ctx, const unsigned char* buf, size_t len)
{
    struct connection *cnx = (struct connection *)ctx;
	if(len >= 5)
	{
		auto record = reinterpret_cast<record_layer*>(const_cast<unsigned char*>(buf));
		WORD attri = set_console_color();
		printf("[send]content_type:%2d ver:0x%04x len:%d\n", record->content_type, record->version, record->len);
		restore_console_color(attri);
	}
	return	mbedtls_net_send(&cnx->q[0].fd, buf, len);
}

static int my_recv(void *ctx, unsigned char* buf, size_t len)
{
    struct connection *cnx = (struct connection *)ctx;

    int n = 0;
    struct queue *q = &cnx->q[1];
    if (q->deferred_data && q->deferred_data_size)
    {
        if (q->deferred_data_size >= len)
        {
            memcpy(buf, q->deferred_data, len);
            n = len;
            q->deferred_data_size -= n;
            q->deferred_data += n;
            if (0 == q->deferred_data_size) {
                free(q->begin_deferred_data);
                q->begin_deferred_data = NULL;
                q->deferred_data = NULL;
                q->deferred_data_size = 0;
            }
        }
        return n;
    }

	if(len >= 5)
	{
		auto record = reinterpret_cast<record_layer*>(buf);
		WORD attri = set_console_color(FOREGROUND_BLUE);
		printf("[recv]content_type:%2d ver:0x%04x len:%d\n", record->content_type, record->version, record->len);
		restore_console_color(attri);
	}
	return mbedtls_net_recv(&cnx->q[0].fd, buf, len);
}
#endif

static thread_info_t    base_info;
static pthread_info_t   threads[MAX_NUM_THREADS];

#ifdef _MSC_VER
UINT WINAPI handle_ssl_connection(LPVOID data)
#else
static void *handle_ssl_connection(void *data)
#endif
{
    int ret, len;
    thread_info_t *thread_info = (thread_info_t *) data;
    struct connection *cnx = thread_info->cnx;
#if defined(_WIN32)
    DWORD thread_id = GetCurrentThreadId();
#else
    long int thread_id = (long int) pthread_self();
#endif
    unsigned char buf[1024];
    mbedtls_ssl_context ssl;

    /* Make sure memory references are valid */
    mbedtls_ssl_init(&ssl);

    mbedtls_printf("  [ #%ld ]  Setting up SSL/TLS data\n", thread_id);

    /*
     * 4. Get the SSL context ready
     */
    if ((ret = mbedtls_ssl_setup(&ssl, thread_info->config)) != 0) {
        mbedtls_printf("  [ #%ld ]  failed: mbedtls_ssl_setup returned -0x%04x\n",
                       thread_id, (unsigned int) -ret);
        goto thread_exit;
    }

#if defined(_WIN32)
    mbedtls_ssl_set_bio(&ssl, cnx, my_send, my_recv, NULL);
#else
    mbedtls_ssl_set_bio(&ssl, client_fd, mbedtls_net_send, mbedtls_net_recv, NULL);
#endif

    /*
     * 5. Handshake
     */
    mbedtls_printf("  [ #%ld ]  Performing the SSL/TLS handshake\n", thread_id);
    fflush(stdout);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("  [ #%ld ]  failed: mbedtls_ssl_handshake returned -0x%04x\n",
                           thread_id, (unsigned int) -ret);
            goto thread_exit;
        }
    }

    mbedtls_printf("  [ #%ld ]  ok\n", thread_id);

    /*
     * 6. Read the HTTP Request
     */
    mbedtls_printf("  [ #%ld ]  < Read from client\n", thread_id);
    fflush(stdout);

    do {
        len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        ret = mbedtls_ssl_read(&ssl, buf, len);

        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret <= 0) {
            switch (ret) {
                case MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY:
                    mbedtls_printf("  [ #%ld ]  connection was closed gracefully\n",
                                   thread_id);
                    goto thread_exit;

                case MBEDTLS_ERR_NET_CONN_RESET:
                    mbedtls_printf("  [ #%ld ]  connection was reset by peer\n",
                                   thread_id);
                    goto thread_exit;

                default:
                    mbedtls_printf("  [ #%ld ]  mbedtls_ssl_read returned -0x%04x\n",
                                   thread_id, (unsigned int) -ret);
                    goto thread_exit;
            }
        }

        len = ret;
        mbedtls_printf("  [ #%ld ]  %d bytes read\n=====\n%s\n=====\n",
                       thread_id, len, (char *) buf);
        fflush(stdout);

        if (ret > 0) {
            break;
        }
    } while (1);

    /*
     * 7. Write the 200 Response
     */
    mbedtls_printf("  [ #%ld ]  > Write to client:\n", thread_id);
    fflush(stdout);

    len = snprintf((char *)buf, sizeof(buf), HTTP_RESPONSE,
                  mbedtls_ssl_get_ciphersuite(&ssl));

    while ((ret = mbedtls_ssl_write(&ssl, buf, len)) <= 0) {
        if (ret == MBEDTLS_ERR_NET_CONN_RESET) {
            mbedtls_printf("  [ #%ld ]  failed: peer closed the connection\n",
                           thread_id);
            goto thread_exit;
        }

        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("  [ #%ld ]  failed: mbedtls_ssl_write returned -0x%04x\n",
                           thread_id, (unsigned int) ret);
            goto thread_exit;
        }
    }

    len = ret;
    mbedtls_printf("  [ #%ld ]  %d bytes written\n=====\n%s\n=====\n",
                   thread_id, len, (char *) buf);
    fflush(stdout);

    mbedtls_printf("  [ #%ld ]  . Closing the connection...\n", thread_id);

    while ((ret = mbedtls_ssl_close_notify(&ssl)) < 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ &&
            ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            mbedtls_printf("  [ #%ld ]  failed: mbedtls_ssl_close_notify returned -0x%04x\n",
                           thread_id, (unsigned int) ret);
            goto thread_exit;
        }
    }

    mbedtls_printf(" ok\n");
    fflush(stdout);

    ret = 0;

thread_exit:

#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("  [ #%ld ]  Last error was: -0x%04x - %s\n\n",
                       thread_id, (unsigned int) -ret, error_buf);
    }
#endif
	if (cnx->q[1].begin_deferred_data && cnx->q[1].deferred_data_size)
	{
		free(cnx->q[1].begin_deferred_data);
	}
    mbedtls_net_free(&cnx->q[0].fd);
    mbedtls_ssl_free(&ssl);
    free(cnx);

    thread_info->thread_complete = 1;

    return NULL;
}

static int thread_create(struct connection* cnx)
{
    int ret, i;

    /*
     * Find in-active or finished thread slot
     */
    for (i = 0; i < MAX_NUM_THREADS; i++) {
        if (threads[i].active == 0) {
            break;
        }

        if (threads[i].data.thread_complete == 1) {
            mbedtls_printf("  [ main ]  Cleaning up thread %d\n", i);
#if defined(_WIN32)
            WaitForSingleObject(threads[i].thread, INFINITE);
#else
            pthread_join(threads[i].thread, NULL);
#endif
            memset(&threads[i], 0, sizeof(pthread_info_t));
            break;
        }
    }

    if (i == MAX_NUM_THREADS) {
        return -1;
    }

    /*
     * Fill thread-info for thread
     */
    memcpy(&threads[i].data, &base_info, sizeof(base_info));
    threads[i].active = 1;
    threads[i].data.cnx = cnx;

#if defined(_WIN32)
    threads[i].thread = (HANDLE)_beginthreadex(NULL, 0, handle_ssl_connection, &threads[i].data, 0, NULL);
#else
    if ((ret = pthread_create(&threads[i].thread, NULL, handle_ssl_connection,
                              &threads[i].data)) != 0) {
        return ret;
    }
#endif

    return 0;
}

static int probe_buffer(char* buf, int len, struct probe_info* probe_in, int probe_len, struct probe_info** probe_out)
{
  *probe_out = 0;
  int res = 0, again = 0;
  struct probe_info* p;
  for(int i = 0; i < probe_len; ++i)
  {
    p = &probe_in[i];
    if(!p)
    {
        continue;
    }
    res = p->probe(buf, len);
    if(res == PROBE_MATCH)
    {
        *probe_out = p;
        return PROBE_MATCH;
    }
    if(res == PROBE_AGAIN)
    {
        again++;
    }
  }
  if(again)
  {
    return PROBE_AGAIN;
  }
  *probe_out = &probe_in[probe_len-1];
  return PROBE_MATCH;
}

static int probe_client_data(struct connection *cnx)
{
    unsigned char buffer[BUFSIZ];
    SSIZE_T n;

    n = mbedtls_net_recv(&cnx->q[0].fd, buffer, sizeof(buffer));
    if (n > 0) {
        defer_write(&cnx->q[1], buffer, n);
        return probe_buffer((char*)cnx->q[1].begin_deferred_data,
                        cnx->q[1].deferred_data_size, 
                        probes, 
                        PROBE_MAX, 
                        &cnx->probe);
    }

    cnx->probe = &probes[PROBE_MAX-1];
    return PROBE_MATCH;
}

int main(void)
{
    int ret;
	int res = PROBE_AGAIN;
    mbedtls_net_context listen_fd, client_fd;
    const char pers[] = "ssl_pthread_server";
    struct connection* cnx = NULL;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_ssl_config conf;
    mbedtls_x509_crt srvcert;
    mbedtls_x509_crt cachain;
    mbedtls_pk_context pkey;
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    unsigned char alloc_buf[100000];
#endif
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_context cache;
#endif

#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_init(alloc_buf, sizeof(alloc_buf));
#endif

#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_init(&cache);
#endif

    mbedtls_x509_crt_init(&srvcert);
    mbedtls_x509_crt_init(&cachain);

    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    memset(threads, 0, sizeof(threads));
    mbedtls_net_init(&listen_fd);
    mbedtls_net_init(&client_fd);

#if defined(_WIN32)
    InitializeCriticalSection(&debug_mutex);
#else
    mbedtls_mutex_init(&debug_mutex);
#endif

    base_info.config = &conf;

    /*
     * We use only a single entropy source that is used in all the threads.
     */
    mbedtls_entropy_init(&entropy);

#if defined(MBEDTLS_USE_PSA_CRYPTO)
    psa_status_t status = psa_crypto_init();
    if (status != PSA_SUCCESS) {
        mbedtls_fprintf(stderr, "Failed to initialize PSA Crypto implementation: %d\n",
                        (int) status);
        ret = MBEDTLS_ERR_SSL_HW_ACCEL_FAILED;
        goto exit;
    }
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    /*
     * 1a. Seed the random number generator
     */
    mbedtls_printf("  . Seeding the random number generator...");

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *) pers,
                                     strlen(pers))) != 0) {
        mbedtls_printf(" failed: mbedtls_ctr_drbg_seed returned -0x%04x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 1b. Load the certificates and private RSA key
     */
    mbedtls_printf("\n  . Loading the server cert. and key...");
    fflush(stdout);

#if defined(_WIN32)
    CHAR szCurrentPath[MAX_PATH];
    GetModuleFileNameA(NULL, szCurrentPath, MAX_PATH);
    strrchr(szCurrentPath, '\\')[1] = '\0';
#else
	char szCurrentPath[1024] = {0};
    int retval = readlink("/proc/self/exe", szCurrentPath, sizeof(szCurrentPath)-1);
    if (retval > 0)
    {
        szCurrentPath[retval] = '\0';
        char* end = strrchr(szCurrentPath, '/');
        if (NULL == end)
            szCurrentPath[0] = 0;
        else
            *end = '\0';
    }
#endif

    char tmp[1024];
    snprintf(tmp, 1024, "%s%s", szCurrentPath, "server.crt");
    /*
     * This demonstration program uses embedded test certificates.
     * Instead, you may want to use mbedtls_x509_crt_parse_file() to read the
     * server and CA certificates, as well as mbedtls_pk_parse_keyfile().
     */
    ret = mbedtls_x509_crt_parse_file(&srvcert, tmp);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_x509_crt_parse_file returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_pk_init(&pkey);
    snprintf(tmp, 1024, "%s%s", szCurrentPath, "server.key");
    ret =  mbedtls_pk_parse_keyfile(&pkey, tmp, NULL);
    if (ret != 0) {
        mbedtls_printf(" failed\n  !  mbedtls_pk_parse_keyfile returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 1c. Prepare SSL configuration
     */
    mbedtls_printf("  . Setting up the SSL data....");

    if ((ret = mbedtls_ssl_config_defaults(&conf,
                                           MBEDTLS_SSL_IS_SERVER,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        mbedtls_printf(" failed: mbedtls_ssl_config_defaults returned -0x%04x\n",
                       (unsigned int) -ret);
        goto exit;
    }

    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);
    mbedtls_ssl_conf_dbg(&conf, my_mutexed_debug, stdout);

    /* mbedtls_ssl_cache_get() and mbedtls_ssl_cache_set() are thread-safe if
     * MBEDTLS_THREADING_C is set.
     */
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_conf_session_cache(&conf, &cache,
                                   mbedtls_ssl_cache_get,
                                   mbedtls_ssl_cache_set);
#endif

    mbedtls_ssl_conf_ca_chain(&conf, &cachain, NULL);
    if ((ret = mbedtls_ssl_conf_own_cert(&conf, &srvcert, &pkey)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_ssl_conf_own_cert returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

    /*
     * 2. Setup the listening TCP socket
     */
    mbedtls_printf("  . Bind on https://localhost:4433/ ...");
    fflush(stdout);

    if ((ret = mbedtls_net_bind(&listen_fd, NULL, "4433", MBEDTLS_NET_PROTO_TCP)) != 0) {
        mbedtls_printf(" failed\n  ! mbedtls_net_bind returned %d\n\n", ret);
        goto exit;
    }

    mbedtls_printf(" ok\n");

reset:
#ifdef MBEDTLS_ERROR_C
    if (ret != 0) {
        char error_buf[100];
        mbedtls_strerror(ret, error_buf, 100);
        mbedtls_printf("  [ main ]  Last error was: -0x%04x - %s\n", (unsigned int) -ret,
                       error_buf);
    }
#endif

    /*
     * 3. Wait until a client connects
     */
    mbedtls_printf("  [ main ]  Waiting for a remote connection\n");
    fflush(stdout);

    if ((ret = mbedtls_net_accept(&listen_fd, &client_fd,
                                  NULL, 0, NULL)) != 0) {
        mbedtls_printf("  [ main ] failed: mbedtls_net_accept returned -0x%04x\n",
                       (unsigned int) ret);
        goto exit;
    }

    cnx = (struct connection*)malloc(sizeof(struct connection));
	memset(cnx, 0, sizeof(struct connection));

    struct timeval tv;
    fd_set fds;
    FD_ZERO(&fds);
    FD_SET(client_fd.fd, &fds);
	memset(&tv, 0, sizeof(tv));
    tv.tv_sec = 1;

    cnx->q[0].fd = client_fd;
    while (res == PROBE_AGAIN)
    {
	   res = select(client_fd.fd+1, &fds, NULL, NULL, &tv); 
       if (res == -1)
       {
       	   mbedtls_printf("  [ main ]  select failed\n");
	       break;
       }
       if (FD_ISSET(client_fd.fd, &fds))
       {
       	   res = probe_client_data(cnx); 
       }
       else
       {
	       continue;
       }
    }

    if (strlen(cnx->probe->name) == 4)
    {
		mbedtls_printf("  [ main ]  http procotol, not https protocol\n");
		ret = 0;
		res = PROBE_AGAIN;
        if (cnx->q[1].deferred_data && cnx->q[1].deferred_data_size)
        {
	       free(cnx->q[1].begin_deferred_data); 
        }
        mbedtls_net_free(&client_fd);
        free(cnx);
        goto reset;
    }
    else if (strlen(cnx->probe->name) == 5)
    {
		mbedtls_printf("  [ main ]  https procotol\n");
    }

    mbedtls_printf("  [ main ]  ok, Creating a new thread\n");

    if ((ret = thread_create(cnx)) != 0) {
        mbedtls_printf("  [ main ]  failed: thread_create returned %d\n", ret);
		ret = 0;
		res = PROBE_AGAIN;
        if (cnx->q[1].deferred_data && cnx->q[1].deferred_data_size)
        {
	       free(cnx->q[1].begin_deferred_data); 
        }
        mbedtls_net_free(&client_fd);
        free(cnx);
        goto reset;
    }

    ret = 0;
    res = PROBE_AGAIN;
    goto reset;

exit:
    mbedtls_x509_crt_free(&srvcert);
    mbedtls_pk_free(&pkey);
#if defined(MBEDTLS_SSL_CACHE_C)
    mbedtls_ssl_cache_free(&cache);
#endif
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
    mbedtls_ssl_config_free(&conf);
    mbedtls_net_free(&listen_fd);
#if defined(_WIN32)
    DeleteCriticalSection(&debug_mutex);
#else
    mbedtls_mutex_free(&debug_mutex);
#endif
#if defined(MBEDTLS_MEMORY_BUFFER_ALLOC_C)
    mbedtls_memory_buffer_alloc_free();
#endif
#if defined(MBEDTLS_USE_PSA_CRYPTO)
    mbedtls_psa_crypto_free();
#endif /* MBEDTLS_USE_PSA_CRYPTO */

    mbedtls_exit(ret);
}

#endif
