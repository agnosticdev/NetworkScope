#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include "opt.h"
#include "utility.h"

#pragma once
enum TLSVersions {
	TLS_1_0 = 0x301,
	TLS_1_1 = 0x302,
	TLS_1_2 = 0x303,
	TLS_1_3 = 0x304
};

typedef enum TLSVersions TLSVersion;

SSL_CTX *ctx;
SSL *ssl;
BIO *bioOutput;
BIO *bio_err;

#define OSSL_PKEY_PARAM_GROUP_NAME          "group"


int attach_tls_to_descriptor(int fd, const char * version);
void print_certificate_chain(BIO *bio, SSL *s, int full);
void print_name(BIO *out, const char *title, const X509_NAME *nm,
                unsigned long lflags);
void print_ca_names(BIO *bio, SSL *s);
int ssl_print_sigalgs(BIO *out, SSL *s);
int ssl_print_tmp_key(BIO *out, SSL *s);
void ssl_print_client_cert_types(BIO *bio, SSL *s);
const char *lookup(int val, const STRINT_PAIR* list, const char* def);
int do_print_sigalgs(BIO *out, SSL *s, int shared);
const char *get_sigtype(int nid);
unsigned long get_nameopt(void);
void print_verify_detail(SSL *s, BIO *bio);
void print_tls_info(BIO *bio, SSL *s, int full);
void shut_down_tls();
char *hexencode(const unsigned char *data, size_t len);
void* app_malloc(int sz, const char *what);
void app_bail_out(char *fmt, ...);
char *opt_getprog(void);
TLSVersion decodeTLSVersion(const char *vesion);
