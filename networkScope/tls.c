#include "tls.h"


static int c_showcerts = 1;
static unsigned long nmflag = 0;
static char nmflag_set = 0;
static char prog[40];
static char *keymatexportlabel = NULL;
static int keymatexportlen = 20;

static STRINT_PAIR cert_type_list[] = {
    {"RSA sign", TLS_CT_RSA_SIGN},
    {"DSA sign", TLS_CT_DSS_SIGN},
    {"RSA fixed DH", TLS_CT_RSA_FIXED_DH},
    {"DSS fixed DH", TLS_CT_DSS_FIXED_DH},
    {"ECDSA sign", TLS_CT_ECDSA_SIGN},
    {"RSA fixed ECDH", TLS_CT_RSA_FIXED_ECDH},
    {"ECDSA fixed ECDH", TLS_CT_ECDSA_FIXED_ECDH},
    {"GOST01 Sign", TLS_CT_GOST01_SIGN},
    {"GOST12 Sign", TLS_CT_GOST12_IANA_SIGN},
    {NULL}
};



// Attach TLS to the file descriptor.
int attach_tls_to_descriptor(int fd, const char * version) {

	printf("-------------- START OF TLS ------------------\n");

	int attachedTLSSuccessfully = 0;

	TLSVersion tlsVersion = decodeTLSVersion(version);
	printf("TLS Version: %x\n", tlsVersion);

	SSL_library_init();

	/* Open TLS Connection */

	/* TODO Alter to be dynamic */
	OpenSSL_add_all_algorithms();


	//ERR_load_BIO_strings();
	ERR_load_crypto_strings();
	SSL_load_error_strings();

	bioOutput = BIO_new_fp(stdout, BIO_NOCLOSE);

    /*
     * 1. Make TLS version dynamic.
     * 2. Clean up code in this file or trim it down.
     */


	/* TODO Alter to be dynamic */
	//SSL_METHOD *method = TLSv1_2_client_method(); // This is deprecrated
	const SSL_METHOD *method = TLS_client_method();


	ctx = SSL_CTX_new(method);
	if (ctx == NULL) {
		printf("Error creating SSL_CTX");
		ERR_print_errors_fp(stderr);
		return attachedTLSSuccessfully;
	}

	ssl = SSL_new(ctx);
	SSL_set_fd(ssl, fd);

	int sslConnectStatus = SSL_connect(ssl);
	if (sslConnectStatus == -1) {
		printf("Error running SSL_connect on SSL_CTX: %d", sslConnectStatus);
		ERR_print_errors_fp(stderr);
		return attachedTLSSuccessfully;
	}

	X509 *leafCertificate = SSL_get_peer_certificate(ssl);
	if (leafCertificate != NULL) {
		printf("Server Certificate(s):\n");
		char *out;
		out = X509_NAME_oneline(X509_get_subject_name(leafCertificate), 0, 0);
		printf("Leaf Subject: %s\n", out);
		free(out);
		out = X509_NAME_oneline(X509_get_issuer_name(leafCertificate), 0, 0);
        printf("Leaf Issuer: %s\n", out);
        free(out);
        X509_free(leafCertificate);
        attachedTLSSuccessfully = 1;


        print_tls_info(bioOutput, ssl, 1);
	} else {
		printf("Error getting client certificates \n");
	}
	return attachedTLSSuccessfully;
}

void shut_down_tls() {
	printf("Shutting down TLS\n");
	SSL_free(ssl);
	SSL_CTX_free(ctx); 
}

/*
 * Code brought into the project for printing out the certificate chain.
 * Consider moving all of this code into a certificate chain file.
 * 
 */
void print_tls_info(BIO *bio, SSL *s, int full) {

	X509 *peer = NULL;
    STACK_OF(X509) *sk;
    const SSL_CIPHER *c;
    const COMP_METHOD *comp, *expansion;
    EVP_PKEY *public_key;
    int i, istls13 = (SSL_version(s) == TLS1_3_VERSION);
    long verify_result;
    unsigned char *exportedkeymat;
    int got_a_chain = 0;

    sk = SSL_get_peer_cert_chain(s);
    if (sk != NULL) {
        got_a_chain = 1;

        BIO_printf(bio, "---\nCertificate chain\n");
        for (i = 0; i < sk_X509_num(sk); i++) {
            BIO_printf(bio, "%2d s:", i);
            X509_NAME_print_ex(bio, X509_get_subject_name(sk_X509_value(sk, i)), 0, get_nameopt());
            BIO_puts(bio, "\n");
            BIO_printf(bio, "   i:");
            X509_NAME_print_ex(bio, X509_get_issuer_name(sk_X509_value(sk, i)), 0, get_nameopt());
            BIO_puts(bio, "\n");
            public_key = X509_get_pubkey(sk_X509_value(sk, i));
            if (public_key != NULL) {
                BIO_printf(bio, "   a:PKEY: %s, %d (bit); sigalg: %s\n",
                           OBJ_nid2sn(EVP_PKEY_base_id(public_key)),
                           EVP_PKEY_bits(public_key),
                           OBJ_nid2sn(X509_get_signature_nid(sk_X509_value(sk, i))));
                EVP_PKEY_free(public_key);
            }
            BIO_printf(bio, "   v:NotBefore: ");
            ASN1_TIME_print(bio, X509_get0_notBefore(sk_X509_value(sk, i)));
            BIO_printf(bio, "; NotAfter: ");
            ASN1_TIME_print(bio, X509_get0_notAfter(sk_X509_value(sk, i)));
            BIO_puts(bio, "\n");
            if (c_showcerts)
                PEM_write_bio_X509(bio, sk_X509_value(sk, i));
        }
    }

    BIO_printf(bio, "---\n");
    peer = SSL_get0_peer_certificate(s);
    if (peer != NULL) {
        BIO_printf(bio, "Server certificate\n");

        /* Redundant if we showed the whole chain */
        if (!(c_showcerts && got_a_chain))
            PEM_write_bio_X509(bio, peer);
        print_name(bio, "subject=", X509_get_subject_name(peer), get_nameopt());
	    BIO_puts(bio, "\n");
	    print_name(bio, "issuer=", X509_get_issuer_name(peer), get_nameopt());
	    BIO_puts(bio, "\n");
    } else {
        BIO_printf(bio, "no peer certificate available\n");
    }
    print_ca_names(bio, s);

    ssl_print_sigalgs(bio, s);
    ssl_print_tmp_key(bio, s);

    // Get embedded SCTs on the 
    const STACK_OF(SCT) *scts = SSL_get0_peer_scts(s);
    int sct_count = scts != NULL ? sk_SCT_num(scts) : 0;

    if (sct_count > 0) {
	    BIO_printf(bio, "---\nSCTs present (%i)\n", sct_count);
	    if (sct_count > 0) {
	        const CTLOG_STORE *log_store = SSL_CTX_get0_ctlog_store(ctx);

	        BIO_printf(bio, "---\n");
	        for (i = 0; i < sct_count; ++i) {
	            SCT *sct = sk_SCT_value(scts, i);

	            BIO_printf(bio, "SCT validation status: %s\n",
	                       SCT_validation_status_string(sct));
	            SCT_print(sct, bio, 0, log_store);
	            if (i < sct_count - 1)
	                BIO_printf(bio, "\n---\n");
	        }
	        BIO_printf(bio, "\n");
	    }
	}

	BIO_printf(bio,
                   "---\nSSL handshake has read %ju bytes "
                   "and written %ju bytes\n",
                   BIO_number_read(SSL_get_rbio(s)),
                   BIO_number_written(SSL_get_wbio(s)));


	print_verify_detail(s, bio);
    BIO_printf(bio, (SSL_session_reused(s) ? "---\nReused, " : "---\nNew, "));
    c = SSL_get_current_cipher(s);
    BIO_printf(bio, "%s, Cipher is %s\n",
               SSL_CIPHER_get_version(c), SSL_CIPHER_get_name(c));
    if (peer != NULL) {
        EVP_PKEY *pktmp;

        pktmp = X509_get0_pubkey(peer);
        BIO_printf(bio, "Server public key is %d bit\n",
                   EVP_PKEY_bits(pktmp));
    }
    BIO_printf(bio, "Secure Renegotiation IS%s supported\n",
               SSL_get_secure_renegotiation_support(s) ? "" : " NOT");

    // Compression / Expansion
    comp = SSL_get_current_compression(s);
    expansion = SSL_get_current_expansion(s);
    BIO_printf(bio, "Compression: %s\n",
               comp ? SSL_COMP_get_name(comp) : "NONE");
    BIO_printf(bio, "Expansion: %s\n",
               expansion ? SSL_COMP_get_name(expansion) : "NONE");

    // ALPN protocol
    const unsigned char *proto;
    unsigned int proto_len;
    SSL_get0_alpn_selected(s, &proto, &proto_len);
    if (proto_len > 0) {
        BIO_printf(bio, "ALPN protocol: ");
        BIO_write(bio, proto, proto_len);
        BIO_write(bio, "\n", 1);
    } else
        BIO_printf(bio, "No ALPN negotiated\n");

    // More TLS information
    if (istls13) {
        switch (SSL_get_early_data_status(s)) {
        case SSL_EARLY_DATA_NOT_SENT:
            BIO_printf(bio, "Early data was not sent\n");
            break;

        case SSL_EARLY_DATA_REJECTED:
            BIO_printf(bio, "Early data was rejected\n");
            break;

        case SSL_EARLY_DATA_ACCEPTED:
            BIO_printf(bio, "Early data was accepted\n");
            break;

        }

        /*
         * We also print the verify results when we dump session information,
         * but in TLSv1.3 we may not get that right away (or at all) depending
         * on when we get a NewSessionTicket. Therefore we print it now as well.
         */
        verify_result = SSL_get_verify_result(s);
        BIO_printf(bio, "Verify return code: %ld (%s)\n", verify_result,
                   X509_verify_cert_error_string(verify_result));
    } else {
        /* In TLSv1.3 we do this on arrival of a NewSessionTicket */
        SSL_SESSION_print(bio, SSL_get_session(s));
    }

    if (SSL_get_session(s) != NULL && keymatexportlabel != NULL) {
        BIO_printf(bio, "Keying material exporter:\n");
        BIO_printf(bio, "    Label: '%s'\n", keymatexportlabel);
        BIO_printf(bio, "    Length: %i bytes\n", keymatexportlen);
        exportedkeymat = app_malloc(keymatexportlen, "export key");
        if (!SSL_export_keying_material(s, exportedkeymat,
                                        keymatexportlen,
                                        keymatexportlabel,
                                        strlen(keymatexportlabel),
                                        NULL, 0, 0)) {
            BIO_printf(bio, "    Error\n");
        } else {
            BIO_printf(bio, "    Keying material: ");
            for (i = 0; i < keymatexportlen; i++)
                BIO_printf(bio, "%02X", exportedkeymat[i]);
            BIO_printf(bio, "\n");
        }
        OPENSSL_free(exportedkeymat);
    }
    BIO_printf(bio, "---\n");
    /* flush, or debugging output gets mixed with http response */
    (void)BIO_flush(bio);
}


char *hexencode(const unsigned char *data, size_t len) {
    static const char *hex = "0123456789abcdef";
    char *out;
    char *cp;
    size_t outlen = 2 * len + 1;
    int ilen = (int) outlen;

    if (outlen < len || ilen < 0 || outlen != (size_t)ilen) {
        BIO_printf(bio_err, "%s: %zu-byte buffer too large to hexencode\n",
                   opt_getprog(), len);
        exit(1);
    }
    cp = out = app_malloc(ilen, "TLSA hex data buffer");

    while (len-- > 0) {
        *cp++ = hex[(*data >> 4) & 0x0f];
        *cp++ = hex[*data++ & 0x0f];
    }
    *cp = '\0';
    return out;
}

void* app_malloc(int sz, const char *what) {
    void *vp = OPENSSL_malloc(sz);

    if (vp == NULL)
        app_bail_out("%s: Could not allocate %d bytes for %s\n",
                     opt_getprog(), sz, what);
    return vp;
}

void app_bail_out(char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    BIO_vprintf(bio_err, fmt, args);
    va_end(args);
    ERR_print_errors(bio_err);
    exit(1);
}

char *opt_getprog(void) {
    return prog;
}


void print_verify_detail(SSL *s, BIO *bio) {
    int mdpth;
    EVP_PKEY *mspki;
    long verify_err = SSL_get_verify_result(s);

    if (verify_err == X509_V_OK) {
        const char *peername = SSL_get0_peername(s);

        BIO_printf(bio, "Verification: OK\n");
        if (peername != NULL)
            BIO_printf(bio, "Verified peername: %s\n", peername);
    } else {
        const char *reason = X509_verify_cert_error_string(verify_err);

        BIO_printf(bio, "Verification error: %s\n", reason);
    }

    if ((mdpth = SSL_get0_dane_authority(s, NULL, &mspki)) >= 0) {
        uint8_t usage, selector, mtype;
        const unsigned char *data = NULL;
        size_t dlen = 0;
        char *hexdata;

        mdpth = SSL_get0_dane_tlsa(s, &usage, &selector, &mtype, &data, &dlen);

        /*
         * The TLSA data field can be quite long when it is a certificate,
         * public key or even a SHA2-512 digest.  Because the initial octets of
         * ASN.1 certificates and public keys contain mostly boilerplate OIDs
         * and lengths, we show the last 12 bytes of the data instead, as these
         * are more likely to distinguish distinct TLSA records.
         */
#define TLSA_TAIL_SIZE 12
        if (dlen > TLSA_TAIL_SIZE)
            hexdata = hexencode(data + dlen - TLSA_TAIL_SIZE, TLSA_TAIL_SIZE);
        else
            hexdata = hexencode(data, dlen);
        BIO_printf(bio, "DANE TLSA %d %d %d %s%s %s at depth %d\n",
                   usage, selector, mtype,
                   (dlen > TLSA_TAIL_SIZE) ? "..." : "", hexdata,
                   (mspki != NULL) ? "signed the certificate" :
                   mdpth ? "matched TA certificate" : "matched EE certificate",
                   mdpth);
        OPENSSL_free(hexdata);
    }
}


unsigned long get_nameopt(void) {
    return (nmflag_set) ? nmflag : XN_FLAG_ONELINE;
}

int ssl_print_sigalgs(BIO *out, SSL *s) {
    int nid;
    if (!SSL_is_server(s))
        ssl_print_client_cert_types(out, s);
    do_print_sigalgs(out, s, 0);
    do_print_sigalgs(out, s, 1);
    if (SSL_get_peer_signature_nid(s, &nid) && nid != NID_undef)
        BIO_printf(out, "Peer signing digest: %s\n", OBJ_nid2sn(nid));
    if (SSL_get_peer_signature_type_nid(s, &nid))
        BIO_printf(out, "Peer signature type: %s\n", get_sigtype(nid));
    return 1;
}

void ssl_print_client_cert_types(BIO *bio, SSL *s) {
    const unsigned char *p;
    int i;
    int cert_type_num = SSL_get0_certificate_types(s, &p);
    if (!cert_type_num)
        return;
    BIO_puts(bio, "Client Certificate Types: ");
    for (i = 0; i < cert_type_num; i++) {
        unsigned char cert_type = p[i];
        const char *cname = lookup((int)cert_type, cert_type_list, NULL);

        if (i)
            BIO_puts(bio, ", ");
        if (cname != NULL)
            BIO_puts(bio, cname);
        else
            BIO_printf(bio, "UNKNOWN (%d),", cert_type);
    }
    BIO_puts(bio, "\n");
}


int do_print_sigalgs(BIO *out, SSL *s, int shared) {
    int i, nsig, client;
    client = SSL_is_server(s) ? 0 : 1;
    if (shared)
        nsig = SSL_get_shared_sigalgs(s, 0, NULL, NULL, NULL, NULL, NULL);
    else
        nsig = SSL_get_sigalgs(s, -1, NULL, NULL, NULL, NULL, NULL);
    if (nsig == 0)
        return 1;

    if (shared)
        BIO_puts(out, "Shared ");

    if (client)
        BIO_puts(out, "Requested ");
    BIO_puts(out, "Signature Algorithms: ");
    for (i = 0; i < nsig; i++) {
        int hash_nid, sign_nid;
        unsigned char rhash, rsign;
        const char *sstr = NULL;
        if (shared)
            SSL_get_shared_sigalgs(s, i, &sign_nid, &hash_nid, NULL,
                                   &rsign, &rhash);
        else
            SSL_get_sigalgs(s, i, &sign_nid, &hash_nid, NULL, &rsign, &rhash);
        if (i)
            BIO_puts(out, ":");
        sstr = get_sigtype(sign_nid);
        if (sstr)
            BIO_printf(out, "%s", sstr);
        else
            BIO_printf(out, "0x%02X", (int)rsign);
        if (hash_nid != NID_undef)
            BIO_printf(out, "+%s", OBJ_nid2sn(hash_nid));
        else if (sstr == NULL)
            BIO_printf(out, "+0x%02X", (int)rhash);
    }
    BIO_puts(out, "\n");
    return 1;
}

const char *get_sigtype(int nid) {
    switch (nid) {
    case EVP_PKEY_RSA:
        return "RSA";

    case EVP_PKEY_RSA_PSS:
        return "RSA-PSS";

    case EVP_PKEY_DSA:
        return "DSA";

     case EVP_PKEY_EC:
        return "ECDSA";

     case NID_ED25519:
        return "Ed25519";

     case NID_ED448:
        return "Ed448";

     case NID_id_GostR3410_2001:
        return "gost2001";

     case NID_id_GostR3410_2012_256:
        return "gost2012_256";

     case NID_id_GostR3410_2012_512:
        return "gost2012_512";

    default:
        return NULL;
    }
}

const char *lookup(int val, const STRINT_PAIR* list, const char* def) {
    for ( ; list->name; ++list)
        if (list->retval == val)
            return list->name;
    return def;
}

int ssl_print_tmp_key(BIO *out, SSL *s) {
    EVP_PKEY *key;

    if (!SSL_get_peer_tmp_key(s, &key))
        return 1;
    BIO_puts(out, "Server Temp Key: ");
    switch (EVP_PKEY_id(key)) {
    case EVP_PKEY_RSA:
        BIO_printf(out, "RSA, %d bits\n", EVP_PKEY_bits(key));
        break;

    case EVP_PKEY_DH:
        BIO_printf(out, "DH, %d bits\n", EVP_PKEY_bits(key));
        break;
    case EVP_PKEY_EC:
        {
            char name[80];
            size_t name_len;

            if (!EVP_PKEY_get_utf8_string_param(key, OSSL_PKEY_PARAM_GROUP_NAME,
                                                name, sizeof(name), &name_len))
                copy_at_legth("?", name, 1);
            BIO_printf(out, "ECDH, %s, %d bits\n", name, EVP_PKEY_bits(key));
        }
    	break;
    default:
        BIO_printf(out, "%s, %d bits\n", OBJ_nid2sn(EVP_PKEY_id(key)),
                   EVP_PKEY_bits(key));
    }
    EVP_PKEY_free(key);
    return 1;
}


void print_ca_names(BIO *bio, SSL *s) {
    const char *cs = SSL_is_server(s) ? "server" : "client";
    const STACK_OF(X509_NAME) *sk = SSL_get0_peer_CA_list(s);
    int i;

    if (sk == NULL || sk_X509_NAME_num(sk) == 0) {
        if (!SSL_is_server(s))
            BIO_printf(bio, "---\nNo %s certificate CA names sent\n", cs);
        return;
    }

    BIO_printf(bio, "---\nAcceptable %s certificate CA names\n",cs);
    for (i = 0; i < sk_X509_NAME_num(sk); i++) {
        X509_NAME_print_ex(bio, sk_X509_NAME_value(sk, i), 0, get_nameopt());
        BIO_write(bio, "\n", 1);
    }
}


void print_name(BIO *out, const char *title, const X509_NAME *nm,
                unsigned long lflags) {
    char *buf;
    char mline = 0;
    int indent = 0;

    if (title)
        BIO_puts(out, title);
    if ((lflags & XN_FLAG_SEP_MASK) == XN_FLAG_SEP_MULTILINE) {
        mline = 1;
        indent = 4;
    }
    if (lflags == XN_FLAG_COMPAT) {
        buf = X509_NAME_oneline(nm, 0, 0);
        BIO_puts(out, buf);
        BIO_puts(out, "\n");
        OPENSSL_free(buf);
    } else {
        if (mline)
            BIO_puts(out, "\n");
        X509_NAME_print_ex(out, nm, indent, lflags);
        BIO_puts(out, "\n");
    }
}

TLSVersion decodeTLSVersion(const char *vesion) {

	if ((strcmp(vesion, "1.0") == 0)) {
		printf("TLS 1.0 found \n");
		return TLS_1_0;
	} else if ((strcmp(vesion, "1.1") == 0)) {
		printf("TLS 1.1 found \n");
		return TLS_1_1;
	} else if ((strcmp(vesion, "1.2") == 0)) {
		printf("TLS 1.2 found \n");
		return TLS_1_2;
	} else if ((strcmp(vesion, "1.3") == 0)) {
		printf("TLS 1.3 found \n");
		return TLS_1_3;
	}
	// Attempt to return a sensible default to make
	// the compiler happy.
	return TLS_1_2;
}