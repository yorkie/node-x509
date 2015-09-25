#ifndef __x509_h
#define __x509_h

// Include header for addon version, node/v8 inclusions, etc.
#include <addon.h>
#include <node_version.h>

// OpenSSL headers
#include <openssl/asn1.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/x509_vfy.h>
#include <openssl/bn.h>
#include <stdio.h>
#include <stdlib.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/pkcs12.h>
#include <openssl/bio.h>

using namespace v8;

void get_altnames(const FunctionCallbackInfo<Value> &args);
void get_subject(const FunctionCallbackInfo<Value> &args);
void get_issuer(const FunctionCallbackInfo<Value> &args);
char* parse_args(const FunctionCallbackInfo<Value> &args);
void parse_cert(const FunctionCallbackInfo<Value> &args);


Handle<Value> try_parse(char *data);
Handle<Value> parse_date(char *date);
Handle<Value> parse_serial(ASN1_INTEGER *serial);
Handle<Object> parse_name(X509_NAME *subject);
char* real_name(char *data);


#endif
