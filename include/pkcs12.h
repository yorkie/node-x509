#ifndef __pkcs12_h__
#define __pkcs12_h__

#include <addon.h>
#include <node_version.h>

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

void extract_p12(const FunctionCallbackInfo<Value> &args);


Handle<Object> extract_from_p12(char *data, char* password);

#endif
