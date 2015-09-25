#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>
#include <pkcs12.h>

using namespace v8;

void init(Handle<Object> exports) {
  NODE_SET_METHOD(exports, "getAltNames", get_altnames);
  NODE_SET_METHOD(exports, "getSubject", get_subject);
  NODE_SET_METHOD(exports, "getIssuer", get_issuer);
  NODE_SET_METHOD(exports, "parseCert", parse_cert);
  NODE_SET_METHOD(exports, "extractP12", extract_p12);
}

NODE_MODULE(wopenssl, init)
