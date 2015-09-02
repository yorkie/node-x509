#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>

using namespace v8;

void init(Handle<Object> exports) {
  exports->Set(String::NewSymbol("version"), String::New(VERSION));
  exports->Set(String::NewSymbol("getAltNames"), FunctionTemplate::New(get_altnames)->GetFunction());
  exports->Set(String::NewSymbol("getSubject"), FunctionTemplate::New(get_subject)->GetFunction());
  exports->Set(String::NewSymbol("getIssuer"), FunctionTemplate::New(get_issuer)->GetFunction());
  exports->Set(String::NewSymbol("parseCert"), FunctionTemplate::New(parse_cert)->GetFunction());
  exports->Set(String::NewSymbol("getPemFromP12"), FunctionTemplate::New(get_pem_from_p12)->GetFunction());
}

NODE_MODULE(wopenssl, init)
