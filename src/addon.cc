#include <cstdlib>
#include <cstdio>

#include <addon.h>
#include <x509.h>
#include <pkcs12.h>

using namespace v8;

void init(Local<Object> exports) {
  Nan::Set(exports, 
    Nan::New<String>("version").ToLocalChecked(),
    Nan::New<String>(VERSION).ToLocalChecked());
  Nan::Set(exports,
    Nan::New<String>("getAltNames").ToLocalChecked(),
    Nan::New<FunctionTemplate>(get_altnames)->GetFunction());
  Nan::Set(exports,
    Nan::New<String>("getSubject").ToLocalChecked(),
    Nan::New<FunctionTemplate>(get_subject)->GetFunction());
  Nan::Set(exports,
    Nan::New<String>("getIssuer").ToLocalChecked(),
    Nan::New<FunctionTemplate>(get_issuer)->GetFunction());
  Nan::Set(exports,
    Nan::New<String>("parseCert").ToLocalChecked(),
    Nan::New<FunctionTemplate>(parse_cert)->GetFunction());
  Nan::Set(exports,
    Nan::New<String>("extractP12").ToLocalChecked(),
    Nan::New<FunctionTemplate>(extract_p12)->GetFunction());
}

NODE_MODULE(wopenssl, init)
