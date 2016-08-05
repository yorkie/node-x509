#include <cstring>
#include <pkcs12.h>

using namespace v8;

NAN_METHOD(extract_p12)
{
  Nan::HandleScope scope;

  if (info.Length() < 2) {
    Nan::ThrowTypeError("Must provide a certificate path and a password");
    info.GetReturnValue().SetUndefined();
  }

  if (!info[0]->IsString() || !info[1]->IsString()) {
    Nan::ThrowTypeError("Certificate and password must be strings.");
    info.GetReturnValue().SetUndefined();
  }

  String::Utf8Value data(info[0]->ToString());
  String::Utf8Value password(info[1]->ToString());

  Local<Object> exports(extract_from_p12(*data, *password));
  info.GetReturnValue().Set(exports);
}


Local<Object> extract_from_p12(char *data, char* password) {
  Nan::EscapableHandleScope	scope;
  Local<Object>			exports = Nan::New<Object>();
  Local<Array>			cacerts = Nan::New<Array>();
  FILE				*fp;
  EVP_PKEY			*pkey;
  RSA				*rsa;
  X509				*cert;
  STACK_OF(X509)		*ca = NULL;
  PKCS12			*p12;
  BIO				*mem; 
  BUF_MEM			*bptr;
  size_t			length;
  char				*output;


  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  if (!(fp = fopen(data, "rb"))) {
    Nan::ThrowError("Cannot open file");
    return scope.Escape(exports);
  }
  p12 = d2i_PKCS12_fp(fp, NULL);
  fclose (fp);
  if (!p12) {
    Nan::ThrowError("Error reading PKCS#12 file\n");
    return scope.Escape(exports);
  }
  if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
    Nan::ThrowError("Cannot parse PKCS#12 file (wrong password?)\n");
    return scope.Escape(exports);
  }
  PKCS12_free(p12);
  if (!cert) {
    Nan::ThrowError("Cannot extract certificate from PKCS#12 file\n");
    return scope.Escape(exports);
  }

  if (cert) {
    mem = BIO_new(BIO_s_mem());
    // add return check
    PEM_write_bio_X509(mem, cert);
    BIO_get_mem_ptr(mem, &bptr);
    static_cast<void>(BIO_flush(mem));
    length = BIO_get_mem_data(mem, &output);
    Nan::Set(exports, Nan::New<String>("certificate").ToLocalChecked(), Nan::New<String>(output).ToLocalChecked());
    //exports->Set(String::NewFromUtf8(isolate, "certificate"), String::NewFromUtf8(isolate, output, String::kNormalString, length));
    BIO_free_all(mem);
  }

  if (pkey) {
    mem = BIO_new(BIO_s_mem());
    rsa = EVP_PKEY_get1_RSA(pkey);
    // add return check
    PEM_write_bio_RSAPrivateKey(mem, rsa, NULL, NULL, 0, NULL, NULL);
    static_cast<void>(BIO_flush(mem));
    length = BIO_get_mem_data(mem, &output);
    Nan::Set(exports, Nan::New<String>("rsa").ToLocalChecked(), Nan::New<String>(output).ToLocalChecked());
    //exports->Set(String::NewFromUtf8(isolate, "rsa"), String::NewFromUtf8(isolate, output, String::kNormalString, length));
    BIO_free_all(mem);
  }

  if (ca && sk_X509_num(ca)) {
    
    for (int i = 0; i < sk_X509_num(ca); i++)
      {
	mem = BIO_new(BIO_s_mem());
	// add return check
	PEM_write_bio_X509(mem, sk_X509_value(ca, i));
	BIO_get_mem_ptr(mem, &bptr);
	static_cast<void>(BIO_flush(mem));
	length = BIO_get_mem_data(mem, &output);
	Nan::Set(cacerts, i, Nan::New<String>(output).ToLocalChecked());
        //cacerts->Set(i, String::NewFromUtf8(isolate, output, String::kNormalString, length));	
	BIO_free_all(mem);
      }
    Nan::Set(exports, Nan::New<String>("ca").ToLocalChecked(), cacerts);
    //exports->Set(String::NewFromUtf8(isolate, "ca"), cacerts);
  }


  sk_X509_pop_free(ca, X509_free);
  X509_free(cert);
  EVP_PKEY_free(pkey);
  return (scope.Escape(exports));
}

