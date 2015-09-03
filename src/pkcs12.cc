#include <cstring>
#include <pkcs12.h>

using namespace v8;

#if NODE_VERSION_AT_LEAST(0, 11, 3) && defined(__APPLE__)

void	extract_p12(const FunctionCallbackInfo<Value> &args)
{
  if (args.Length() < 2) {
    ThrowException(Exception::Error(String::New("Must provide a certificate path and a password")));
    return NULL;
  }

  if (!args[0]->IsString() || !args[1]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Certificate and password must be strings.")));
    return NULL;
  }

  Local<Object> exports(extract_from_p12(args[0]->ToString(), args[1]->ToString()));
  args.GetReturnValue().Set(exports);
}


#else

Handle<Value> extract_p12(const Arguments &args) {
  HandleScope scope;

  if (args.Length() < 2) {
    ThrowException(Exception::Error(String::New("Must provide a certificate file path and a password.")));
    return scope.Close(Undefined());
  }

  if (!args[0]->IsString()) {
    ThrowException(Exception::TypeError(String::New("Certificate and password must be strings.")));
    return scope.Close(Undefined());
  }

  String::Utf8Value path(args[0]);
  String::Utf8Value password(args[1]);

  Handle<Value> exports(extract_from_p12(*path, *password));

  return scope.Close(exports);
}

#endif

Handle<Value> extract_from_p12(char *data, char* password) {
  HandleScope		scope;
  Handle<Object>	exports(Object::New());
  Local<Array>		cacerts(Array::New());
  FILE			*fp;
  EVP_PKEY		*pkey;
  RSA			*rsa;
  X509			*cert;
  STACK_OF(X509)	*ca = NULL;
  PKCS12		*p12;
  BIO			*base64;
  BIO			*mem; 
  BUF_MEM		*bptr;
  size_t		length;
  char			*output;


  OpenSSL_add_all_algorithms();
  ERR_load_crypto_strings();
  if (!(fp = fopen(data, "rb"))) {
    ThrowException(Exception::TypeError(String::New("Cannot open file")));
    return scope.Close(Undefined());
  }
  p12 = d2i_PKCS12_fp(fp, NULL);
  fclose (fp);
  if (!p12) {
    ThrowException(Exception::TypeError(String::New("Error reading PKCS#12 file\n")));
    return scope.Close(Undefined());
  }
  if (!PKCS12_parse(p12, password, &pkey, &cert, &ca)) {
    ThrowException(Exception::TypeError(String::New("Error parsing PKCS#12 file\n")));
    return scope.Close(Undefined());
  }
  PKCS12_free(p12);
  if (!cert) {
    ThrowException(Exception::TypeError(String::New("Cannot extract certificate from PKCS#12 file\n")));
    return scope.Close(Undefined());
  }

  if (cert) {
    mem = BIO_new(BIO_s_mem());
    // add return check
    PEM_write_bio_X509(mem, cert);
    BIO_get_mem_ptr(mem, &bptr);
    static_cast<void>(BIO_flush(mem));
    length = BIO_get_mem_data(mem, &output);
    exports->Set(String::NewSymbol("certificate"), String::New(output, length));
    BIO_free_all(mem);
  }

  if (pkey) {
    mem = BIO_new(BIO_s_mem());
    rsa = EVP_PKEY_get1_RSA(pkey);
    // add return check
    PEM_write_bio_RSAPrivateKey(mem, rsa, NULL, NULL, 0, NULL, NULL);
    static_cast<void>(BIO_flush(mem));
    length = BIO_get_mem_data(mem, &output);
    exports->Set(String::NewSymbol("rsa"), String::New(output, length));
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
        cacerts->Set(i, String::New(output, length));	
	BIO_free_all(mem);
      }
    exports->Set(String::NewSymbol("ca"), cacerts);
  }


  sk_X509_pop_free(ca, X509_free);
  X509_free(cert);
  EVP_PKEY_free(pkey);
  return (scope.Close(exports));
}

