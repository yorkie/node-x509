#include <cstring>
#include <x509.h>

using namespace v8;

// Field names that OpenSSL is missing.
char *MISSING[3][2] = {
  {
    (char*) "1.3.6.1.4.1.311.60.2.1.1",
    (char*) "jurisdictionOfIncorpationLocalityName"
  },

  {
    (char*) "1.3.6.1.4.1.311.60.2.1.2",
    (char*) "jurisdictionOfIncorporationStateOrProvinceName"
  },

  {
    (char*) "1.3.6.1.4.1.311.60.2.1.3",
    (char*) "jurisdictionOfIncorporationCountryName"
  }
};


void get_altnames(const FunctionCallbackInfo<Value> &args) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  args.GetReturnValue().Set(exports->Get(String::NewFromUtf8(isolate, "altNames")));
}

void get_subject(const FunctionCallbackInfo<Value> &args) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  args.GetReturnValue().Set(exports->Get(String::NewFromUtf8(isolate, "subject")));
}

void get_issuer(const FunctionCallbackInfo<Value> &args) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  args.GetReturnValue().Set(exports->Get(String::NewFromUtf8(isolate, "issuer")));
}

char* parse_args(const FunctionCallbackInfo<Value> &args) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  if (args.Length() == 0) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Must provide a certificate file.")));
    return NULL;
  }

  if (!args[0]->IsString()) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Certificate must be a string.")));
    return NULL;
  }

  if (args[0]->ToString()->Length() == 0) {
    isolate->ThrowException(Exception::TypeError(String::NewFromUtf8(isolate, "Certificate argument provided, but left blank.")));
    return NULL;
  }

  char *value = (char*) malloc(sizeof(char*) * args[0]->ToString()->Length());
  sprintf(value, "%s", *String::Utf8Value(args[0]->ToString()));
  return value;
}

void parse_cert(const FunctionCallbackInfo<Value> &args) {
  Local<Object> exports(try_parse(parse_args(args))->ToObject());
  args.GetReturnValue().Set(exports);
}

/*
 * This is where everything is handled for both -0.11.2 and 0.11.3+.
 */


Handle<Value> try_parse(char *data) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  EscapableHandleScope scope(isolate);
  Local<Object> exports(Object::New(isolate));
  X509 *cert;

  BIO *bio = BIO_new(BIO_s_mem());
  int result = BIO_puts(bio, data);

  if (result == -2) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "BIO doesn't support BIO_puts.")));
    return scope.Escape(exports);
  }
  else if (result <= 0) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "No data was written to BIO.")));
    return scope.Escape(exports);
  }

  // Try raw read
  cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

  if (cert == NULL) {
    // Switch to file BIO
    bio = BIO_new(BIO_s_file());

    // If raw read fails, try reading the input as a filename.
    if (!BIO_read_filename(bio, data)) {
      isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "File doesn't exist.")));
      return scope.Escape(exports);
    }

    // Try reading the bio again with the file in it.
    cert = PEM_read_bio_X509(bio, NULL, 0, NULL);

    if (cert == NULL) {
      isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Unable to parse certificate.")));
      return scope.Escape(exports);
    }
  }

  exports->Set(String::NewFromUtf8(isolate, "version"), Integer::New(isolate, (int) X509_get_version(cert)));
  exports->Set(String::NewFromUtf8(isolate, "subject"), parse_name(X509_get_subject_name(cert)));
  exports->Set(String::NewFromUtf8(isolate, "issuer"), parse_name(X509_get_issuer_name(cert)));
  exports->Set(String::NewFromUtf8(isolate, "serial"), parse_serial(X509_get_serialNumber(cert)));
  exports->Set(String::NewFromUtf8(isolate, "notBefore"), parse_date((char*) ASN1_STRING_data(X509_get_notBefore(cert))));
  exports->Set(String::NewFromUtf8(isolate, "notAfter"), parse_date((char*) ASN1_STRING_data(X509_get_notAfter(cert))));

  // Signature Algorithm
  int sig_alg_nid = OBJ_obj2nid(cert->sig_alg->algorithm);
  if (sig_alg_nid == NID_undef) {
    isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "unable to find specified signature algorithm name.")));
    return scope.Escape(exports);
  }
  exports->Set(String::NewFromUtf8(isolate, "signatureAlgorithm"), 
    String::NewFromUtf8(isolate, OBJ_nid2ln(sig_alg_nid)));

  // fingerPrint
  unsigned int md_size, idx;
  unsigned char md[EVP_MAX_MD_SIZE];
  if (X509_digest(cert, EVP_sha1(), md, &md_size)) {
    const char hex[] = "0123456789ABCDEF";
    char fingerprint[EVP_MAX_MD_SIZE * 3];
    for (idx = 0; idx < md_size; idx++) {
      fingerprint[3*idx] = hex[(md[idx] & 0xf0) >> 4];
      fingerprint[(3*idx)+1] = hex[(md[idx] & 0x0f)];
      fingerprint[(3*idx)+2] = ':';
    }

    if (md_size > 0) {
      fingerprint[(3*(md_size-1))+2] = '\0';
    } else {
      fingerprint[0] = '\0';
    }
    exports->Set(String::NewFromUtf8(isolate, "fingerPrint"), String::NewFromUtf8(isolate, fingerprint));
  }

  // public key
  int pkey_nid = OBJ_obj2nid(cert->cert_info->key->algor->algorithm);
  if (pkey_nid == NID_undef) {
    isolate->ThrowException(Exception::Error(
      String::NewFromUtf8(isolate, "unable to find specified public key algorithm name.")));
    return scope.Escape(exports);
  }
  EVP_PKEY *pkey = X509_get_pubkey(cert);
  Local<Object> publicKey = Object::New(isolate);
  publicKey->Set(String::NewFromUtf8(isolate, "algorithm"), 
    String::NewFromUtf8(isolate, OBJ_nid2ln(pkey_nid)));

  if (pkey_nid == NID_rsaEncryption) {
    char *rsa_e_dec, *rsa_n_hex;
    RSA *rsa_key;
    rsa_key = pkey->pkey.rsa;
    rsa_e_dec = BN_bn2dec(rsa_key->e);
    rsa_n_hex = BN_bn2hex(rsa_key->n);
    publicKey->Set(String::NewFromUtf8(isolate, "e"), String::NewFromUtf8(isolate, rsa_e_dec));
    publicKey->Set(String::NewFromUtf8(isolate, "n"), String::NewFromUtf8(isolate, rsa_n_hex));
  }
  exports->Set(String::NewFromUtf8(isolate, "publicKey"), publicKey);
  EVP_PKEY_free(pkey);

  // alt names
  Local<Array> altNames(Array::New(isolate));
  STACK_OF(GENERAL_NAME) *names = NULL;
  int i;

  names = (STACK_OF(GENERAL_NAME)*) X509_get_ext_d2i(cert, NID_subject_alt_name, NULL, NULL);

  if (names != NULL) {
    int length = sk_GENERAL_NAME_num(names);
    for (i = 0; i < length; i++) {
      GENERAL_NAME *current = sk_GENERAL_NAME_value(names, i);

      if (current->type == GEN_DNS) {
        char *name = (char*) ASN1_STRING_data(current->d.dNSName);

        if (ASN1_STRING_length(current->d.dNSName) != (int) strlen(name)) {
          isolate->ThrowException(Exception::Error(String::NewFromUtf8(isolate, "Malformed alternative names field.")));
          return scope.Escape(exports);
        }

        altNames->Set(i, String::NewFromUtf8(isolate, name));
      }
    }
  }
  exports->Set(String::NewFromUtf8(isolate, "altNames"), altNames);

  // Extensions
  Local<Object> extensions(Object::New(isolate));
  STACK_OF(X509_EXTENSION) *exts = cert->cert_info->extensions;
  int num_of_exts;
  int index_of_exts;
  if (exts) {
    num_of_exts = sk_X509_EXTENSION_num(exts);
  } else {
    num_of_exts = 0;
  }

  // IFNEG_FAIL(num_of_exts, "error parsing number of X509v3 extensions.");

  for (index_of_exts = 0; index_of_exts < num_of_exts; index_of_exts++) {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, index_of_exts);
    // IFNULL_FAIL(ext, "unable to extract extension from stack");
    ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
    // IFNULL_FAIL(obj, "unable to extract ASN1 object from extension");

    BIO *ext_bio = BIO_new(BIO_s_mem());
    // IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
    if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
      M_ASN1_OCTET_STRING_print(ext_bio, ext->value);
    }

    BUF_MEM *bptr;
    BIO_get_mem_ptr(ext_bio, &bptr);
    BIO_set_close(ext_bio, BIO_NOCLOSE);

    // remove newlines
    int lastchar = bptr->length;
    if (lastchar > 1 && (bptr->data[lastchar-1] == '\n' || bptr->data[lastchar-1] == '\r')) {
      bptr->data[lastchar-1] = (char) 0;
    }
    if (lastchar > 0 && (bptr->data[lastchar] == '\n' || bptr->data[lastchar] == '\r')) {
      bptr->data[lastchar] = (char) 0;
    }
    BIO_free(ext_bio);

    unsigned nid = OBJ_obj2nid(obj);
    if (nid == NID_undef) {
      char extname[100];
      OBJ_obj2txt(extname, 100, (const ASN1_OBJECT *) obj, 1);
      extensions->Set(String::NewFromUtf8(isolate, extname), String::NewFromUtf8(isolate, bptr->data));
    } else {
      const char *c_ext_name = OBJ_nid2ln(nid);
      // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
      extensions->Set(String::NewFromUtf8(isolate, c_ext_name), String::NewFromUtf8(isolate, bptr->data));
    }
  }
  exports->Set(String::NewFromUtf8(isolate, "extensions"), extensions);

  X509_free(cert);

  free(data);

  return scope.Escape(exports);
}

Handle<Value> parse_serial(ASN1_INTEGER *serial) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  EscapableHandleScope scope(isolate);
  Local<String> serialNumber;
  BIGNUM *bn = ASN1_INTEGER_to_BN(serial, NULL);
  char *hex = BN_bn2hex(bn);

  serialNumber = String::NewFromUtf8(isolate, hex);
  BN_free(bn);
  OPENSSL_free(hex);
  return scope.Escape(serialNumber);
}

Handle<Value> parse_date(char *date) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  EscapableHandleScope scope(isolate);
  char current[3];
  int i;
  Local<Array> dateArray(Array::New(isolate));
  Local<String> output(String::NewFromUtf8(isolate, ""));
  Local<Value> args[1];

  for (i = 0; i < (int) strlen(date) - 1; i += 2) {
    strncpy(current, &date[i], 2);
    current[2] = '\0';

    dateArray->Set((i / 2), String::NewFromUtf8(isolate, current));
  }

  output = String::Concat(output, String::Concat(dateArray->Get(1)->ToString(), String::NewFromUtf8(isolate, "/")));
  output = String::Concat(output, String::Concat(dateArray->Get(2)->ToString(), String::NewFromUtf8(isolate, "/")));
  output = String::Concat(output, String::Concat(String::NewFromUtf8(isolate, "20"), dateArray->Get(0)->ToString()));
  output = String::Concat(output, String::NewFromUtf8(isolate, " "));
  output = String::Concat(output, String::Concat(dateArray->Get(3)->ToString(), String::NewFromUtf8(isolate, ":")));
  output = String::Concat(output, String::Concat(dateArray->Get(4)->ToString(), String::NewFromUtf8(isolate, ":")));
  output = String::Concat(output, String::Concat(dateArray->Get(5)->ToString(), String::NewFromUtf8(isolate, " GMT")));

  args[0] = output;

  return scope.Escape(isolate->GetCurrentContext()->Global()->Get(String::NewFromUtf8(isolate, "Date"))->ToObject()->CallAsConstructor(1, args));
}

Handle<Object> parse_name(X509_NAME *subject) {
  v8::Isolate* isolate = v8::Isolate::GetCurrent();
  EscapableHandleScope scope(isolate);
  Local<Object> cert(Object::New(isolate));
  int i, length;
  ASN1_OBJECT *entry;
  unsigned char *value;
  char buf[255];
  length = X509_NAME_entry_count(subject);
  for (i = 0; i < length; i++) {
    entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(subject, i));
    OBJ_obj2txt(buf, 255, entry, 0);
    value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(subject, i)));
    cert->Set(String::NewFromUtf8(isolate, real_name(buf)), String::NewFromUtf8(isolate, (const char*) value));
  }
  return scope.Escape(cert);
}

// Fix for missing fields in OpenSSL.
char* real_name(char *data) {
  int i, length = (int) sizeof(MISSING) / sizeof(MISSING[0]);

  for (i = 0; i < length; i++) {
    if (strcmp(data, MISSING[i][0]) == 0)
      return MISSING[i][1];
  }

  return data;
}
