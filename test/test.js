var wopenssl = require('../index'),
    fs = require('fs'),
    path = require('path');

// All cert files should read without throwing an error.
// Simple enough test, no? 

fs.readdirSync(path.join(__dirname, 'certs')).forEach(function (file) {
  console.log("File: %s", file);
  console.log(wopenssl.x509.parseCert(path.join(__dirname, 'certs', file)));
  // wopenssl.parseCert(path.join(__dirname, 'certs', file));
  console.log();
});


console.log(wopenssl.x509.parseCert(wopenssl.pkcs12.extract("test/p12/cert.p12", "password").certificate));
