wopenssl
=========

Simple OpenSSL wrapper for NodeJS.

[![Build Status](https://travis-ci.org/wixyvir/node-wopenssl.svg?branch=master)](https://travis-ci.org/wixyvir/node-wopenssl)


## Notice

This is based on the awesome work of https://github.com/yorkie/node-x509

This project **is not yet ready for production** and a **work in progress**.

This project aim to implement [OpenSSL](https://www.openssl.org/) commonly used features as a NodeJS module.

## Installation

This package works for:

 - node 0.12.*


From NPM *(recommended)*: `npm install wopenssl`

Building and testing from source:
```
sudo npm install -g node-gyp
npm install
npm test
```

## Usage
Reading from a file:
```js
var wopenssl = require('wopenssl');

var issuer = wopenssl.x509.getIssuer(__dirname + '/certs/your.crt');
```

Reading from a string:
```js
var fs = require('fs'),
    wopenssl = require('wopenssl');

var issuer = wopenssl.x509.getIssuer(fs.readFileSync('./certs/your.crt').toString());
```

## x509 Methods
**Notes:**
- `cert` may be a filename or a raw base64 encoded PEM string in any of these methods.


#### wopenssl.x509.getAltNames(`cert`)
Parse certificate with `wopenssl.x509.parseCert` and return the alternate names.

```js
var wopenssl = require('wopenssl');

var altNames = wopenssl.x509.getAltNames(__dirname + '/certs/nodejitsu.com.crt');
/*
altNames = [ '*.nodejitsu.com', 'nodejitsu.com' ]
*/
```

#### wopenssl.x509.getIssuer(`cert`)
Parse certificate with `wopenssl.x509.parseCert` and return the issuer.

```js
var wopenssl = require('wopenssl');

var issuer = wopenssl.x509.getIssuer(__dirname + '/certs/nodejitsu.com.crt');
/*
issuer = { countryName: 'GB',
  stateOrProvinceName: 'Greater Manchester',
  localityName: 'Salford',
  organizationName: 'COMODO CA Limited',
  commonName: 'COMODO High-Assurance Secure Server CA' }
*/
```

#### wopenssl.x509.getSubject(`cert`)
Parse certificate with `wopenssl.x509.parseCert` and return the subject.

```js
var wopenssl = require('wopenssl');

var subject = wopenssl.x509.getSubject(__dirname + '/certs/nodejitsu.com.crt');
/*
subject = { countryName: 'US',
  postalCode: '10010',
  stateOrProvinceName: 'NY',
  localityName: 'New York',
  streetAddress: '902 Broadway, 4th Floor',
  organizationName: 'Nodejitsu',
  organizationalUnitName: 'PremiumSSL Wildcard',
  commonName: '*.nodejitsu.com' }
*/
```

#### wopenssl.x509.parseCert(`cert`)
Parse subject, issuer, valid before and after date, and alternate names from certificate.

```js
var wopenssl = require('wopenssl');

var cert = wopenssl.x509.parseCert(__dirname + '/certs/nodejitsu.com.crt');
/*
cert = { subject: 
   { countryName: 'US',
     postalCode: '10010',
     stateOrProvinceName: 'NY',
     localityName: 'New York',
     streetAddress: '902 Broadway, 4th Floor',
     organizationName: 'Nodejitsu',
     organizationalUnitName: 'PremiumSSL Wildcard',
     commonName: '*.nodejitsu.com' },
  issuer: 
   { countryName: 'GB',
     stateOrProvinceName: 'Greater Manchester',
     localityName: 'Salford',
     organizationName: 'COMODO CA Limited',
     commonName: 'COMODO High-Assurance Secure Server CA' },
  notBefore: Sun Oct 28 2012 20:00:00 GMT-0400 (EDT),
  notAfter: Wed Nov 26 2014 18:59:59 GMT-0500 (EST),
  altNames: [ '*.nodejitsu.com', 'nodejitsu.com' ],
  signatureAlgorithm: 'sha1WithRSAEncryption',
  fingerPrint: 'E4:7E:24:8E:86:D2:BE:55:C0:4D:41:A1:C2:0E:06:96:56:B9:8E:EC',
  publicKey: {
    algorithm: 'rsaEncryption',
    e: '65537',
    n: '.......' } }
*/
```

## PKCS#12 Methods

#### wopenssl.pkcs12.extract

Parse and extract a PKCS#12 file.

```js
var wopenssl = require('wopenssl');

var p12 = wopenssl.pkcs12.extract(__dirname + '/p12/cert.p12 + ', 'password');

var subject = wopenssl.x509.getSubject(p12.certificate);

```

## Examples
Checking the date to make sure the certificate is active:
```js
var wopenssl = require('wopenssl'),
    cert = wopenssl.x509.parseCert('yourcert.crt'),
    date = new Date();

if (cert.notBefore > date) {
  // Certificate isn't active yet.
}
if (cert.notAfter < date) {
  // Certificate has expired.
}
```

## License

MIT
