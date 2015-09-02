node-x509
=========

Simple OpenSSL certificate parser.

## Notice

This is based on the awesome work of https://github.com/yorkie/node-x509

## Installation

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

var issuer = wopenssl.getIssuer(__dirname + '/certs/your.crt');
```

Reading from a string:
```js
var fs = require('fs'),
    wopenssl = require('wopenssl');

var issuer = wopenssl.getIssuer(fs.readFileSync('./certs/your.crt').toString());
```

## Methods
**Notes:**
- `cert` may be a filename or a raw base64 encoded PEM string in any of these methods.


#### wopenssl.getAltNames(`cert`)
Parse certificate with `wopenssl.parseCert` and return the alternate names.

```js
var wopenssl = require('wopenssl');

var altNames = wopenssl.getAltNames(__dirname + '/certs/nodejitsu.com.crt');
/*
altNames = [ '*.nodejitsu.com', 'nodejitsu.com' ]
*/
```

#### wopenssl.getIssuer(`cert`)
Parse certificate with `wopenssl.parseCert` and return the issuer.

```js
var wopenssl = require('wopenssl');

var issuer = wopenssl.getIssuer(__dirname + '/certs/nodejitsu.com.crt');
/*
issuer = { countryName: 'GB',
  stateOrProvinceName: 'Greater Manchester',
  localityName: 'Salford',
  organizationName: 'COMODO CA Limited',
  commonName: 'COMODO High-Assurance Secure Server CA' }
*/
```

#### wopenssl.getSubject(`cert`)
Parse certificate with `wopenssl.parseCert` and return the subject.

```js
var wopenssl = require('wopenssl');

var subject = wopenssl.getSubject(__dirname + '/certs/nodejitsu.com.crt');
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

#### wopenssl.getPemFromP12

Parser a PKCS#12 file, exports its PEM certificate.

```js
var wopenssl = require('wopenssl');

var pemCert = wopenssl.getPemFromP12(__dirname + '/p12/cert.p12 + ', 'password');

var subject = wopenssl.getSubject(__dirname + '/certs/nodejitsu.com.crt');

```

#### wopenssl.parseCert(`cert`)
Parse subject, issuer, valid before and after date, and alternate names from certificate.

```js
var wopenssl = require('wopenssl');

var cert = wopenssl.parseCert(__dirname + '/certs/nodejitsu.com.crt');
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

## Examples
Checking the date to make sure the certificate is active:
```js
var wopenssl = require('wopenssl'),
    cert = wopenssl.parseCert('yourcert.crt'),
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