
var source = require('./build/Release/wopenssl');

exports.x509 = {};
exports.pkcs12 = {};

exports.version = source.version;
exports.x509.getAltNames = source.getAltNames;
exports.x509.getSubject = source.getSubject;
exports.x509.getIssuer = source.getIssuer;
exports.pkcs12.extract = source.extractP12;

exports.x509.parseCert = function(path) {
  var ret = source.parseCert(path);
  var exts = {};
  for (var key in ret.extensions) {
    var newkey = key.replace('X509v3', '').replace(/ /g, '');
    newkey = newkey.slice(0, 1).toLowerCase() + newkey.slice(1);
    exts[newkey] = ret.extensions[key];
  }
  delete ret.extensions;
  ret.extensions = exts;
  return ret;
};