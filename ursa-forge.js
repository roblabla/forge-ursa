// An implementation of ursa-native in pure-js using forge.
// Notes : All arguments passed are either strings or buffers (except for ints,
// duh), but forge uses its own buffer-like structure. Everything returned
// should be a buffer.

var forge = require('node-forge');

/*function textToNid() {
    forge.pki.
}*/

function toNode(val) {
    if (typeof val === "string") {
        return new Buffer(val, 'utf8');
    } else if (val instanceof forge.util.ByteBuffer) {
        var returnVal = new Buffer();
        returnVal.write(val.read);
        return returnVal;
    } else if (Array.isArray(val)) {
        var returnVal = new Buffer();
        for (var i = 0; i < val.length; i++) {
            returnVal[i] = val[i];
        }
        return returnVal;
    } else if (val instanceof forge.jsbn.BigInteger) {
        // TODO : Optimize to avoid a needless copy.
        return toNode(val.toByteArray());
    } else {
        throw new Exception("Unexpected value of type " + typeof val);
    }
}

function toForge(val) {
    // If string, do nothing. If buffer, transform to ByteBuffer
    if (Buffer.isBuffer(val)) {
        var buf = forge.util.createBuffer();
        buf.putBytes(val.toString('utf8'));
        return buf;
    } else {
        return val;
    }
}

function RsaWrap() {
}

RsaWrap.prototype.generatePrivateKey = function(modulusBits, exponent) {
    this.key = forge.pki.rsa.generateKeyPair({bits: modulusBits, e: exponent}).privateKey;
};

RsaWrap.prototype.getExponent = function() {
    return toNode(this.key.e);
};

RsaWrap.prototype.getModulus = function() {
    return toNode(this.key.n);
};

RsaWrap.prototype.getPrivateKeyPem = function() {
    return toNode(forge.pki.privateKeyToPem(this.key));
};

RsaWrap.prototype.getPublicKeyPem = function() {
    return toNode(forge.pki.publicKeyToPem(this.key));
};

RsaWrap.prototype.privateDecrypt = function(buf, padding) {
    return toNode(this.key.decrypt(toForge(buf), padding));
};

RsaWrap.prototype.privateEncrypt = function(buf) {
    throw new Exception("Not supported yet");
};

RsaWrap.prototype.publicDecrypt = function(buf) {
    throw new Exception("Not supported yet");
};
RsaWrap.prototype.publicEncrypt = function(buf, padding) {
    return this.key.encrypt(toForge(buf), padding);
};
RsaWrap.prototype.setPrivateKeyPem = function(pem, password) {
    // TODO : Support password
    this.key = forge.pki.privateKeyFromPem(toForge(pem));
};
RsaWrap.prototype.setPublicKeyPem = function(pem) {
    this.key = forge.pki.publicKeyFromPem(toForge(pem));
};

RsaWrap.prototype.sign = function(algorithm, hash) {
    // TODO : Algorithm ?
    return toNode(this.key.sign(toForge(hash)));
};

RsaWrap.prototype.verify = function(algorithm, hash, sig) {
    // TODO : Algorithm ?
    return this.key.verify(toForge(hash), sig); // Returns a bool.
};

module.exports = {
//    textToNid: textToNid,
    RsaWrap: RsaWrap,
    RSA_PKCS1_PADDING: 'RSAES-PKCS1-V1_5',
    RSA_PKCS1_OAEP_PADDING: 'RSA-OAEP'
};
