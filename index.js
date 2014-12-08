/**
 * Raw Paillier Cryptoscheme
 * @module paillier
 * @fileOverview A Paillier Cryptoscheme implementation compatible with Python-Paillier.
 * @version 0.1
 * @author Brian Thorne <brian.thorne@nicta.com.au>
 *
 * @example
 *
 * paillier = require("paillier");
 * // Create a new Paillier keypair
 * var keypair = paillier.generate_paillier_keypair();
 * keypair.public_key.encrypt("1")
 */

var bn = require('jsbn');
var crypto = require('crypto');

/**
 * Random number generator using node's crypto.rng
 * @private
 */
function SecureRandom(){
    return {
        nextBytes: function(ba) {
            // returns a "SlowBuffer" of given length
            // can be cast to an ArrayBuffer
            // var ab = new Uint8Array(buf)

            var i;
            var n = ba.length;
            var buf = crypto.rng(n);
            for (i = 0; i < n; ++i) {
                ba[i] = buf[i];
            }
            return ba;
        }
    };
}
var rng = SecureRandom();

/**
 * A number or string containing a number. Essentially something that can be parsed into a
 * BigInteger type.
 * @typedef {(number|string|BigInteger)} NumberLike
 * */

/**
 * Convert a {@link NumberLike} into a {@link external:BigInteger}.
 * @private
 * @param {NumberLike} input - The value to be converted into a BigInteger instance.
 * @returns {BigInteger}
 */
function convertToBN(input){
    // Todo use instanceof as well?

    if(typeof input == "number"){
        console.log('WARNING: you are using javascript numbers for cryptography');
        input = input.toString();
    }

    if(typeof input == "string" ){
        //console.log("Converting input string to BigInteger");
        input = new bn(input, 10);
        //console.log(input.toString());
    }


    return input;
}

/**
 * Create a Private Key.
 *
 * @namespace PrivateKey
 * @constructs PrivateKey
 *
 * @param {NumberLike} lambda - part of the public key - see Paillier's paper.
 * @param {NumberLike} mu - part of the public key - see Paillier's paper.
 * @param {PublicKey} public_key - The corresponding public key.
 *
 * @returns {PrivateKey}
 * */
exports.privateKey = function(lambda, mu, public_key){

    lambda = convertToBN(lambda);
    mu = convertToBN(mu);

    /**
     * @lends PrivateKey#
     */
    var data = {
        lambda: lambda,
        mu: mu,
        public_key: public_key
    };

    data.toJSON = function(){
        // Override JSON routine to convert the BigIntegers into strings
        return {
            lambda: this.lambda.toString(),
            mu: this.mu.toString()
        };
    };

    data.raw_decrypt = function(ciphertext){
        // if plaintext isn't a bignum convert it...
        ciphertext = convertToBN(ciphertext);

        // TODO define output type string/Uint8Array/Buffer?
        var u = ciphertext.modPow(data.lambda, data.public_key.nsquare);
        var l_of_u = u.subtract(bn.ONE).divide(data.public_key.n);
        return l_of_u.multiply(data.mu).mod(data.public_key.n);
    };

    return data;
};

/**
 * Create a Public Key.
 *
 * @example
 * var publicKey = phe.publicKey("6497955158", "126869");
 *
 * @namespace PublicKey
 * @constructs PublicKey
 *
 * @param {NumberLike} g
 * @param {NumberLike} n
 *
 * @returns {PublicKey}
 */
exports.publicKey = function(g, n){
    g = convertToBN(g);
    n = convertToBN(n);

    /**
     * @lends PublicKey#
     */
    var pk = {
        /** @property {BigInteger} g */
        g:  g,
        /** @property {BigInteger} n */
        n: n,
        nsquare: n.multiply(n),
        /** @property {BigInteger} max_int - The largest number that can be encrypted with this public key. */
        max_int: n.divide(new bn("3", 10)).subtract(bn.ONE)
    };

    // Return an integer number between 1 and n
    function get_random_lt_n(){
        do {
            r = new bn(1 + Math.log(pk.n)/Math.LN2, 1, rng);
            // make sure r <= n
        } while(r.compareTo(pk.n) <= 0);
        return r;
    }

    /**
     * Raw paillier encryption of a positive integer plaintext.
     *
     * You probably want to use {@link encrypt} instead, because
     * it handles signed integers as well as floats.
     *
     * @param {NumberLike} plaintext - a positive integer. Typically an encoding of the actual value.
     * @param {NumberLike} [r_value] - obfuscator for the ciphertext. By default a random value is used.
     * @returns {BigInteger} ciphertext
     */
    pk.raw_encrypt = function(plaintext, r_value){
        // if plaintext isn't a bignum convert it...
        plaintext = convertToBN(plaintext);
        r_value = convertToBN(r_value);

        var nude_ciphertext;
        if( (pk.n.subtract(pk.max_int).compareTo(plaintext) <= 0) && (plaintext < pk.n)){
            var neg_plaintext = pk.n.subtract(plaintext);
            var neg_ciphertext = pk.g.modPow(neg_plaintext, pk.nsquare);
            nude_ciphertext = neg_ciphertext.modInverse(pk.nsquare);
        } else {
            nude_ciphertext = pk.g.modPow(plaintext, pk.nsquare);
        }

        if(r_value == undefined){
            r_value = get_random_lt_n();
        }

        var obfuscator = r_value.modPow(pk.n, pk.nsquare);

        return nude_ciphertext.multiply(obfuscator).mod(pk.nsquare);
    };

    /**
     * Encode and encrypt a signed int or float value.
     *
     * @param {number|float} value - an int or float to be encrypted.
     *      If int, it must satisfy abs(value) < n/3
     *      If float, it must satisfy abs(value/precision) << n/3
     * @param {float} precision - Passed to {@link EncodedNumber.encode}.
     *
     * @returns {EncryptedNumber} The encrypted number instance
     *
     * @TODO finish documenting and implementing me
     */
    pk.encrypt = function(value, precision, r_value){
        var encoding = exports.EncodedNumber.encode(this, value, precision);
    };

    /**
     * Create a json serialization
     * @function
     * @returns {string} The JSON representation of the Public Key. Comprises
     *      g and n attributes.
     */
    pk.toJSON = function(){

        return {
            g: this.g.toString(),
            n: this.n.toString()
        };
    };

    return pk;
};

/**
 * Return a random N-bit prime number using the System's best
 * Cryptographic random source.
 * @private
 * @param {NumberLike} bitLength - n-bit prime number
 */
function getprimeover(bitLength){

    function getNBitRand(n){
        return new bn(n, 1, rng);
    }

    var p = bn.ZERO;
    while(!p.isProbablePrime(20)){
        p = getNBitRand(bitLength);
    }
    return p;
}



/**
 * Generate a Paillier KeyPair of given strength.
 *
 * @param {NumberLike} [n_length=1024] - key size in bits
 *
 * @example
 * // Create a default keypair public, private:
 * var keypair = paillier.generate_paillier_keypair();
 *
 * @returns {KeyPair} KeyPair
 */
exports.generate_paillier_keypair = function(n_length){
    var keysize;
    if(n_length == undefined){
        keysize = 1024;
        console.log("Using default key size of " + keysize + " bits");
    } else {
        keysize = n_length;
    }

    console.log("Generating new keypair with " + keysize + " bit length key");

    var p, q, n, g, phi_n, mu;
    var correctLength = false;
    while (!correctLength || p.compareTo(q) == 0){
        p = getprimeover(keysize>>1);
        q = getprimeover(keysize>>1);
        n = p.multiply(q);
        correctLength = n.testBit(keysize -1)
    }
    // simple paillier variant with g=n+1
    g = n.add(bn.ONE);

    phi_n = p.subtract(bn.ONE).multiply(q.subtract(bn.ONE));
    mu = phi_n.modInverse(n);

    var pubKey = exports.publicKey(g, n);

    /**
     * A KeyPair
     * @typedef KeyPair
     * @property {PublicKey} public_key
     * @property {PrivateKey} private_key
     * @property {number} n_length - The key length in bits
     * */
    return {
        public_key: pubKey,
        private_key: exports.privateKey(phi_n, mu, pubKey),
        n_length: keysize
    };

};

/**
 * Represents a float or int encoded for Paillier encryption.
 *
 * For end users, this class is mainly useful for specifying precision
 * when adding/multiplying an {@link EncryptedNumber} by a scalar.
 *
 * @namespace EncodedNumber
 * @constructs EncodedNumber
 *
 * @param {PublicKey} public_key - public key for which to encode (this is necessary because max_int varies)
 * @param {BigInteger} encoding - The encoded number to store. Must be positive and less than max_int
 * @param {number} exponent - Together with the fixed BASE, determines the level of fixed-precision used
 *      in encoding the number.
 *
 * @returns {EncodedNumber}
 */
exports.EncodedNumber = function(public_key, encoding, exponent){

    /**
     * Base to use when exponentiating. Larger `BASE` means
     * that exponent leaks less information. If you vary this,
     * you'll have to manually inform anyone decoding your numbers.
     */
    var BASE = 16;


    /**
     * Class method/constructor for EncodedNumber
     *
     * @param {PublicKey} public_key
     * @param {number} scalar
     * @param {float} precision
     * @param {number} max_exponent
     *
     * @returns {EncodedNumber}
     */
    function encode(){

    }


    // TODO https://github.com/NICTA/python-paillier/blob/master/phe/paillier.py#L428


};

/**
 * Represents the Paillier encryption of a float or int.
 * Typically, an `EncryptedNumber` is created by {@link PublicKey.encrypt}.
 * You would only instantiate an EncryptedNumber manually if you are de-serializing
 * a number someone else encrypted.
 *
 * @namespace EncryptedNumber
 * @constructs EncryptedNumber
 *
 * @param {PublicKey} public_key - The PublicKey against which the number was encrypted.
 * @param {BigInteger} ciphertext - Encrypted representation of the encoded number.
 * @param {number} [exponent=0] - Used by {@link EncodedNumber} to keep track of fixed precision - usually negative.
 *
 * @returns {EncryptedNumber}
 */
exports.EncryptedNumber = function(public_key, ciphertext, exponent){

    /** @lends EncryptedNumber */
    var ns = {
        /**
         * Get the raw ciphertext underlying this EncryptedNumber
         *
         * Choosing a random number is slow. Therefore, methods like
         * add and multiply take a shortcut and do not
         * follow Paillier encryption fully - every encrypted sum or
         * product should be multiplied by r ^ PublicKey.n for random r < n (i.e., the result
         * is obfuscated). Not obfuscating provides a big speed up in,
         * e.g., an encrypted dot product: each of the product terms need
         * not be obfuscated, since only the final sum is shared with
         * others - only this final sum needs to be obfuscated.
         * Not obfuscating is OK for internal use, where you are happy for
         * your own computer to know the scalars you've been adding and
         * multiplying to the original ciphertext. But this is *not* OK if
         * you're going to be sharing the new ciphertext with anyone else.
         * So, by default, this method returns an obfuscated ciphertext -
         * obfuscating it if necessary. If instead you set be_secure=False
         * then the ciphertext will be returned, regardless of whether it
         * has already been obfuscated. We thought that this approach,
         * while a little awkward, yields a safe default while preserving
         * the option for high performance.
         *
         * @param {boolean} [be_secure=true] If any untrusted party will see the returned ciphertext, then this
         *      should be true.
         * @returns {BigInteger} The ciphertext. WARNING, if be_secure is false then it could be possible
         *      for an attacker to deduce numbers involved in calculating this ciphertext.
         */
        ciphertext: function(be_secure){
            return "TODO";
        }
    };

    return ns;
};