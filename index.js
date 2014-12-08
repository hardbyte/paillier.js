/**
 * Raw Paillier Cryptoscheme
 * @module paillier
 */

var bn = require('jsbn');
var crypto = require('crypto');

/**
 * Random number generator using node's crypto.rng
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
 * @function convertToBN
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
 * @function privateKey
 * @param {NumberLike} lambda - part of the public key - see Paillier's paper.
 * @param {NumberLike} mu - part of the public key - see Paillier's paper.
 * @param {PublicKey} public_key - The corresponding public key.
 * @returns {PrivateKey}
 * */
exports.privateKey = function(lambda, mu, public_key){

    lambda = convertToBN(lambda);
    mu = convertToBN(mu);

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

///**
//* A Paillier.PublicKey
//* @typedef PublicKey
//* @property {BigInteger} g
//* @property {BigInteger} n
//* @property {BigInteger} nsquare
//* @property {BigInteger} max_int - The maximum raw integer value that can be encrypted with this public key.
//* @property {function} raw_encrypt
//*/


/**
 * Create a Public Key
 *
 * @example
 * var publicKey = phe.publicKey("6497955158", "126869");
 *
 * @constructs PublicKey
 * @param {NumberLike} g
 * @param {NumberLike} n
 * @returns {PublicKey}
 */
exports.publicKey = function(g, n){
    g = convertToBN(g);
    n = convertToBN(n);


    ///** @namespace PublicKey */
    var pk = {
        g: g,
        n: n,
        nsquare: n.multiply(n),
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
     * @memberof PublicKey
     * @name raw_encrypt
     * @function raw_encrypt
     * @param {NumberLike} plaintext
     * @param {NumberLike} [r_value]
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
     * @memberof PublicKey
     * @function encrypt
     * @name encrypt
     * @TODO finish me
     */
    pk.encrypt = function(value, precision, r_value){

    };

    /**
     * Create a json serialization
     * @function
     * @returns {{g: (string|*), n: (string|*)}}
     */
    pk.toJSON = function(){

        return {
            g: this.g.toString(),
            n: this.n.toString()
        };
    };

    return pk;
};


function getNBitRand(n){
    return new bn(n, 1, rng);
}


/**
 * Return a random N-bit prime number using the System's best
 * Cryptographic random source.
 * @private
 * @param {NumberLike} bitLength - n-bit prime number
 */
function getprimeover(bitLength){
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

