/**
 * Raw Paillier Cryptoscheme
 */

var bn = require('jsbn');
var crypto = require('crypto');

/* Random numbers
 *
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


// Library

function privateKey(lambda, mu, public_key){
    var data = {
        lambda: lambda,
        mu: mu,
        public_key: public_key
    };

    data.toJSON = function(){
        // Override JSON routine to convert the bignumbers into strings
        return {
            lambda: this.lambda.toString(),
            mu: this.mu.toString()
        };
    };

    data.raw_decrypt = function(ciphertext){
        // if plaintext isn't a bignum convert it...
        // Todo use instanceof as well
        if(typeof ciphertext == "string" ){
            console.log("Converting input string to bignumber");
            ciphertext = new bn(ciphertext, 10);
            console.log(ciphertext.toString());
        }


        // TODO define output type string/Uint8Array/Buffer?
        var u = ciphertext.modPow(data.lambda, data.public_key.nsquare);
        var l_of_u = u.subtract(bn.ONE).divide(data.public_key.n);
        return l_of_u.multiply(data.mu).mod(data.public_key.n);
    };
    return data;
}

function publicKey(g, n){

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

    pk.raw_encrypt = function(plaintext, r_value){
        console.log(typeof plaintext);

        // if plaintext isn't a bignum convert it...
        // Todo use instanceof as well
        if(typeof plaintext == "string" ){
            console.log("Converting input string to bignumber");
            plaintext = new bn(plaintext, 10);
            console.log(plaintext.toString());
        }

        var nude_ciphertext;
        if( (pk.n.subtract(pk.max_int).compareTo(plaintext) <= 0) && (plaintext < pk.n)){
            console.log("TODO - Extremely large plaintext - TODO");
            console.log("Plaintext is: " + plaintext.toString());
            console.log("N is: " + pk.n.toString());
            console.log("Max int is: " + pk.max_int.toString());

            var neg_plaintext = pk.n.subtract(plaintext);
            console.log('neg:' + neg_plaintext.toString());

        } else {
            nude_ciphertext = pk.g.modPow(plaintext, pk.nsquare);
        }

        if(r_value == undefined){
            r_value = get_random_lt_n();
        }

        var obfuscator = r_value.modPow(pk.n, pk.nsquare);

        return nude_ciphertext.multiply(obfuscator).mod(pk.nsquare);
    };

    pk.toJSON = function(){
        // create a json serialization
        return {
            g: this.g.toString(),
            n: this.n.toString()
        };
    };

    return pk;
}


function getNBitRand(n){
    return new bn(n, 1, rng);
}


/**
 * Return a random N-bit prime number using the System's best
 * Cryptographic random source.
 * @param n-bit prime number
 */
function getprimeover(bitLength){
    var p = bn.ZERO;
    while(!p.isProbablePrime(20)){
        p = getNBitRand(bitLength);
    }
    return p;
}


/**
  param n_length: key size in bits.
  Returns The public and private key.
  {
    public_key: {n: "LARGENUMBER", g: "LARGENUMBER"},
    private_key: {lambda: "LARGENUMBER", mu: "LARGENUMBER"}
  }
 */
exports.generate_paillier_keypair = function(n_length){
    var keysize;
    if(n_length == undefined){
        console.log("Using default key size");
        keysize = 1024;
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

    var pubKey = publicKey(g, n);
    var keypair = {
        public_key: pubKey,
        private_key: privateKey(phi_n, mu, pubKey),
        n_length: keysize
    };


    return keypair;
};

