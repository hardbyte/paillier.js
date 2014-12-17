var phe = require('../');
var test = require('tape');
var bn = require('jsbn');

// We have to finish in ~10 minutes for travis not to give up
var keypair = phe.generate_paillier_keypair(512);
var pub = keypair.public_key;

test('Encoded Number Regression', function(t){
    t.plan(1);
    var number = 12345;
    var publicKey = phe.publicKey("6497955158", "126869");
    var enc = phe.EncodedNumber.encode(publicKey, number);

    t.equals(enc.decode(), number);
});

test('Encode Int 0', function(t){
    t.plan(2);
    // A small positive number
    var number = 15;
    var enc = phe.EncodedNumber.encode(pub, number);

    t.equals("0", enc.exponent.toString());
    t.equals("15", enc.encoding.toString());
});

test('Encode Int String 0', function(t){
    t.plan(2);
    // A small positive number
    var number = "15";
    var enc = phe.EncodedNumber.encode(pub, number);

    t.equals("0", enc.exponent.toString());
    t.equals("15", enc.encoding.toString());
});

test("Decode Int 0", function (t) {
    t.plan(1);
    var enc = phe.EncodedNumber.encode(pub, 15);
    t.equals(15, enc.decode());
});

test('Encode Int 1', function(t){
    t.plan(3);
    // A small negative number
    var number = -15;
    var enc = phe.EncodedNumber.encode(pub, number);

    t.equals("0", enc.exponent.toString());
    t.notEqual("-15", enc.encoding.toString());
    t.equal(
        (new bn('-15', 10)).mod(pub.n).toString(),
        enc.encoding.toString());
});


test("Decode Int 1", function (t) {
    t.plan(1);
    var enc = phe.EncodedNumber.encode(pub, -15);
    t.equals(-15, enc.decode());
});

test('Encode Decode Int 2', function(t){
    t.plan(1);
    // A large positive number
    var number = Math.pow(2, 140);
    console.log(number.toString(16));
    var enc = phe.EncodedNumber.encode(pub, number);
    t.equals(enc.decode().toString(16), number.toString(16));
});

test('Encode Decode Int 3', function(t){
    t.plan(1);
    // A large positive number
    var number = Math.pow(-2, 140);
    var enc = phe.EncodedNumber.encode(pub, number);
    t.equals(number, enc.decode());
});

test('Encode Decode Int 4', function(t){
    t.plan(1);
    // The largest positive number
    var number = parseInt(pub.max_int.toString());
    var enc = phe.EncodedNumber.encode(pub, number);
    t.equals(number, enc.decode());
});

test('Encode Decode Int 5', function(t){
    t.plan(1);
    // The largest negative number
    var number = -1 * parseInt(pub.max_int.toString());
    var enc = phe.EncodedNumber.encode(pub, number);
    t.equals(number, enc.decode());
});

test("Encode Int Too Large Positive", function (t) {
    t.plan(1);

    /**
     * Since we want to use realistic sized keys (> 512bit)
     * this test can't pass a Javascript Number into encode
     * So we pass in a decimal string.
     * */
    var number = pub.max_int.add(bn.ONE).toString(10);

    t.throws(
        function(){
            phe.EncodedNumber.encode(pub, number);
        }, "ValueError"
    );
});