var phe = require('../');
var test = require('tape');
var bn = require('jsbn');

// We have to finish in ~10 minutes for travis not to give up
var keypair = phe.generate_paillier_keypair(256);
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

    t.equals(0, enc.exponent);
    t.equals("15", enc.encoding.toString());
});

test("Decode Int 0", function (t) {
    t.plan(1);
    var enc = phe.EncodedNumber.encode(pub, 15);
    t.equals(15, enc.decode());
});

test('Encode Int Number 1', function(t){
    t.plan(2);
    // A small negative number
    var number = -15;
    var enc = phe.EncodedNumber.encode(pub, number);

    t.equals(0, enc.exponent);
    t.equals("-15", enc.encoding.toString());
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
    var enc = phe.EncodedNumber.encode(pub, number);
    t.equals(number, enc.decode());
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

//test("Encode Int Too Large Positive", function (t) {
//    t.plan(1);
//    var number = 1 + parseInt(pub.max_int.toString());
//    t.throws(
//        function(){phe.EncodedNumber.encode(pub, number);}, "ValueError"
//    );
//});