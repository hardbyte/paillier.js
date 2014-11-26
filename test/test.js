var phe = require('../');
var test = require('tape');
var bn = require('jsbn');

// We have to finish in ~10 minutes for travis not to give up
var ONLY_FAST = true;

function generateRandomNumbers(n){
    var results = [];
    for (var i = 0; i < n; i++) {
        results.push(Math.floor(Math.random() * Math.pow(2, 16)));
    }
    return results;
}

var keypairs = [];

test('Generate paillier keypairs', function (t) {
    var keyLengthsToTest = [128, 256, 512, 1024];

    if(!ONLY_FAST) {
        Array.prototype.push.apply(keyLengthsToTest, [2048, 4096]);
    }

    t.plan(keyLengthsToTest.length);

    keyLengthsToTest.forEach(function (keyLength) {
        var keypair = phe.generate_paillier_keypair(keyLength);
        t.equal(keypair.n_length, keyLength, "keypairs should be correct length");
        keypairs.push(keypair);

        console.log("Keypair serilization test:\n" + JSON.stringify(keypair));
    });

});

test('Random int encryption/decryption', function (t) {

    var numbersToTest = generateRandomNumbers(3);
    t.plan(keypairs.length * numbersToTest.length * 2);

    keypairs.forEach(function(keypair){
        numbersToTest.forEach(function(number_to_encrypt){
            console.log("Number we are encrypting: " + number_to_encrypt);
            var plaintextString = number_to_encrypt.toString();
            console.log("Encrypting with key of length " + keypair.n_length);
            var testCipher = keypair.public_key.raw_encrypt(plaintextString);
            t.notEqual(testCipher.toString(), plaintextString, "Ciphertext should not be equal to the plaintext");
            var possiblePlaintext = keypair.private_key.raw_decrypt(testCipher);
            t.equal(possiblePlaintext.intValue(), number_to_encrypt, "Decryption should match original");
        });
    });
});


test('Encrypt/Decrypt large number', function (t) {
    t.plan(2 * keypairs.length);
    keypairs.forEach(function(keypair){
        var data = "123456789123456789123456789123456789";
        var ciphertext = keypair.public_key.raw_encrypt(data);
        // Note this assumes the data integer is representable with the given keypair
        t.notEqual(ciphertext.toString(), data, "Ciphertext should not be equal to the plaintext");
        var decryption = keypair.private_key.raw_decrypt(ciphertext).toString();
        t.equal(decryption, data, 'Decrypted value should be same as input');
    });
});


test('ModuloN', function(t){
    t.plan(3);
    var keypair = keypairs[keypairs.length-1];

    // Check encryption/decryption works for n - 1
    var plaintext1 = keypair.public_key.n.subtract(bn.ONE);
    console.log('The plaintext to encrypt: ');
    console.log(plaintext1.toString());
    var ciphertext1 = keypair.public_key.raw_encrypt(plaintext1.toString());
    t.equal(plaintext1.toString(), keypair.private_key.raw_decrypt(ciphertext1).toString());

    // Check decryption wraps for n to 0
    var plaintext2 = keypair.public_key.n;
    var ciphertext2 = keypair.public_key.raw_encrypt(plaintext2);
    t.equal('0', keypair.private_key.raw_decrypt(ciphertext2).toString());

    // Check decryption wraps for n + 1 to 1
    var plaintext3 = keypair.public_key.n.add(bn.ONE);
    var ciphertext3 = keypair.public_key.raw_encrypt(plaintext3);
    t.equal('1', keypair.private_key.raw_decrypt(ciphertext3).toString());

});