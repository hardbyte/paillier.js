var phe = require('../');
var test = require('tape');
var bn = require('jsbn');

function generateRandomNumbers(n){
    var results = [];
    for (var i = 0; i < n; i++) {
        results.push(Math.floor(Math.random() * Math.pow(2, 16)));
    }
    return results;
}

var keypairs = [];

test('Generate paillier keypairs', function (t) {
    var keyLengthsToTest = [64, 128, 256, 512
        // commented out in the interests of testing speed during development
        //,1024, 2048
    ];

    t.plan(keyLengthsToTest.length);

    keyLengthsToTest.forEach(function (keyLength) {
        var keypair = phe.generate_paillier_keypair(keyLength);
        t.equal(keypair.n_length, keyLength, "keypairs should be correct length");
        keypairs.push(keypair);

        //console.log("Private key:\n" + JSON.stringify(keypair.private_key));
        //console.log("Public key:\n" + JSON.stringify(keypair.public_key));
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
            t.notEqual(testCipher.toString(), plaintextString);
            var possiblePlaintext = keypair.private_key.raw_decrypt(testCipher);
            t.equal(possiblePlaintext.intValue(), number_to_encrypt, "Decryption should match original");
        });
    });
});


test('Encrypt/Decrypt large number', function(t){
    t.plan(1);
    var data = "123456789123456789123456789123456789";

    var keypair = phe.generate_paillier_keypair();
    var ciphertext = keypair.public_key.raw_encrypt(data);
    var decryption = keypair.private_key.raw_decrypt(ciphertext).toString();
    t.equal(decryption, data, 'Decrypted value should be same as input');
});

test('ModuloN', function(t){
    t.plan(1);

    var keypair = phe.generate_paillier_keypair();
    // Check encryption/decryption works for n - 1
    var plaintext1 = keypair.public_key.n.subtract(bn.ONE);
    console.log('The plaintext to encrypt: ');
    console.log(plaintext1.toString());
    var ciphertext1 = keypair.public_key.raw_encrypt(plaintext1.toString());

    t.equal(plaintext1.toString(), keypair.private_key.raw_decrypt(ciphertext1).toString());

});