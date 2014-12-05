var phe = require('../');

var keyLengths = [128, 256, 512, 1024, 2048, 4096];

keyLengths.forEach(function (keyLength) {
    console.time(keyLength);
    phe.generate_paillier_keypair(keyLength);
    console.timeEnd(keyLength);
});
