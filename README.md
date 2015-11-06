
# paillier.js

A pure javascript implementation of [python-paillier](https://github.com/NICTA/python-paillier).

Currently relies on jsbn and crypto.

[![Build Status](https://travis-ci.org/hardbyte/paillier.js.svg)](https://travis-ci.org/hardbyte/paillier.js)

## What is done?

- [x] Generate paillier keypairs
- [ ] Raw encryption of integers
  - [x] Raw encryption of small integers (less than 2^16)
  - [x] Deal with encrypting large numbers (see [shortcut](https://github.com/NICTA/python-paillier/blob/master/phe/paillier.py#L129))
- [x] Raw decryption of ciphertext strings into integers
- [ ] Encoded Number
- [ ] Full test coverage
  - [ ] Port of python-paillier's [raw encryption tests](https://github.com/NICTA/python-paillier/blob/master/phe/tests/paillier_test.py#L75)
  - [ ] Port of python-paillier's [encoded number tests](https://github.com/NICTA/python-paillier/blob/master/phe/tests/paillier_test.py#L134)
  - [ ] Port of python-paillier's [encrypted number tests](https://github.com/NICTA/python-paillier/blob/master/phe/tests/paillier_test.py#L332)
  - [ ] Port of python-paillier's [keyring tests](https://github.com/NICTA/python-paillier/blob/master/phe/tests/paillier_test.py#L963)
  - [ ] in-browser tests ([crypto-browserify](https://github.com/dominictarr/crypto-browserify) may come in handy)


## Paillier Cryptosystem


The homomorphic properties of the paillier crypto system are:

* Encrypted numbers can be multiplied by a non encrypted scalar.
* Encrypted numbers can be added together.
* Encrypted numbers can be added to non encrypted scalars.

