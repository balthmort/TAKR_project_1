#!/usr/bin/env python3
# author:   Petr Surý
# Date:     7.3.2017
# File:     keys.py
# Project:  TAKR project

import sys
from Cryptodome.Random import get_random_bytes
from Cryptodome.PublicKey import RSA


secret_code = "secret"


def generateAESKey():
    # {{{
    sys.stderr.write("Generate random AES key\n")
    return get_random_bytes(16)
    # }}}


def generateRSAKeys():
    # {{{
    private_key = RSA.generate(2048)
    encrypted_key = private_key.exportKey(
            passphrase=secret_code,
            pkcs=8,
            protection="scryptAndAES128-CBC")

    return encrypted_key
    # }}}


def readRSAKey(key_file):
    # {{{
    with open(key_file, "rb") as encrypted_key:
        imported_key = encrypted_key.read()
    key = RSA.import_key(imported_key, passphrase=secret_code)
    return key
    # }}}


def RSAPrivate(key_file):
    # {{{
    key = readRSAKey(key_file)
    return key
    # }}}


def RSAPublic(key_file):
    # {{{
    key = readRSAKey(key_file)
    return key.publickey()
    # }}}


def readAESKey(key_file):
    # {{{
    sys.stderr.write("Read key from file\n")
    with open(key_file, "rb") as key:
        return key.read()
    # }}}


def storeKey(key, key_file):
    # {{{
    sys.stderr.write("Saving key into " + key_file + "\n")
    with open(key_file, "wb") as key_file:
        key_file.write(key)
    # }}}
