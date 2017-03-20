#!/usr/bin/env python3
# author:   Petr Surý
# Date:     7.3.2017
# File:     compute_rsa.py
# Project:  TAKR project

import sys
from Cryptodome.Cipher import AES, PKCS1_OAEP
from Cryptodome.Random import get_random_bytes


class encrypt_RSA(object):
    # {{{
    cipher = None
    ciphertext = None
    tag = None
    session_key = None

    def __init__(self, key, input_file, output_file):
        # {{{
        sys.stderr.write("Encrypt RSA\n")

        self.session_key = get_random_bytes(16)

        cipher = PKCS1_OAEP.new(key)

        with open(output_file, "wb") as file_out:
            file_out.write(cipher.encrypt(self.session_key))

        self.do_encrypt(self.session_key, input_file)
        self.save_into_file(output_file)

        sys.stderr.write("Encryption done\n")
        # }}}

    def do_encrypt(self, session_key, input_file):
        # {{{
        sys.stderr.write("Encryption in progress\n")

        with open(input_file, "rb") as data:
            self.cipher = AES.new(session_key, AES.MODE_EAX)
            self.ciphertext, self.tag = self.cipher.encrypt_and_digest(data.read())
        # }}}

    def save_into_file(self, output_file):
        # {{{
        sys.stderr.write("Saving encrypted file\n")
        with open(output_file, "ab") as file_out:
            [file_out.write(x) for x in (self.cipher.nonce, self.tag, self.ciphertext)]
        # }}}
    # }}}


class decrypt_RSA(object):
    # {{{
    data = None

    def __init__(self, key, input_file, output_file):
        # {{{
        sys.stderr.write("Decrypt RSA\n")

        self.do_decrypt(key, input_file)
        self.save_into_file(output_file)

        sys.stderr.write("Decryption done\n")
        # }}}

    def do_decrypt(self, key, input_file):
        # {{{
        sys.stderr.write("Decryption in progress\n")
        with open(input_file, "rb") as encrypted_file:
            session_key_encrypted, nonce, tag, ciphertext = [encrypted_file.read(x) for x in (key.size_in_bytes(), 16, 16, -1)]

        cipher_rsa = PKCS1_OAEP.new(key)
        session_key = cipher_rsa.decrypt(session_key_encrypted)

        # Decrypt the data with the AES session key
        cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
        self.data = cipher_aes.decrypt_and_verify(ciphertext, tag)
        # }}}

    def save_into_file(self, output_file):
        # {{{
        sys.stderr.write("Saving decrypted file\n")
        with open(output_file, "w") as output_file:
            output_file.write(self.data.decode())
        # }}}

    # }}}
