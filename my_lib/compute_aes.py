#!/usr/bin/env python3
# author:   Petr Surý
# Date:     7.3.2017
# File:     compute_aes.py
# Project:  TAKR project

import sys
from Cryptodome.Cipher import AES


class encrypt_AES(object):
    # {{{
    cipher = None
    ciphertext = None
    tag = None

    def __init__(self, key, input_file, output_file):
        # {{{
        sys.stderr.write("Encrypt AES\n")

        self.cipher = AES.new(key, AES.MODE_EAX)
        self.do_encrypt(self.cipher, input_file)
        self.save_into_file(output_file)

        sys.stderr.write("Encryption done\n")
        # }}}

    def do_encrypt(self, cipher, input_file):
        # {{{
        sys.stderr.write("Encryption in progress\n")
        with open(input_file, "rb") as data:
            self.ciphertext, self.tag = cipher.encrypt_and_digest(data.read())
        # }}}

    def save_into_file(self, output_file):
        # {{{
        sys.stderr.write("Saving encrypted file\n")
        with open(output_file, "wb") as file_out:
            [file_out.write(x) for x in (self.cipher.nonce, self.tag, self.ciphertext)]
        # }}}
    # }}}


class decrypt_AES(object):
    # {{{
    data = None

    def __init__(self, key, input_file, output_file):
        # {{{
        sys.stderr.write("Decrypt AES\n")

        self.do_decrypt(key, input_file)
        self.save_into_file(output_file)

        sys.stderr.write("Decryption done\n")
        # }}}

    def do_decrypt(self, key, input_file):
        # {{{
        sys.stderr.write("Decryption in progress\n")
        with open(input_file, "rb") as encrypted_file:
            nonce, tag, ciphertext = [encrypted_file.read(x) for x in (16, 16, -1)]
        cipher = AES.new(key, AES.MODE_EAX, nonce)
        self.data = cipher.decrypt_and_verify(ciphertext, tag)
        # }}}

    def save_into_file(self, output_file):
        # {{{
        sys.stderr.write("Saving decrypted file\n")
        with open(output_file, "w") as output_file:
            output_file.write(self.data.decode())
        # }}}

    # }}}
