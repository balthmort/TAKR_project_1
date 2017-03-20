#!/usr/bin/env python3
# author:   Petr Surý
# Date:     7.3.2017
# File:     TAKR_project1.py
# Project:  TAKR project

import sys
from lib import param_parser
from lib import compute_aes
from lib import compute_rsa
from lib import keys

if __name__ == "__main__":
    param = param_parser.ParseParams()

    if(param.subparser == "encrypt"):
        sys.stderr.write("Encrypt\n")

        if(param.encryption_param):  # AES
            if(param.key_file is None):
                key = keys.generateAESKey()
                keys.storeKey(key, "generatedAES.key")
            else:
                key = keys.readAESKey(param.key_file)

            compute_aes.encrypt_AES(key, param.input_file, param.output_file)
        else:  # RSA
            if(param.key_file is None):
                key = keys.generateRSAKeys()
                keys.storeKey(key, "generatedRSA.key")
                key = keys.RSAPublic("generatedRSA.key")
            else:
                key = keys.RSAPublic(param.key_file)

            compute_rsa.encrypt_RSA(key, param.input_file, param.output_file)
    elif(param.subparser == "decrypt"):
        sys.stderr.write("Decrypt\n")
        if(param.decryption_param):  # AES
            key = keys.readAESKey(param.key_file)

            compute_aes.decrypt_AES(key, param.input_file, param.output_file)
        else:  # RSA
            key = keys.RSAPrivate(param.key_file)

            compute_rsa.decrypt_RSA(key, param.input_file, param.output_file)
    elif(param.subparser == "gen"):
        sys.stderr.write("Generate keys\n")
        if(param.generate_param):  # AES
            keys.storeKey(
                    keys.generateAESKey(),
                    param.generate_output)
        else:  # RSA
            keys.storeKey(
                    keys.generateRSAKeys(),
                    param.generate_output)
    else:
        param.help_print()
