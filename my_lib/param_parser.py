#!/usr/bin/env python3
# author:   Petr Surý
# Date:     7.3.2017
# File:     parser.py
# Project:  TAKR project

import argparse


class ParseParams(object):
    # {{{
    encryption_param = None
    decryption_param = None
    input_file = None
    output_file = None
    key_file = None
    generate_param = None
    generate_output = None
    subparser = None
    parser = None

    def __init__(self):
        # {{{
        self.parser = argparse.ArgumentParser(
                prog="TAKR Project 1",
                description='''
                TAKR - Project 1
                Script for encrypting/decrypting text file with RSA or AES
                ''')

        self.parseParams(self.parser)
        # }}}

    def help_print(self):
        # {{{
        self.parser.print_help()
        # }}}

    def parseParams(self, parser):
        # {{{
        # {{{ Generic parser
        parser.add_argument(
                "--version", action="version",
                version="%(prog)s 1.0")
        # }}}

        # {{{ Create subparsers
        subparsers = parser.add_subparsers(
                dest="subparser",
                title="subcommands",
                description="Generate keys only or encrypt/decrypt file",
                help="additional help")
        # }}}

        # {{{ Parser for encrypting
        parser_encryption = subparsers.add_parser(
                "encrypt",
                help="Encrypt file")

        type_of_encryption = parser_encryption.add_mutually_exclusive_group(
                required=True)
        type_of_encryption.add_argument(
                "-A", "--AES",
                help="Encrypt file with AES",
                dest="encryption_param",
                action="store_true")

        type_of_encryption.add_argument(
                "-R", "--RSA",
                help="Encrypt file with RSA",
                dest="encryption_param",
                action="store_false")

        parser_encryption.add_argument(
                "-f", "--file",
                help="input file. Default: file.input",
                required=False,
                default="file.input")

        parser_encryption.add_argument(
                "-o", "--output",
                help="Output file. Default: file.output",
                required=False,
                default="file.output")

        parser_encryption.add_argument(
                "-k", "--key",
                help="Key file for encryption.\
                If not set, key will be randomly generated.",
                default=None,
                required=False)
        # }}}

        # {{{ Parser for decrypting
        parser_decryption = subparsers.add_parser(
                "decrypt",
                help="Decrypt file")

        type_of_decryption = parser_decryption.add_mutually_exclusive_group(
                required=True)
        type_of_decryption.add_argument(
                "-A", "--AES",
                help="Decrypt AES file",
                dest="decryption_param",
                action="store_true")

        type_of_decryption.add_argument(
                "-R", "--RSA",
                help="Decrypt RSA file",
                dest="decryption_param",
                action="store_false")

        parser_decryption.add_argument(
                "-f", "--file",
                help="input file. Default: file.input",
                required=False,
                default="file.input")

        parser_decryption.add_argument(
                "-o", "--output",
                help="Output file. Default: file.output",
                required=False,
                default="file.output")

        parser_decryption.add_argument(
                "-k", "--key",
                help="Key file for decryption. Default: generated.key",
                required=True,
                default="generated.key")
        # }}}

        # {{{ Parser for generating keys
        parser_generate = subparsers.add_parser(
                "gen",
                help="Generate keys")

        aes_rsa = parser_generate.add_mutually_exclusive_group(
                required=True)
        aes_rsa.add_argument(
                "-A", "--AES",
                help="Generate AES key for encrypt/decrypt",
                dest="generate_param",
                action="store_true")

        aes_rsa.add_argument(
                "-R", "--RSA",
                dest="generate_param",
                help="Generate RSA key pair for encrypt/decrypt",
                action="store_false")

        parser_generate.add_argument(
                "-o", "--output",
                help="Generated key file. Default: generated.key",
                dest="generate_output",
                required=False,
                default="generated.key")
        # }}}

        arguments = parser.parse_args()

        self.subparser = arguments.subparser

        if self.subparser == "encrypt":
            self.encryption_param = arguments.encryption_param
            self.input_file = arguments.file
            self.output_file = arguments.output
            self.key_file = arguments.key
        elif self.subparser == "decrypt":
            self.decryption_param = arguments.decryption_param
            self.input_file = arguments.file
            self.output_file = arguments.output
            self.key_file = arguments.key
        elif self.subparser == "gen":
            self.generate_param = arguments.generate_param
            self.generate_output = arguments.generate_output
        # }}}
    # }}}
