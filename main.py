#!/usr/bin/env python

"""
verifies ssh key loaded in ssh-agent by fingerprint
and loads passwords_db encrypted with the ssh key

important:
    * DB is encrypted using absolute bytes of an SSH-KEY,
      therefore if you move the DB, you have to move the key
      you used in first run as well
    * ..

todo:
    * if trying to read empty db, don't check by args,
      but by length of encrypted_db?
    * option to list saved passwords? secret_d.keys()

exits:
    0 - all fine
    1 - key not loaded in ssh-agent
    2 - trying to read empty db or no write command
    3 - no path for key provided during setup_header_blob()
    4 - badd password provided during setup_header_blob()
"""

# 2017.08.29 - V 0.1 initial logic, setup ssh key to verify and load
# 2017.10.22 - V 0.2 remembering what was it about, thinking
# 2017.11.18 - V 0.3 cryptography for encryption of the passwords_db
# 2017.11.20 - V 0.3.5 argparse implemented, now for tests

import os  # for checking files
import sys  # for correct $?
import json  # for password structure
import getpass  # for prompting the pass on init
import paramiko  # for handling ssh key
import argparse  # for cli usage
import base64  # for fernet_crypto_custom_password
from cryptography.fernet import Fernet  # for fernet_crypto
from cryptography.hazmat.backends import default_backend  # for fernet_crypto
from cryptography.hazmat.primitives import hashes  # for fernet_crypto
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # for fernet_crypto_custom_password


# config
passwords_db = 'vesla.db'


def setup_header_blop(path_to_key):
    "Runs on first start, creates"
    print("Loading key, enter password for it, so its fingerprint can be verified in ssh-agent")
    prompt_password = getpass.getpass('File {}, enter password:'.format(path_to_key))

    def try_load_private_key(path, password):
        try:
            key = paramiko.RSAKey.from_private_key_file(path, password=password)
            return key
        except paramiko.SSHException as sshe:
            print(sshe)
            print('Probably bad password?')
            return False
        except FileNotFoundError as fnfe:
            print(fnfe)
            print('No key on path {}'.format(path_to_key))
            return False

    key = try_load_private_key(path_to_key, prompt_password)
    if key:
        fp = key.get_fingerprint()  # a 16-byte `string <str>` (binary) of the MD5 fingerprint, in SSH format
        salt = os.urandom(16)  # for encryption
        return fp + salt  # 32 bytes
    else:
        raise ValueError


def verify_fp_in_ssh_agent(target_fingerprint):
    Agent = paramiko.Agent()
    for key in Agent.get_keys():
        if key.get_fingerprint() == target_fingerprint:
            return key


def fernet_crypto(salt, password, message, mode='read'):
    """Same example from documentation:
    https://cryptography.io/en/latest/fernet/?highlight=fernet#using-passwords-with-fernet
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    f = Fernet(key)
    if mode == 'write':
        token = f.encrypt(message)
        return token
    elif mode == 'read':
        return f.decrypt(message)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='eJSONPass')
    parser.add_argument('--read', '-r',
                        help='read mode, READ is key in DB')
    parser.add_argument('--write', '-w',
                        help='write mode, WRITE is key in DB')
    parser.add_argument('--path_to_key', '-k',
                        help='Path to your ssh key, only for creating new DB')

    args = parser.parse_args()

    if not os.path.exists(passwords_db):  # first run
        print('\nNo passwords db, creating: {}'.format(passwords_db))
        # path_to_key provided?
        if not args.path_to_key:
            print('You must provide path to private SSH key'
                  'after parameter [--path_to_key|-k]')
            sys.exit(3)
        try:  # verify SSH key by re-entering password
            fp_salt_blop = setup_header_blop(args.path_to_key)
        except ValueError:
            print("ERROR: bad password or bad path for the key entered.")
            sys.exit(4)
        # header (fingerprint + salt) can be saved
        with open(passwords_db, 'wb') as pdb_w_w:
            pdb_w_w.write(fp_salt_blop)
        print('DB created at {}'.format(passwords_db))
        # base done, continue to load agent's key
        key = verify_fp_in_ssh_agent(fp_salt_blop[:16])
        if args.read:
            print('Read mode read selected on empty db')
            sys.exit(2)
        elif not args.write:
            print('Write mode not selected, nothing to do')
            sys.exit(2)
        # can continue to write the first item
        encrypted_db = bytes()  # db is empty
    else:  # normal run
        if not args.read and not args.write:
            print('No mode not selected, nothing to do')
            sys.exit(2)
        with open(passwords_db, 'rb') as pdb_w_r:
            payload = pdb_w_r.read()
        fp_salt_blop = payload[:32]
        encrypted_db = payload[32:]
        # verify
        key = verify_fp_in_ssh_agent(fp_salt_blop[:16])

    if not key:
        print('ERROR: Target key not loaded in ssh-agent')
        sys.exit(1)

    # do main thing
    salt = fp_salt_blop[16:]
    # open the DB, if there is something
    if len(encrypted_db) > 1:
        secret_d = json.loads(
            fernet_crypto(salt, key.asbytes(),
                          encrypted_db, mode='read'))
    else:
        secret_d = {}  # DB is empty, make new one

    if args.write:  # write mode
        if secret_d.get(args.write):  # args.write is JSON key to get
            print('Key {} already exists'.format(args.write))
        secret_d[args.write] = getpass.getpass(
            'Enter value for the {}: '.format(args.write))
        # encrypt the secret_d again
        encrypted_db = fernet_crypto(
            salt, key.asbytes(),
            json.dumps(secret_d).encode(encoding='UTF-8'), mode='write')
        with open(passwords_db, 'wb') as pdb_w_w:
            pdb_w_w.write(fp_salt_blop + encrypted_db)
    if args.read:  # read mode
        secret_p = secret_d.get(args.read)  # args.read is JSON key to get
        if secret_p:
            print(secret_p)
        else:
            print('No value for key {}'.format(args.read))
    sys.exit(0)
