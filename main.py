#!/usr/bin/env python

"""
verifies ssh key loaded in ssh-agent by fingerprint and loads passwords_db encrypted with the ssh key

important:
    * path to key is for what?
    * base64 of the key is used to encrypt the password_db, IF YOU LOSE THE KEY, YOU LOSE ACCESS TO THE DB!
"""

# 2017.8.29 - V 0.1 initial logic, setup ssh key to verify and load
# 2017.10.22 - V 0.2 remembering what was it about, thinking
# 2017.11.18 - V 0.3 cryptography for encryption of the passwords_db

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
path_to_key = "/home/pulec/.ssh/personal_github"  # must be private key
passwords_db = 'vesla.db'

#mode = 'write'
mode = 'read'

#params
#for both modes, which key to read
get_key = 'test01'


def setup_header_blop():
    "Runs on first start, creates"
    print("Loading key, enter password for it, so its fingerprint is verified in ssh-agent")
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
            print('Bad path_to_key provided')
            return False

    key = try_load_private_key(path_to_key, prompt_password)
    if key:
        fp = key.get_fingerprint()  # a 16-byte `string <str>` (binary) of the MD5 fingerprint, in SSH format
        salt = os.urandom(16)  # for encryption
        return fp + salt  # 32 bytes
    else:
        print("ERROR: bad password or bad path for the key entered. EXIT 1")
        sys.exit(1)


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
    token = f.encrypt(message)
    if mode == 'write':
        return token
    elif mode == 'read':
        return f.decrypt(message)


if __name__ == '__main__':
    if not os.path.exists(passwords_db):
        print('No passwords db, creating one')
        fp_salt_blop = setup_header_blop()
        with open(passwords_db, 'wb') as pdb_w_w:
            pdb_w_w.write(fp_salt_blop)
        # base done, continue to load agent's key
        key = verify_fp_in_ssh_agent(fp_salt_blop[:16])
        if mode == 'read':
            sys.exit(3)  # mode read selected on empty db
    else:
        with open(passwords_db, 'rb') as pdb_w_r:
            payload = pdb_w_r.read()
        fp_salt_blop = payload[:32]
        encrypted = payload[32:]
        # verify
        key = verify_fp_in_ssh_agent(fp_salt_blop[:16])

    if not key:
        print('ERROR: Target key not loaded in ssh-agent')
        sys.exit(2)
    # do main thing
    salt = fp_salt_blop[16:]
    # open the db
    secret_d = json.loads(fernet_crypto(salt, key.asbytes(), encrypted, mode='read'))

    # write mode
    if mode == 'write':
        if secret_d.get(get_key):
            print('Key {} already exists'.format(get_key))
        secret_d[get_key] = getpass.getpass('Enter value for the {}: '.format(get_key))
        # encrypt the secret_d again
        encrypted = fernet_crypto(salt, key.asbytes(), json.dumps(secret_d).encode(encoding='UTF-8'), mode='write')
        with open(passwords_db, 'wb') as pdb_w_w:
            pdb_w_w.write(fp_salt_blop + encrypted)
    # read mode
    if mode == 'read':
        secret_p = secret_d.get(get_key)
        if secret_p:
            print(secret_p)
        else:
            print('No value for key {}'.format(get_key))
    sys.exit(0)
