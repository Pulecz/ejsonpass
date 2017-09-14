#!/usr/bin/env python

"""
verifies ssh key and load passwords_db in encrypted pickle

important:
    path to key can't change
    if fingerprint of the key changes, you will have to make new fingerptints_db
    base64 of the key is used to encrypt (probably bad idea?) the password_db, IF YOU LOSE THE KEY, YOU LOSE THE DB!
"""

#2017.8.29 - V 0.1 initial logic, setup ssh key to verify and load

import getpass #for prompting the pass on init
import paramiko #for handling ssh key
import pickle #rick
import os #for checking files
import sys #for correct $?

#config
path_to_key = "/home/pulec/.ssh/github" #must be private key
fingerprints_db = 'fingerprints.dat'
passwords_db = 'vesla.db'

def setup():
    "Runs on first start, creates config"
    print("Loading key, enter password for it, so its fingerprint is verified in ssh-agent")
    prompt_password = getpass.getpass('File {}, enter password:'.format(path_to_key))
    def try_load_private_key(path, password):
        try:
            key = paramiko.RSAKey.from_private_key_file(path, password=password)
            return key
        except paramiko.SSHException as e:
            print(e)
            print('Probably bad password?')
            return False
    key = try_load_private_key(path_to_key, prompt_password)
    if key:
        print("OK: Saving fingerprint for key: {}".format(path_to_key))
        rick = {
                path_to_key : key.get_fingerprint()
                }
        pickle.dump(rick, open(fingerprints_db, 'wb'))
        return True
    else:
        #bad password
        print("ERROR: badd password for the key intered. EXIT 1")
        sys.exit(1)

def verify_key_fingerprint():
    fingerprints = pickle.load(open(fingerprints_db, 'rb'))
    #select fingerprint by the path of the key
    target_fingerprint = fingerprints.get(path_to_key)
    if target_fingerprint:
        return target_fingerprint

if not os.path.exists(fingerprints_db):
    setup() #ask for password for key, creates fingerprint
    target_fingerprint = verify_key_fingerprint()
else:
    #load stuff
    target_fingerprint = verify_key_fingerprint()

#instance an agent
Agent = paramiko.Agent()
#find our ssh key in it
for key in Agent.get_keys():
    if key.get_fingerprint() == target_fingerprint:
        #do main thing
        print('yay')
        if not os.path.exists(passwords_db):
            print('No passwords db, creating one and asking you for passwords')
            #todo_save_pass()
        #now based on the input load the specific key
        #todo load_pass
        sys.exit(0)
else:
    print('ERROR: Target key not loaded in ssh-agent')
    sys.exit(2)
