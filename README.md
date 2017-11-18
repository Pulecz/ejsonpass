# ePicklePass

Simple decrypt/encrypt password database in encrypted json which authenticates via key loaded in ssh-agent.

# Requirements
* python3
*	paramiko - for SSH key authentication
*	cryptography - for cryptography

# Usage

Run the script with some ssh key in ssh-agent loaded:

3 modes:
* --init|-i:
	* For first time setup only, requires path to some public ssh-key

* --write|-w:
	* requires the key to save the password under

* --read|-r:
	* requires the key to read from passwords
