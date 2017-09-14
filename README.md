# ePicklePass

Simple decrypt/encrypt password database in encrypted pickle which authenticates via key loaded in ssh-agent.

# Requirements
* python3
*	paramiko - for SSH key authentication

# Usage

Edit config.ini (TODO)
	Enter path to the personal ssh-key
	Change filenames of the fingerprint and passwords db if you wish

Run it
Firt time setup - enter password for the ssh-key

If you have the ssh key loaded in ssh-agent it will let you continue
rest is TODO
