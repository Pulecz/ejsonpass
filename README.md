# eJSONPass

Simple decrypt/encrypt password database in encrypted json which authenticates via key loaded in ssh-agent.

# Requirements
* python3
*	paramiko - for SSH key authentication
*	cryptography - for cryptography

# Usage

Run the script with some ssh key in ssh-agent loaded (ssh-add):
On first run provide path to parameter after flag -k, this key will be needed to access the DB.

During first run you can also provide -w and key of the first password.

Then use -r and -w KEY with the ssh-agent in shell loaded.