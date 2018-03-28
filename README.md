# Check Pwned Password

The basic principle of this script is to hash an inputed password, keep the first five characters of the hash, and request a list of pwned password beginning with these letters.
Once the list is retrieved, the script simply check whether the hash is present.
Thus, no password (nor full hash) is sent as cleartext.
