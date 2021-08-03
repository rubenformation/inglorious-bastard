import sys
import hashlib
import readline

# Written By Ruben Enkaoua - GL4DI4T0R
# Inglorious Bastards suite
# python3 hashbastard.py

class k:
    B = '\033[94m'
    G = '\033[92m'
    W = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'

print("""


""")

for i in range(5):
	if i == 2:
		print(k.G + "          - - - - - - - - - - HASHBASTARD - - - - - - - - - -" + k.END)
	else:
		print(' +' * 36)

print("""


""")

mode = input(k.G + "[+] Select your hash type \t\t\t> " + k.END)
enc = input(k.G + "[+] Input your hash here \t\t\t> " + k.END)
wordlist = input(k.G + "[+] Enter the full path for your wordlist \t> " + k.END)

print("\n")

if False in {bool(mode), bool(enc), bool(wordlist)}:
	print(k.W + "[-] Empty parameter. You have to set a mode to continue" + k.END)
	sys.exit()
elif mode not in {'md5', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'}:
	print(k.W + "[-] Wrong hash mode" + k.END)
	sys.exit()
else:
	print(k.G + "[*] verify mode input... OK \t\t\t" + k.END)

try:
    with open(wordlist) as f:
        print(k.G + "[*] check for wordlist... OK \t\t\t" + k.END)
except IOError:
    print(k.W + "[-] The file is not accessible or doesn't exist" + k.END)
    sys.exit()

try:
    hexval = int(enc, 16)
    pass
except:
    print(k.W + "[-] Wrong hash. The hash must contain only hex characters" + k.END)
    sys.exit()
if (
	mode == 'md5' and len(enc) != 32
	or mode == 'sha1' and len(enc) != 40
	or mode == 'sha224' and len(enc) != 56
	or mode == 'sha256' and len(enc) != 64
	or mode == 'sha384' and len(enc) != 96
	or mode == 'sha512' and len(enc) != 128
	):
	print(k.W + "[-] Wrong hash length" + k.END)
	sys.exit()
else:
	print(k.G + "[*] verify hash input... OK \t\t\t\n" + k.END)

print(k.G + "[*] Hashbastard is starting... \t\t\t" + k.END)

if mode == 'md5':
	meth = hashlib.md5
elif mode == 'sha1':
	meth = hashlib.sha1
elif mode == 'sha224':
	meth = hashlib.sha224
elif mode == 'sha256':
	meth = hashlib.sha256
elif mode == 'sha384':
	meth = hashlib.sha384
elif mode == 'sha512':
	meth = hashlib.sha512

try:
	wordlist = open(wordlist, 'r')
	for password in wordlist.readlines():
		password = password.strip('\n')
		chall = meth(bytes(password,'utf-8')).hexdigest()
		if chall == enc:
			print(k.G + "[*] Password found: " + password + "\t\t\t" + k.END)
			sys.exit()
		elif chall != enc:
			continue
	print(k.W + "[-] The password is not in the wordlist" + k.END)
except Exception as exc:
	print(k.W + "[-] An error Occured %s" % (exc) + k.END)