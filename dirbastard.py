import sys
import requests
import readline
from urllib3.exceptions import InsecureRequestWarning

# Written By Ruben Enkaoua - GL4DI4T0R
# Inglorious Bastards suite
# command: python3 dirbastard.py

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
		print(k.G + "           - - - - - - - - - - DIRBASTARD - - - - - - - - - -" + k.END)
	else:
		print(' +' * 36)

print("""


""")

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

url = input(k.G + "[+] Input the target here \t\t\t> " + k.END)
wordlist = input(k.G + "[+] Enter the full path of your wordlist \t> " + k.END)

if url[-1] != '/':
	url = url + '/'

try:
	r = requests.get(url, timeout=2)
	if r.status_code in {404, 400, 409, 412}:
		print(k.W + "[-] Target unreachable" + k.END)
		sys.exit()
	else:
		print(k.G + "[*] check for target... OK \t\t\t" + k.END)
except Exception as exc:
	print(k.W + "\n[-] Target unreachable" + k.END)
	sys.exit()

try:
    with open(wordlist) as f:
        print(k.G + "[*] check for wordlist... OK \t\t\t" + k.END)
except IOError:
    print(k.W + "\n[-] The file is not accessible or doesn't exist" + k.END)
    sys.exit()

print("\n")

try:
	wordlist = open(wordlist, 'r')
	for word in wordlist.readlines():
		word = word.strip('\n')
		r = requests.get(url + word, timeout=1, verify=False)
		if r.status_code == 404:
			pass
		else:
			print(k.G + "[*] Found /" + word + k.B + " code: " + str(r.status_code) + k.END)
			print('-' * 30)
except Exception as exc:
	print(k.W + "[-] An error Occured %s" % (exc) + k.END)
