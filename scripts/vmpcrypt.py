from VMPC import VMPC
import sys, select, getpass, os, time, getopt, hashlib
ivlength = 16

if sys.argv[1] == "selftest":
    if VMPC("key").selftest():
        sys.stdout.write("Passed Test\n")
    else:
        sys.stdout.write("Failed Test\n")
    sys.exit(0)

try:
    mode = sys.argv[1]
except IndexError as ier:
    print "Error: Did you forget encrypt/decrypt?"
    sys.exit(1)

input_filename = sys.argv[2]
output_filename = sys.argv[3]

try:
    infile = open(input_filename, "r")
except IOError as ier:
    print "Input file not found."
    sys.exit(1)

try:
    outfile = open(output_filename, "w")
except IOError as ier:
    print "Output file not found."
    sys.exit(1)

try:
    key = sys.argv[4]
except IndexError as ier:
    key = getpass.getpass("Enter key: ")

salt = hashlib.sha256(key).digest()
key = hashlib.pbkdf2_hmac('sha256', key, salt, 100000)

data = infile.read()
infile.close()
start = time.time()

if mode == "encrypt":
    iv = os.urandom(ivlength)
    cipher_text = VMPC(key).crypt(data, iv)
    outfile.write(iv+cipher_text)
elif mode == "decrypt":
    iv = data[:ivlength]
    msg = data[ivlength:]
    outfile.write(VMPC(key).crypt(msg, iv))
outfile.close()

end = time.time() - start
bps = len(data) / end
sys.stdout.write("Completed in "+str(end)+" seconds\n")
sys.stdout.write(str(bps)+" bytes per second.\n")
