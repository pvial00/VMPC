class VMPC:
    def __init__(self, key):
        self.key = key

    def ksa(self, iv):
        P = []
        K = self.key
        c = len(self.key)
        s = 0
        for n in range(256):
            P.append(n)
        for m in range(768):
            n = m % 256
            s = P[(s + P[n] + ord(K[m % c])) % 256]
            P[n], P[s] = P[s], P[n]
        if iv != "":
            V = iv
            z = len(iv)
            for m in range(768):
                n = m % 256
                s = P[(s + P[n] + ord(V[m % z])) % 256]
                P[n], P[s] = P[s], P[n]
        return P, s

    def crypt(self, data, iv=""):
        cipher_text = ""
        n = 0
        P, s = self.ksa(iv)
        for byte in data:
            s = P[(s + P[n]) % 256]
            cipher_text += chr(ord(byte) ^ P[(P[P[s]]+1) % 256])
            P[n], P[s] = P[s], P[n]
            n = (n + 1) % 256
        return cipher_text

    def selftest(self):
        K = "9661410AB797D8A9EB767C21172DF6C7"
        V = "4B5C2F003E67F39557A8D26F3DA2B155"
        vectors = { 0:'a8', 1:'24', 2:'79', 3:'f5', 252:'b8', 253:'fc', 254:'66', 255:'a4', 1020:'e0',1021:'56', 1022:'40', 1023:'a5', 102396:'81', 102397:'ca', 102398:'49', 102399:'9a' }
        key = K.decode('hex')
        iv = V.decode('hex')
        nbytes = 102400
        testdata = chr(0) * nbytes
        cipher = VMPC(key)
        ctxt = cipher.crypt(testdata, iv)
        for key in vectors.keys():
            value = ctxt[key].encode('hex')
            vector = vectors[key]
            if value != vector:
                return False
        return True
