import time
import socket
import pickle
from Crypto.Util import number

class RSA:
    @staticmethod
    def Encryption(message: tuple, key: tuple):
        e, n = key
        
        cipher = []
        for m in message:
            cipher.append(RSA.RSA_Operation(m, e, n))
            
        return tuple(cipher)

    @staticmethod
    def Decryption(message: tuple, key: tuple):
        d, n = key
        
        plain = []
        for m in message:
            plain.append(RSA.RSA_Operation(m, d, n))
            
        return tuple(plain)

    @staticmethod
    def RSA_Operation(m, x, n):
        temp = 1

        if x == temp:
            p = m % n
            return p

        if x % 2 != 0:
            return ((((RSA.RSA_Operation(m, x // 2, n) % n) * (RSA.RSA_Operation(m, x // 2, n) % n)) % n) * m) % n
        else:
            return ((RSA.RSA_Operation(m, x // 2, n) % n) * (RSA.RSA_Operation(m, x // 2, n) % n)) % n
            

    @staticmethod
    def RSA_Encode(msg):
        tup = []
        char_map = {char: ord(char) - ord("a") for char in 'abcdefghijklmnopqrstuvwxyz'}
        char_map.update({str(i): 26 + i for i in range(10)})  # Mapping digits to ASCII values

        index = 0
        while index < len(msg):
            char = msg[index].lower()
            if char in char_map:
                tup.append(char_map[char])
            index += 1
        return tuple(tup)

    @staticmethod
    def RSA_Decode(tup):
        msg = ""
        char_map = {value: chr(value + ord("a")) for value in range(26)}
        char_map.update({value: chr(value - 26 + ord("0")) for value in range(26, 36)})  # Mapping ASCII values to characters

        index = 0
        while index < len(tup):
            char = tup[index]
            if char in char_map:
                msg += char_map[char]
            index += 1
        return msg
    
    def gcd(self,x, y, a, b, c, d):
        q = x // y
        c = a - (q * b)
        a = b
        b = c
        if x % y == 1:
            d[0] = c
        if x % y == 0:
            return y
        return self.gcd(y, x % y, a, b, c, d)

class PKDA:

    def __init__(self, mappings, pr_key, pu_key):
        self.pr_key = pr_key
        self.mappings = mappings
        self.pu_key = pu_key
    
    def Msg_from_client(self, message):
        client_id, t1, n1 = RSA.Decryption(message, self.pr_key)

        client_pu_key = self.mappings.get(client_id)
        if client_pu_key is not None:
            x, y = client_pu_key

            n2 = self.Res_Nonce(n1)

            t2 = self.Time()

            return RSA.Encryption((x, y, client_id, t2, n2), self.pr_key)
        else:
            return None  # Handle the case where client_id is not found in mappings

    
    @staticmethod
    def Res_Nonce(n):
        ans = n + 1
        return ans
    
    @staticmethod
    def Time():
        ans = int(time.time())
        return ans

if __name__=="__main__":
    global_mappings = { 1:() , 2: ()}
    for j in range(3):
        p=number.getPrime(8)
        q=number.getPrime(8)
        rsa = RSA()
        print(p,q)
        n=p*q
        phi=(p-1)*(q-1)
        t_i_minus_one = 0
        t_i = 1
        e = None
        d = [0]

        for i in range(2, phi):
            if rsa.gcd(phi, i, t_i_minus_one, t_i, 1, d) == 1:
                e = i
                if d[0] < 0:
                    d[0] = phi + d[0]
                break
            else:
                t_i_minus_one = 0
                t_i = 1

        print(p, q, n, phi, e, d[0])
        pr_key = (e,n)
        pu_key = (d[0],n)
        if j == 0:
            f = open("A_pu_k.txt", "w")
            f.write(str(d[0]))
            f.write("\n")
            f.write(str(n))
            f.close()
            f = open("A_pr_k.txt", "w")
            f.write(str(e))
            f.write("\n")
            f.write(str(n))
            f.close()
            global_mappings[1] = (d[0],n)
        if j == 1:
            f = open("B_pu_k.txt", "w")
            f.write(str(d[0]))
            f.write("\n")
            f.write(str(n))
            f.close() 
            f = open("B_pr_k.txt", "w")
            f.write(str(e))
            f.write("\n")
            f.write(str(n))
            f.close()
            global_mappings[2] = (d[0],n)
        if j == 2:
            f = open("pkda_pu_k.txt", "w")
            f.write(str(d[0]))
            f.write("\n")
            f.write(str(n))
            f.close()
    print(pr_key)
    print(global_mappings)
    pkda = PKDA(global_mappings, pr_key=pr_key, pu_key=pu_key)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_address = ('localhost', 12345)
    server_socket.bind(server_address)
    server_socket.listen(1)

    print("PKDA server is running...")

    while True:
        # Waiting for a connection
        connection, client_address = server_socket.accept()

        try:
            print("Connection from", client_address)
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            public_k_requested = pkda.Msg_from_client(received_tuple)
            serialized_data = pickle.dumps(public_k_requested)
            connection.sendall(serialized_data)
        finally:
            connection.close()
