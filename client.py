import time
import random
import socket
import pickle
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

class Client:

    def __init__(self, client_id, pr_key, pu_key, pkda_pu_key):
        self.pr_key = pr_key
        self.client_id = client_id
        self.pkda_pu_key = pkda_pu_key
        self.pu_key = pu_key
        self.mappings = {}
    
    def Generate_msg_for_pkda(self, client_id: int):
        message = (client_id, self.Time(), self.Gen_Nonce())
        return RSA.Encryption(message, self.pkda_pu_key)
    
    def Msg_from_pkda(self, message):
        x, y, client_id, t2, n2 = RSA.Decryption(message, self.pkda_pu_key)
        if x is not None and y is not None and client_id is not None:
            self.mappings[client_id] = (x, y)
            return (x, y, client_id, t2, n2)
        else:
            return None  # Handled the case where Decryption fails


    def Msg_for_client(self, client_id: int, msg: str, nonce=None):
        n1 = -1
        if nonce is not None:
            n1 = self.Res_Nonce(nonce)
        else:
            n1 = self.Gen_Nonce()
            
        message = [self.Time(), n1, self.client_id]
        message.extend(RSA.RSA_Encode(msg))
        
        return (RSA.Encryption(message, key=self.mappings.get(client_id)),n1)

    def Msg_from_client(self, message):
        tup = RSA.Decryption(message, self.pr_key)
        return (tup[0], tup[1], tup[2], RSA.RSA_Decode(tup[3:]))

    def Gen_Nonce(self):
        ans = random.randint(1, self.pu_key[1] - 2)
        return ans

    @staticmethod
    def Res_Nonce(n):
        ans = n + 1
        return ans
    
    @staticmethod
    def Time():
        ans = int(time.time())
        return ans

    def Req_pu_k_from_pkda(self,pkda_address, m):
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect(pkda_address)
        
        try:
            # Send client name to PKDA
            serialized_data = pickle.dumps(m)
            client_socket.sendall(serialized_data)
            received_data = client_socket.recv(4096)
            received_tuple = pickle.loads(received_data)
            public_key = self.Msg_from_pkda(received_tuple)
            return public_key
        
        finally:
            client_socket.close()


if __name__=="__main__":
    global_mappings = { 1:(), 2:() }
    file1 = open('A_pu_k.txt', 'r')
    count = 0
    x=[]
    for line in file1:
        count += 1
        x.append(int(line.strip()))
    global_mappings[1] = tuple(x)
    file1.close()
    file1 = open('B_pu_k.txt', 'r')
    count = 0
    x=[]
    for line in file1:
        count += 1
        x.append(int(line.strip()))
    global_mappings[2] = tuple(x)
    file1.close()
    file1 = open('A_pr_k.txt', 'r')
    count = 0
    x=[]
    for line in file1:
        count += 1
        x.append(int(line.strip()))
    A_pr_k = tuple(x)
    file1.close()
    file1 = open('B_pr_k.txt', 'r')
    count = 0
    x=[]
    for line in file1:
        count += 1
        x.append(int(line.strip()))
    B_pr_k = tuple(x)    
    file1.close()
    file1 = open('pkda_pu_k.txt', 'r')
    count = 0
    x=[]
    for line in file1:
        count += 1
        x.append(int(line.strip()))
    pkda_pu_k = tuple(x)    
    file1.close()
    client_id = int(input("Enter Client ID: "))
    if client_id == 1:
        cl = Client(client_id=1, pr_key=A_pr_k, pu_key=global_mappings[1], pkda_pu_key=pkda_pu_k)
        # A requests B's public key from PKDA
        m = cl.Generate_msg_for_pkda(client_id=2)
        # Define PKDA server address and port
        pkda_server_address = ('localhost', 12345)
        other_client_pu_k = cl.Req_pu_k_from_pkda(pkda_server_address,m)
        print(other_client_pu_k)
        
        a=1
        while a==1:
            try:
                client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                B_address = ('172.20.10.3', 8080)
                
                client_socket.connect(B_address)
                
                m,n_A=cl.Msg_for_client(2,msg="Lets Talk")
                serialized_data = pickle.dumps(m)
                client_socket.sendall(serialized_data)


                received_data = client_socket.recv(4096)
                received_tuple = pickle.loads(received_data)
                m_from_B = cl.Msg_from_client(received_tuple)
                
                if int(m_from_B[3])==n_A+1:
                    m,x=cl.Msg_for_client(2,msg=str(cl.Res_Nonce(m_from_B[1])))
                    print(m)
                    serialized_data = pickle.dumps(m)
                    client_socket.sendall(serialized_data)
                time.sleep(1)
                message,x = cl.Msg_for_client(2, msg="hi1")
                serialized_data = pickle.dumps(message)
                client_socket.sendall(serialized_data)
                received_data = client_socket.recv(4096)
                received_tuple = pickle.loads(received_data)
                message_from_B = cl.Msg_from_client(received_tuple)
                print(message_from_B)

                message,x = cl.Msg_for_client(2, msg="hi2")
                serialized_data = pickle.dumps(message)
                client_socket.sendall(serialized_data)
                received_data = client_socket.recv(4096)
                received_tuple = pickle.loads(received_data)
                message_from_B = cl.Msg_from_client(received_tuple)
                print(message_from_B)

                message,x = cl.Msg_for_client(2, msg="hi3")
                serialized_data = pickle.dumps(message)
                client_socket.sendall(serialized_data)
                received_data = client_socket.recv(4096)
                received_tuple = pickle.loads(received_data)
                message_from_B = cl.Msg_from_client(received_tuple)
                print(message_from_B)
                a=2
            except Exception as e:
                a=1
            

    else:
        cl = Client(client_id=2, pr_key=B_pr_k, pu_key=global_mappings[2], pkda_pu_key=pkda_pu_k)
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_address = ('172.20.10.3', 8080)
        server_socket.bind(server_address)
        server_socket.listen(1)

        print("Client B is listening...")

        while True:
            # Wait for a connection
            connection, client_address = server_socket.accept()
            print("Connection from", client_address)
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            m_from_A = cl.Msg_from_client(received_tuple)
            # B requests A's public key from PKDA
            m = cl.Generate_msg_for_pkda(client_id=1)
            pkda_server_address = ('localhost', 12345)
            other_client_pu_k = cl.Req_pu_k_from_pkda(pkda_server_address,m)
            #printing the requested public key
            print(other_client_pu_k)
            m_for_A,n_B = cl.Msg_for_client(1,msg=str(cl.Res_Nonce(m_from_A[1])))
            serial_data = pickle.dumps(m_for_A)
            connection.sendall(serial_data)
            time.sleep(1)
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            print(received_tuple)
            m_from_A = cl.Msg_from_client(received_tuple)
            print(m_from_A)
            if int(m_from_A[3]) == n_B+1:
                print("Connection Successful!")
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            message_from_A = cl.Msg_from_client(received_tuple)
            print(message_from_A)
            if message_from_A[3] == "hi1":
                revert,x = cl.Msg_for_client(1, msg="gotit1")
                serial_data = pickle.dumps(revert)
                connection.sendall(serial_data)
            time.sleep(1)
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            message_from_A = cl.Msg_from_client(received_tuple)
            print(message_from_A)
            if message_from_A[3] == "hi2":
                revert,x = cl.Msg_for_client(1, msg="gotit2")
                serial_data = pickle.dumps(revert)
                connection.sendall(serial_data)
            
            received_data = connection.recv(4096)
            received_tuple = pickle.loads(received_data)
            message_from_A = cl.Msg_from_client(received_tuple)
            print(message_from_A)
            if message_from_A[3] == "hi3":
                revert,x = cl.Msg_for_client(1, msg="gotit3")
                serial_data = pickle.dumps(revert)
                connection.sendall(serial_data)
            break

    