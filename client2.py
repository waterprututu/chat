from Crypto.PublicKey import RSA
from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import time
import socket
# import tqdm
# import os
import random

BUFFER_SIZE = 65535
SEPARATOR = "<SEPARATOR>"

s = socket.socket()

def rsa_encrypt(text, key):
    # with open('public_key.txt', 'rb') as file:
    #     key = file.read() #.replace('\n', '') u could use this if u were using strings
    #print(key)
    #key = hex2bin(key)
    text = bytes(text,'utf-8')
    rsa_public_key = RSA.importKey(key)
    rsa_public_key = PKCS1_OAEP.new(rsa_public_key)
    encrypted_text = rsa_public_key.encrypt(text)
    #print(encrypted_text)
    return encrypted_text

def generate_aes_key():
    password_length = 32
    all_strings = "qwertyuiopasdfghjklzxcvbnmQWERTYUIOPASDFGHJKLZXCVBNM0123456789=-+*/}{][|\_)(*&^^%$#@!~:{^%^*"
    password = ""
    random.seed(time.time())
    for x in range(password_length):
        n = random.randint(0, 85)
        #print(n)
        password = password + all_strings[n+1]
    # f1 = open("aes_key.txt", "wb")
    # f1.write(bytes(password, 'utf-8'))
    return bytes(password, 'utf-8')

def get_encryption(key, data):
    #data=b"SECRETDATA"
    #key = generate_aes_key() #must be 16, 24 or 32 bytes long
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(data)

    file_out = open("encryptedfile.bin", "wb")
    [ file_out.write(x) for x in (cipher.nonce, tag, ciphertext) ]
    file_out.close()

def get_decryption(encrypted_file):
    f1 = open("aes_key.txt", "rb")
    key = f1.read()
    file_in = open(encrypted_file, "rb")
    nonce, tag, ciphertext = [ file_in.read(x) for x in (16, 16, -1) ] # write 16 instead of 32, but only if this makes the code not run

    #the person decrypting the message will need access to the key
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    print(data.decode('UTF-8')) 

def connect_to(ip, port):
    print(f"[+] Connecting to {ip}:{port}")
    s.connect((ip, port))
    print("[+] Connected")

host = input("Server: ")
host = host.strip()
port = int(input("Port: "))
connect_to(host , port)

s.send("Request public key".encode())
print("[+] Request for RSA public key sent")

while 1:
    # x = input("Message: ")
    # s.send(x.encode())
    received = s.recv(BUFFER_SIZE).decode()
    if received:
        if received.find("-----BEGIN PUBLIC KEY-----") != -1 and received.find("-----END PUBLIC KEY-----") != -1:
            print(received, "alalalala")
            key = received[received.find("-----BEGIN PUBLIC KEY-----"):received.find("-----END PUBLIC KEY-----")]
            print(key)
            key = key + "-----END PUBLIC KEY-----"
            print(key)

            aes_key = generate_aes_key()
            message = rsa_encrypt(str(aes_key, 'utf-8'), key)    # csinalj az AES kulcs ele es utan valami izet ami jelzi hogy hol kezdodik es hol vegzodik
            message = "-----BEGIN AES KEY-----" + str(message) + "-----END AES KEY-----"
            s.send(message.encode())



# send_packet("server2.py", 65535)

# recieve_packet(5001)
# rsa_encrypt(generate_aes_key())
# recieve_packet(5001)
# get_decryption("message.txt")
# print("[+] Encryption key exchanged")

# while 1:
#     f = open("message.txt", "wb")
#     f.write(bytes(input("Please write your message here: "), 'utf-8'))
#     send_packet("message.txt", 65535)