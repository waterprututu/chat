from Crypto.PublicKey import RSA
# from Crypto import Random
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Cipher import AES
import tqdm
import os
import socket

SERVER_HOST = "0.0.0.0"
SERVER_PORT = 5001

SEPARATOR = "<SEPARATOR>"
BUFFER_SIZE = 65535

s = socket.socket()

dict_of_keys = dict()

def generate_rsa_key():
    key = RSA.generate(2048)
    private_key = key.export_key('PEM')  # if u want binary use DER, if not PEM
    public_key = key.publickey().exportKey('PEM')

    # print(str(public_key, 'utf-8'))
    # print(private_key)

    rsa_public_key = RSA.importKey(public_key)
    f_public = open("public_key.txt", "wb")      # use "wb" write bytes
    f_public.write(public_key)
    rsa_private_key = RSA.importKey(private_key)
    f_private = open("private_key.txt", "wb")
    f_private.write(private_key)

    return (str(public_key, 'utf-8'), str(private_key, 'utf-8'))

def rsa_decrypt(text, key):
    # with open('private_key.txt', 'rb') as file:
    #     key = file.read() #.replace('\n', '') u could use this if u were using strings
    rsa_private_key = RSA.importKey(key)
    rsa_private_key = PKCS1_OAEP.new(rsa_private_key)
    decrypted_text = rsa_private_key.decrypt(text)
    return decrypted_text

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

def recieve_packet(port):
    client_socket, address = s.accept()
    received = client_socket.recv(BUFFER_SIZE).decode()
    filename, filesize = received.split(SEPARATOR)

    filename = os.path.basename(filename)

    filesize = bytes(filesize, 'utf-8')

    progress = tqdm.tqdm(range(filesize), f"Receiving {filename}", unit="B", unit_scale=True, unit_divisor = 1024)
    with open(filename, "wb") as f:
        while True:
            bytes_read = client_socket.recv(BUFFER_SIZE)
            if not bytes_read:
                break
            f.write(bytes_read)
            progress.update(len(bytes_read))

def send_packet(filename, filesize):
    s.send(f"{filename}{SEPARATOR}{filesize}".encode())

    progress = tqdm.tqdm(range(filesize), f"Sending {filename}", unit="B", unit_scale=True, unit_divisor=1024)
    with open(filename, "rb") as f:
        while True:
            bytes_read = f.read(BUFFER_SIZE)
            if not bytes_read:
                break
            s.sendall(bytes_read)
            progress.update(len(bytes_read))

s.bind((SERVER_HOST, SERVER_PORT))

s.listen(10)
print(f"[*] Listening as {SERVER_HOST}:{SERVER_PORT}")

client_socket, address = s.accept()
print(f"[+] {address} is connected. ")

print(f"[+] Sending RSA public key to {address}")
pub_key, priv_key = generate_rsa_key()
dict_of_keys.update(client_socket, priv_key) # lehet hogy itten van problema
client_socket.send(pub_key.encode())

decryption_key = ""

# send_packet("public_key.txt", 65535)
# recieve_packet(5001)
# print("[+] AES Encryption key received")

# f = open("message.txt", "wb")
# f.write(bytes("Key exchanged"))
# f.close()
# send_packet("message.txt", 65535)

while 1:
    print("[+] Waiting for packets...")
    received = client_socket.recv(BUFFER_SIZE).decode()
    if received:
        print(f"{address} says: ",received)     
        if received.find("-----BEGIN AES KEY-----") != -1:
            key = received[received.find("-----BEGIN AES KEY-----"):received.find("-----END AES KEY-----")]
            key = key[22:]
            f = open("private_key.txt", "r")
            priv_key = f.read()
            rsa_decrypt(key, priv_key)
        # client_socket.send(received.encode())
