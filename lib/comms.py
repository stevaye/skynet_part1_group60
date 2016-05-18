import struct
import base64

from Crypto.Hash import HMAC
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
from Crypto import Random

from Crypto.Random import get_random_bytes
from Crypto import *

from dh import create_dh_key, calculate_dh_secret
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        self.key = None
        self.iv = None
        self.shared_hash = None
        self.initiate_session()
        

    def initiate_session(self):
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            self.send(bytes(str(my_public_key), "ascii"))
            # Send them our public key
            their_public_key = int(self.recv())
            # Receive their public key
            shared_hash = calculate_dh_secret(their_public_key, my_private_key)
            # Obtain our shared secret
            print("Shared hash: {}".format(shared_hash))
            # Prints shared hash on session establishment
            self.shared_hash = shared_hash
            # References shared hash
            self.key = self.shared_hash[32:]
            # Key is taken from the last 32 bytes of the shared key
            print("SELF.KEY is: " + str(self.key))
            # Prints self key as a string
            self.iv = self.shared_hash[16:]
            # IV is taken from the last 16 bytes of the shared key
            print("SELF.IV in INITIATE_SESSION is: " + str(self.iv))
            # Prints IV as string
            self.cipher = (self.key, AES.MODE_CBC, self.iv)


        # Default XOR algorithm can only take a key of length 32
        #self.cipher = XOR.new(shared_hash[:4])

    def send(self, data):
        # AES.block_size = 16
        #data = get_random_bytes(16) + data
        #iv = Random.new().read(AES.block_size) #IV is created for every time something is sent, so you cannot predict the outcome of the string
        #self.cipher = AES.new(self.key, AES.MODE_CBC, iv) ###self.key or just key?
        if type(data) != bytes:
           data = bytes(data, "ascii")


        if self.cipher:
<<<<<<< Updated upstream
            secret = self.shared_hash[32:].encode("ascii")
            # Secret is taken from the last 32 bytes of the shared hash
            h = HMAC.new(secret, digestmod=SHA256)
            # Creates the HMAC
            print("HMAC in SEND is: ", h.hexdigest())            
            # Prepends the HMAC digest to the data
            dataHMAC = bytes(h.hexdigest() + data.decode("ascii"), "ascii")
            # Give the HMAC the data
            h.update(data)
            print("This is data and HMAC in SEND: ",dataHMAC)
            # Prints HMAC


            self.iv = Random.get_random_bytes(16)
            # Generates 16 random bytes for the IV
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            # Creates cipher object
            padded_d = ANSI_X923_pad(dataHMAC, AES.block_size)
            # Pads the HMAC



=======
            iv = Random.new().read(AES.block_size)
            #self.cipher = AES.new(self.key, AES.MODE_CBC, iv) ###self.key or just key?
            self.cipher = AES.new(self.key, AES.MODE_CBC, iv) ###self.key or just key?
            padded_d = ANSI_X923_pad(data, AES.block_size)  
            data = padded_d
            encrypted_data = iv + self.cipher.encrypt(data)
>>>>>>> Stashed changes


            encrypted_data = self.iv + self.cipher.encrypt(padded_d)



            print("SELF.IV in SEND (After encrypted_data = self.iv + self.cipher.encrypt(data)) is: " + str(self.iv))
            # Prints IV as a string
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self): #recieve strips the IV off either the end or front of the encrypted message (IV is 16 bits)
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
        	# Create the secret used in the parameter for the second HMAC which is identical to the first one
            secret = self.shared_hash[32:].encode("ascii")
            # IV is stripped off the first 16 of the encrypted data
            self.iv = encrypted_data[:16]
            # IV is stripped off the first 16 bytes of the encrypted data
            encrypted_data = encrypted_data[AES.block_size:]
            # Encrypted data is stripped off the rest of the block size
            self.cipher = AES.new(self.key, AES.MODE_CBC, self.iv)
            # Creates the cipher object needed to decrypt
            data = self.cipher.decrypt(encrypted_data)
            # Decrypts the data with the HMAC and padded data
            data = ANSI_X923_unpad(data, AES.block_size)
            # Unpads the data that will give us the HMAC data
            h2 = HMAC.new(secret, digestmod=SHA256)
            # Creates the second HMAC so we can compare it to the one we sent
            print("This is 'h2' in RECV: ",h2.hexdigest())
            # Prints 2nd HMAC in hexadecimal

            
            #Extract the HMAC from the data that was sent over
            hmac = data[:h2.digest_size * 2]
            print("This is 'hmac' after stripping it from the data sent over: ",hmac)
            #Extract the data
            data = data[h2.digest_size * 2:]
            print("This is 'data' after stripping it from the data sent over: ",data)
            #Give the second HMAC the data
            #h2.update(data)
            #print("This is 'h2' in RECV AFTER UPDATE: ",h2.hexdigest())

            #Test the HMAC that was sent over compared to the one we just created. If it doesnt match - print an error
            #if compare_digest(h.hexdigest, hmac) != True:
            if h2.hexdigest() == str(hmac, "ascii"):
                print ("HMAC matches!")
                print ("HMAC in SEND in IF STATEMENT: ",h2.hexdigest())
                print ("HMAC in RECV in IF STATEMENT: ",str(hmac,"ascii"))
            else:
                print("HMAC doesnt match!")
                print("HMAC in SEND in IF STATEMENT: ",h2.hexdigest())
                print("HMAC in RECV in IF STATEMENT: ",str(hmac, "ascii"))

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data

    def close(self):
        self.conn.close()