from RSA import RSA # Libreria para cifrado y descifrado de RSA
from tkinter import messagebox as MessageBox # libreria para mandar aviso con tkinter
import random 
from AES import AES
from FileManager import FileManager

from Crypto.Util.Padding import pad,unpad


class HybridCipher:
    def __init__(self):
        self.dataE = b''
        self.key_aes = self.random_keys(97, 123).encode()
        self.iv = self.random_keys(48, 58).encode()

    def random_keys(self, asciiB, asciiT):
        rand = ''.join(random.choice([chr(x) for x in range(asciiB, asciiT)]) for _ in range(16))
        return rand

    def cbc_flow_encrypt(self, file_name, public_key_path, private_key_path):
        rsa_public = RSA()
        rsa_private = RSA()
        with open(public_key_path, 'r') as f:
            public_key_pem = f.read()
        rsa_public.import_key_pem(public_key_pem, key_type='public')

        with open(private_key_path, 'r') as f:
            private_key_pem = f.read()
        rsa_private.import_key_pem(private_key_pem, key_type='private')

        # Leer el contenido del archivo y firmar el mensaje
        file_manager = FileManager(file_name)
        message = file_manager.read_file()
        signature = rsa_private.sign(message)

        kE = rsa_public.encrypt(int.from_bytes(self.key_aes, byteorder='big'))
        ivE = rsa_public.encrypt(int.from_bytes(self.iv, byteorder='big'))

        state = pad(message, 16)

        aes_ins = AES(self.key_aes)
        self.dataE = bytearray()

        previous_block = bytearray(self.iv)
        for i in range(0, len(state), 16):
            block = bytearray(state[i:i + 16])
            for j in range(16):
                block[j] ^= previous_block[j]
            encrypted_block = aes_ins.encrypt(block)
            self.dataE.extend(encrypted_block)
            previous_block = encrypted_block

        delimiter = b"\n/////////////////\n"
        encrypted_content = file_manager.join_by_delimiter([
            self.dataE,
            kE.to_bytes((kE.bit_length() + 7) // 8, byteorder='big'),
            ivE.to_bytes((ivE.bit_length() + 7) // 8, byteorder='big'),
            signature.to_bytes((signature.bit_length() + 7) // 8, byteorder='big')
        ], delimiter)

        
        wFile = FileManager("E_mensaje.txt")
        wFile.write_file(encrypted_content)

        return self.dataE

    def cbc_flow_decrypt(self, file_name, private_key_path, public_key_path):
        rsa_private = RSA()
        rsa_public = RSA()
        with open(private_key_path, 'r') as f:
            private_key_pem = f.read()
        rsa_private.import_key_pem(private_key_pem, key_type='private')

        with open(public_key_path, 'r') as f:
            public_key_pem = f.read()
        rsa_public.import_key_pem(public_key_pem, key_type='public')

        file_manager = FileManager(file_name)
        file_content = file_manager.read_file()
        delimiter = b"\n/////////////////\n"
        data_sections = file_manager.split_by_delimiter(file_content, delimiter)

        self.dataE = data_sections[0]
        kE = int.from_bytes(data_sections[1], byteorder='big')
        ivE = int.from_bytes(data_sections[2], byteorder='big')
        signature = int.from_bytes(data_sections[3], byteorder='big')

        try:
            self.key_aes = rsa_private.decrypt(kE).to_bytes(16, byteorder='big')
            self.iv = rsa_private.decrypt(ivE).to_bytes(16, byteorder='big')
        except OverflowError:
            MessageBox.showerror("Error", "The provided private key does not correspond to the public key used for encryption.")
            return

        aes_ins = AES(self.key_aes)
        state = bytearray()

        previous_block = bytearray(self.iv)
        for i in range(0, len(self.dataE), 16):
            encrypted_block = self.dataE[i:i + 16]
            decrypted_block = aes_ins.decrypt(encrypted_block)
            decrypted_block = bytearray(decrypted_block)
            for j in range(16):
                decrypted_block[j] ^= previous_block[j]
            state.extend(decrypted_block)
            previous_block = encrypted_block

        state = unpad(state, 16)

        if not rsa_public.verify(state, signature):
            MessageBox.showerror("Error", "The signature does not match the message. The message may have been tampered with.")
            return

        wFile = FileManager("D_mensaje.txt")
        wFile.write_file(state)
        return state



