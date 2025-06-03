from tkinter import messagebox as MessageBox
from RSA import RSA
from tkinter import filedialog

class RSAKeyGenerator:
    def __init__(self):
        self.rsa = RSA(bits=2048)
        self.rsa.generate_keys()

    def generate(self, name):
        private_key_pem = self.rsa.export_key_pem(self.rsa.get_private_key(), key_type='private')
        public_key_pem = self.rsa.export_key_pem(self.rsa.get_public_key(), key_type='public')

        with open("PrivateKey_" + name + ".pem", "w") as f:
            f.write(private_key_pem)

        with open("PublicKey_" + name + ".pem", "w") as f:
            f.write(public_key_pem)

        MessageBox.showinfo("Keys generated!", "Keys Ready to use, do not share private key")

    def getDireccionArchivo(self, direccion, extension):
        direccion[0] = filedialog.askopenfilename(title="Open key", filetypes=[("Files " + extension, "*." + extension), ("All files", "*.*")])
