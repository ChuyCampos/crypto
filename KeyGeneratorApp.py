from tkinter import *
from tkinter import ttk
import tkinter.font as tkFont
from tkinter import messagebox as MessageBox
from tkinter import filedialog
from tkinter.ttk import *
from functools import partial
from RSAKeyGenerator import RSAKeyGenerator

class KeyGeneratorApp:
    def __init__(self, master):
        self.master = master
        self.master.state('normal') 
        self.master.title("Key Generator")
        self.tab_control = ttk.Notebook(self.master)
        self.keygen_tab = ttk.Frame(self.tab_control)
        self.tab_control.add(self.keygen_tab, text='Key Generator')
        self.tab_control.pack(expand=1, fill='both')
        
        self.create_widgets()

    def create_widgets(self):
        self.titleHash = Label(self.keygen_tab, text="RSA Key Pair Generator", font=("Arial ", 20), padding=7)
        self.titleHash.grid(row=1, column=1, columnspan=4)

        self.labelHash = Label(self.keygen_tab, text="Name:", padding="20 0 0 0")
        self.labelHash.grid(row=6, column=1)

        self.entry = Entry(self.keygen_tab)
        self.entry.grid(row=6, column=2, padx=10)
        
        self.generateBtn = Button(self.keygen_tab, text='Generate Key Pair', command=self.generate_keys, width=20)
        self.generateBtn.grid(row=6, column=3)
        
        self.labelHash = Label(self.keygen_tab, text="", padding="10")
        self.labelHash.grid(row=6, column=4)

    def generate_keys(self):
        key_generator = RSAKeyGenerator()
        key_generator.generate(str(self.entry.get()))

def main():
    root = Tk()
    app = KeyGeneratorApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
