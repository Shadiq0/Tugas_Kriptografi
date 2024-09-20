import tkinter as tk
from tkinter import filedialog, messagebox
import numpy as np

def vigenere_encrypt(text, key):
    key = key.upper()
    text = text.upper().replace(" ", "")
    key_repeat = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    encrypted = []
    for i in range(len(text)):
        if text[i].isalpha():
            encrypted_char = chr(((ord(text[i]) - ord('A')) + (ord(key_repeat[i]) - ord('A'))) % 26 + ord('A'))
            encrypted.append(encrypted_char)
        else:
            encrypted.append(text[i])
    return ''.join(encrypted)

def vigenere_decrypt(text, key):
    key = key.upper()
    text = text.upper().replace(" ", "")
    key_repeat = (key * (len(text) // len(key))) + key[:len(text) % len(key)]
    decrypted = []
    for i in range(len(text)):
        if text[i].isalpha():
            decrypted_char = chr(((ord(text[i]) - ord('A')) - (ord(key_repeat[i]) - ord('A'))) % 26 + ord('A'))
            decrypted.append(decrypted_char)
        else:
            decrypted.append(text[i])
    return ''.join(decrypted)

def hill_encrypt(text, key):
    text = text.upper().replace(" ", "")
    while len(text) % 2 != 0:
        text += 'X'  
    key_matrix = generate_key_matrix(key[:4]) 
    encrypted_text = []
    for i in range(0, len(text), 2):
        vector = np.array([[ord(text[i]) - ord('A')], [ord(text[i+1]) - ord('A')]])
        encrypted_vector = np.dot(key_matrix, vector) % 26
        encrypted_text.append(chr(encrypted_vector[0][0] + ord('A')))
        encrypted_text.append(chr(encrypted_vector[1][0] + ord('A')))
    return ''.join(encrypted_text)

def hill_decrypt(text, key):
    text = text.upper().replace(" ", "")
    key_matrix = generate_key_matrix(key[:4])  
    inverse_key_matrix = find_matrix_inverse(key_matrix, 26)
    decrypted_text = []
    for i in range(0, len(text), 2):
        vector = np.array([[ord(text[i]) - ord('A')], [ord(text[i+1]) - ord('A')]])
        decrypted_vector = np.dot(inverse_key_matrix, vector) % 26
        decrypted_text.append(chr(int(decrypted_vector[0][0]) + ord('A')))
        decrypted_text.append(chr(int(decrypted_vector[1][0]) + ord('A')))
    return ''.join(decrypted_text)

def generate_key_matrix(key):
    key_matrix = np.zeros((2, 2), dtype=int)
    key_matrix[0][0] = ord(key[0]) - ord('A')
    key_matrix[0][1] = ord(key[1]) - ord('A')
    key_matrix[1][0] = ord(key[2]) - ord('A')
    key_matrix[1][1] = ord(key[3]) - ord('A')
    return key_matrix

def find_matrix_inverse(matrix, mod):
    det = int(np.round(np.linalg.det(matrix)))  
    det_inv = modular_inverse(det, mod)  
    matrix_mod_inv = (det_inv * np.round(det * np.linalg.inv(matrix)).astype(int)) % mod
    return matrix_mod_inv

def modular_inverse(a, m):
    a = a % m
    for x in range(1, m):
        if (a * x) % m == 1:
            return x
    return None

def generate_playfair_matrix(key):
    key = key.upper().replace("J", "I")
    matrix = []
    used_letters = set()
    for char in key:
        if char not in used_letters and char.isalpha():
            matrix.append(char)
            used_letters.add(char)
    for char in 'ABCDEFGHIKLMNOPQRSTUVWXYZ':
        if char not in used_letters:
            matrix.append(char)
            used_letters.add(char)
    return [matrix[i:i + 5] for i in range(0, 25, 5)]

def find_position(matrix, letter):
    for i, row in enumerate(matrix):
        if letter in row:
            return i, row.index(letter)
    return None

def playfair_encrypt(text, key):
    text = text.upper().replace("J", "I").replace(" ", "")
    matrix = generate_playfair_matrix(key)
    pairs = []
    i = 0
    while i < len(text):
        if i == len(text) - 1:
            pairs.append(text[i] + 'X')
            i += 1
        elif text[i] == text[i+1]:
            pairs.append(text[i] + 'X')
            i += 1
        else:
            pairs.append(text[i:i+2])
            i += 2
    encrypted_text = []
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        if row1 == row2:
            encrypted_text.append(matrix[row1][(col1 + 1) % 5])
            encrypted_text.append(matrix[row2][(col2 + 1) % 5])
        elif col1 == col2:
            encrypted_text.append(matrix[(row1 + 1) % 5][col1])
            encrypted_text.append(matrix[(row2 + 1) % 5][col2])
        else:
            encrypted_text.append(matrix[row1][col2])
            encrypted_text.append(matrix[row2][col1])
    return ''.join(encrypted_text)

def playfair_decrypt(text, key):
    text = text.upper().replace("J", "I").replace(" ", "")
    matrix = generate_playfair_matrix(key)
    pairs = [text[i:i+2] for i in range(0, len(text), 2)]
    decrypted_text = []
    for pair in pairs:
        row1, col1 = find_position(matrix, pair[0])
        row2, col2 = find_position(matrix, pair[1])
        if row1 == row2:
            decrypted_text.append(matrix[row1][(col1 - 1) % 5])
            decrypted_text.append(matrix[row2][(col2 - 1) % 5])
        elif col1 == col2:
            decrypted_text.append(matrix[(row1 - 1) % 5][col1])
            decrypted_text.append(matrix[(row2 - 1) % 5][col2])
        else:
            decrypted_text.append(matrix[row1][col2])
            decrypted_text.append(matrix[row2][col1])
    return ''.join(decrypted_text)

class CipherApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Cipher Encryption & Decryption")
        
        self.label_key = tk.Label(root, text="Input Key (min 12 chars):")
        self.label_key.grid(row=0, column=0, padx=10, pady=5)
        
        self.entry_key = tk.Entry(root, width=50)
        self.entry_key.grid(row=0, column=1, padx=10, pady=5)
        
        self.label_message = tk.Label(root, text="Input Message:")
        self.label_message.grid(row=1, column=0, padx=10, pady=5)
        
        self.text_message = tk.Text(root, height=10, width=50)
        self.text_message.grid(row=1, column=1, padx=10, pady=5)
        
        self.button_encrypt_vigenere = tk.Button(root, text="Encrypt with Vigenere", command=self.encrypt_vigenere)
        self.button_encrypt_vigenere.grid(row=2, column=0, padx=10, pady=5)
        
        self.button_decrypt_vigenere = tk.Button(root, text="Decrypt with Vigenere", command=self.decrypt_vigenere)
        self.button_decrypt_vigenere.grid(row=2, column=1, padx=10, pady=5)

        self.button_encrypt_playfair = tk.Button(root, text="Encrypt with Playfair", command=self.encrypt_playfair)
        self.button_encrypt_playfair.grid(row=3, column=0, padx=10, pady=5)
        
        self.button_decrypt_playfair = tk.Button(root, text="Decrypt with Playfair", command=self.decrypt_playfair)
        self.button_decrypt_playfair.grid(row=3, column=1, padx=10, pady=5)

        self.button_encrypt_hill = tk.Button(root, text="Encrypt with Hill", command=self.encrypt_hill)
        self.button_encrypt_hill.grid(row=4, column=0, padx=10, pady=5)
        
        self.button_decrypt_hill = tk.Button(root, text="Decrypt with Hill", command=self.decrypt_hill)
        self.button_decrypt_hill.grid(row=4, column=1, padx=10, pady=5)

        self.button_upload = tk.Button(root, text="Upload File", command=self.upload_file)
        self.button_upload.grid(row=5, column=0, padx=10, pady=5)
        
        self.label_output = tk.Label(root, text="Output:")
        self.label_output.grid(row=6, column=0, padx=10, pady=5)
        
        self.text_output = tk.Text(root, height=10, width=50)
        self.text_output.grid(row=6, column=1, padx=10, pady=5)
        
        self.message = ''
    
    def upload_file(self):
        file_path = filedialog.askopenfilename(filetypes=[("Text Files", "*.txt")])
        if file_path:
            with open(file_path, 'r') as file:
                self.message = file.read()
                self.text_message.insert(tk.END, self.message)
    
    def pad_key(self, key, min_length=12):
        if len(key) < min_length:
            key = key + '#' * (min_length - len(key))
        return key

    def encrypt_vigenere(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip()  
        padded_key = self.pad_key(key)
        encrypted_message = vigenere_encrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, encrypted_message)

    def decrypt_vigenere(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip()  
        padded_key = self.pad_key(key)
        decrypted_message = vigenere_decrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, decrypted_message)

    def encrypt_playfair(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip()  
        padded_key = self.pad_key(key)
        encrypted_message = playfair_encrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, encrypted_message)

    def decrypt_playfair(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip()  
        padded_key = self.pad_key(key)
        decrypted_message = playfair_decrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, decrypted_message)

    def encrypt_hill(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip()  
        padded_key = self.pad_key(key)
        encrypted_message = hill_encrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, encrypted_message)

    def decrypt_hill(self):
        key = self.entry_key.get()
        if len(key) < 12:
            messagebox.showerror("Error", "Kunci harus minimal 12 karakter.")
            return
        message = self.text_message.get("1.0", tk.END).strip() 
        padded_key = self.pad_key(key)
        decrypted_message = hill_decrypt(message, padded_key)
        self.text_output.delete("1.0", tk.END)
        self.text_output.insert(tk.END, decrypted_message)

if __name__ == "__main__":
    root = tk.Tk()
    app = CipherApp(root)
    root.mainloop()

