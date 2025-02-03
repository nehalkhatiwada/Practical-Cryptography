import tkinter as tk
from tkinter import messagebox, filedialog
import base64
import os
import pyperclip
import hashlib
import rsa


class DigitalSignatureApp:
    def __init__(self, master):
        self.master = master
        master.title("Stream and Block Cipher Digital Signature")

       
        self.private_key, self.public_key = self.load_or_generate_keys()

        self.stream_key = os.urandom(16)

        
        self.encrypted_message = None
        self.message_hash = None
        self.signature = None

      
        self.label = tk.Label(master, text="Enter message:")
        self.label.pack()

        self.message_entry = tk.Entry(master, width=50)
        self.message_entry.pack()

        self.encrypt_button = tk.Button(master, text="Encrypt and Sign", command=self.encrypt_and_sign)
        self.encrypt_button.pack()

        self.encrypted_label = tk.Label(master, text="Encrypted Message Saved to File")
        self.encrypted_label.pack()

     
        self.hash_label = tk.Label(master, text="Message Hash:")
        self.hash_label.pack()

      
        self.hash_display = tk.Label(master, text="", wraplength=400, justify="left", fg="green")
        self.hash_display.pack()

   
        self.copy_hash_button = tk.Button(master, text="Copy Hash", command=self.copy_hash)
        self.copy_hash_button.pack()

       
        self.signature_label = tk.Label(master, text="Generated Signature:")
        self.signature_label.pack()

     
        self.signature_display = tk.Label(master, text="", wraplength=400, justify="left", fg="blue")
        self.signature_display.pack()

     
        self.copy_button = tk.Button(master, text="Copy Signature", command=self.copy_signature)
        self.copy_button.pack()

     
        self.save_button = tk.Button(master, text="Save Hash and Signature", command=self.save_hash_and_signature)
        self.save_button.pack()

        self.hash_verify_label = tk.Label(master, text="Enter Hash to Verify:")
        self.hash_verify_label.pack()

        self.hash_entry = tk.Entry(master, width=50)
        self.hash_entry.pack()

     
        self.verify_hash_button = tk.Button(master, text="Verify Hash", command=self.verify_hash)
        self.verify_hash_button.pack()

        self.signature_verify_label = tk.Label(master, text="Enter Signature to Verify:")
        self.signature_verify_label.pack()

        self.signature_entry = tk.Entry(master, width=50)
        self.signature_entry.pack()

   
        self.verify_signature_button = tk.Button(master, text="Verify Signature", command=self.verify_signature)
        self.verify_signature_button.pack()

   
        self.decrypted_label = tk.Label(master, text="Decrypted Message:")
        self.decrypted_label.pack()

        self.decrypted_display = tk.Label(master, text="", wraplength=400, justify="left")
        self.decrypted_display.pack()

    def load_or_generate_keys(self):
        """Load RSA keys from files or generate and save new ones."""
        private_key_file = "private_key.pem"
        public_key_file = "public_key.pem"

        if os.path.exists(private_key_file) and os.path.exists(public_key_file):
            try:
                with open(private_key_file, "rb") as priv_file:
                    private_key = rsa.PrivateKey.load_pkcs1(priv_file.read())
                with open(public_key_file, "rb") as pub_file:
                    public_key = rsa.PublicKey.load_pkcs1(pub_file.read())
                return private_key, public_key
            except Exception as e:
                messagebox.showerror("Error", f"Error loading keys: {e}")

        (public_key, private_key) = rsa.newkeys(2048)

  
        with open(private_key_file, "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())
        with open(public_key_file, "wb") as pub_file:
            pub_file.write(public_key.save_pkcs1())
        return private_key, public_key

    def encrypt_and_sign(self):
        """Encrypt the message using XOR (stream cipher), hash it, and sign the hash."""
        try:
          
            message = self.message_entry.get().encode('utf-8')

            self.message_hash = self.hash_message(message)

       
            self.hash_display.config(text=self.message_hash)

            encrypted_message = self.xor_encrypt_decrypt(message, self.stream_key)

     
            signature = rsa.sign(self.message_hash.encode('utf-8'), self.private_key, 'SHA-256')

      
            self.encrypted_message = encrypted_message
            self.signature = signature

            self.signature_display.config(text=base64.b64encode(signature).decode('utf-8'))

        
            self.encrypted_label.config(text="Encrypted Message and Signature Generated!")
            self.message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Error", f"Error encrypting and signing the message: {e}")

    def hash_message(self, message):
        """Hash the message using SHA-256."""
        sha256_hash = hashlib.sha256()
        sha256_hash.update(message)
        return sha256_hash.hexdigest()

    def xor_encrypt_decrypt(self, data, key):
        """Simple XOR encryption/decryption function."""
        return bytes([data[i] ^ key[i % len(key)] for i in range(len(data))])

    def copy_hash(self):
        """Copy the hash to the clipboard."""
        try:
            message_hash = self.hash_display.cget("text")
            if message_hash:
                pyperclip.copy(message_hash)
                messagebox.showinfo("Success", "Hash copied to clipboard!")
            else:
                messagebox.showerror("Error", "No hash to copy.")
        except Exception as e:
            messagebox.showerror("Error", f"Error copying hash: {e}")

    def copy_signature(self):
        """Copy the signature to the clipboard."""
        try:
            signature = self.signature_display.cget("text")
            if signature:
                pyperclip.copy(signature)
                messagebox.showinfo("Success", "Signature copied to clipboard!")
            else:
                messagebox.showerror("Error", "No signature to copy.")
        except Exception as e:
            messagebox.showerror("Error", f"Error copying signature: {e}")

    def save_hash_and_signature(self):
        """Save the hash and signature to separate files."""
        try:
            if self.message_hash is None or self.signature is None:
                messagebox.showerror("Error", "No hash or signature to save.")
                return

            with open("hash.txt", "w") as hash_file:
                hash_file.write(self.message_hash)

            with open("signature.txt", "wb") as signature_file:
                signature_file.write(base64.b64encode(self.signature))

            messagebox.showinfo("Success", "Hash and signature saved to separate files!")
        except Exception as e:
            messagebox.showerror("Error", f"Error saving hash and signature: {e}")

    def verify_hash(self):
        """Verify the entered hash against the stored hash."""
        try:
            entered_hash = self.hash_entry.get()

            if not os.path.exists("hash.txt"):
                messagebox.showerror("Error", "Hash file not found!")
                return

            with open("hash.txt", "r") as hash_file:
                stored_hash = hash_file.read().strip()

            if entered_hash == stored_hash:
                messagebox.showinfo("Hash Verification", "Hash is valid!")
            else:
                messagebox.showerror("Hash Verification", "Hash is invalid!")
        except Exception as e:
            messagebox.showerror("Error", f"Error verifying hash: {e}")

    def verify_signature(self):
        """Verify the entered signature."""
        try:
            entered_signature = base64.b64decode(self.signature_entry.get())

            if not os.path.exists("signature.txt"):
                messagebox.showerror("Error", "Signature file not found!")
                return

            rsa.verify(self.message_hash.encode('utf-8'), entered_signature, self.public_key)
            messagebox.showinfo("Signature Verification", "Signature is valid!")

            decrypted_message = self.xor_encrypt_decrypt(self.encrypted_message, self.stream_key)
            self.decrypted_display.config(text=decrypted_message.decode('utf-8'))
        except Exception:
            messagebox.showerror("Signature Verification", "Signature is invalid!")
        except Exception as e:
            messagebox.showerror("Error", f"Error verifying signature: {e}")


if __name__ == "__main__":
    root = tk.Tk()
    app = DigitalSignatureApp(root)
    root.mainloop()
