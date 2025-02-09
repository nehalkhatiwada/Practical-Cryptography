import hashlib
import base64
from tkinter import Tk
from tkinter.filedialog import askopenfilename

class DigitalSignature:
    def __init__(self):
        self.private_key = None
        self.public_key = None

    def generate_keys(self):
        
        self.private_key = "my_private_key"
        self.public_key = "my_public_key"

    def hash_file(self, filepath):
        
        hasher = hashlib.sha256()
        with open(filepath, "rb") as f:
            while chunk := f.read(8192):
                hasher.update(chunk)
        return hasher.hexdigest()

    def xor_encrypt(self, key, data):
        
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

    def encrypt_image(self, filepath):
       
        with open(filepath, "rb") as f:
            image_data = f.read()
        encrypted_image = base64.b64encode(image_data).decode()
        return encrypted_image

    def sign_file(self, filepath):
        
        hashed_message = self.hash_file(filepath)
        encrypted_message = self.xor_encrypt(self.private_key, hashed_message)
        encrypted_image = self.encrypt_image(filepath)

     
        with open("signature_data.txt", "w") as f:
            f.write(f"Hash: {hashed_message}\n")
            f.write(f"Signature: {base64.b64encode(encrypted_message.encode()).decode()}\n")  # Save the signature in base64
        
        
        with open("encrypted_image.txt", "w") as f:
            f.write(f"Encrypted Image: {encrypted_image}\n") 
        
        return encrypted_message

if __name__ == "__main__":
    app = DigitalSignature()
    app.generate_keys()
    
   
    Tk().withdraw()
    
    
    filepath = askopenfilename(title="Select an Image File", filetypes=[("Image Files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif")])
    
    if filepath:
        encrypted_signature = app.sign_file(filepath)
        print("Image has been encrypted and saved successfully.")
    else:
        print("No file selected.")
