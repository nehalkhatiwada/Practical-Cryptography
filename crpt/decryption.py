import hashlib
import base64
from PIL import Image
import io

class DigitalSignature:
    def hash_message(self, message):
       
        return hashlib.sha256(message.encode()).hexdigest()

    def xor_decrypt(self, key, data):
      
        return ''.join(chr(ord(c) ^ ord(key[i % len(key)])) for i, c in enumerate(data))

    def decrypt_and_verify(self, hashed_input, encrypted_input):
      
        decrypted_signature = self.xor_decrypt("my_private_key", base64.b64decode(encrypted_input).decode())
        return hashed_input == decrypted_signature

if __name__ == "__main__":
    app = DigitalSignature()
    
   
    with open("signature_data.txt", "r") as f:
        lines = f.readlines()
        saved_hash = lines[0].strip().split(": ")[1]
        saved_signature = lines[1].strip().split(": ")[1]

   
    with open("encrypted_image.txt", "r") as f:
        encrypted_image_data = f.readline().strip().split(": ")[1] 

   
    hash_input = input("Enter the hash for verification: ")
    signature_input = input("Enter the signature for verification: ")

    if app.decrypt_and_verify(hash_input, signature_input):
        print("Verification successful: The signature is valid.")
     
        image_data = base64.b64decode(encrypted_image_data)
        img = Image.open(io.BytesIO(image_data))
        img.show()
    else:
        print("Verification failed: The signature is invalid.")
