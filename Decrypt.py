from Crypto.Cipher import AES
import base64

# key = "KEY4DB@oFIbecssT"
# encrypted_text = "Fnn7jX1FdewOn0BYLhNHQUyVHTh8qJItzf1g/prS4LG91k1B7Nni/Yx+C7yuydTfkKU52g1U31yi89dTY8Qt+YFIlj3ASdXDkx6Qek5cgCs="

def decrypt_text(encrypted_text, key):
    # Convert the key to bytes
    key_bytes = key.encode('utf-8')
    if len(key_bytes) < 16:
        raise ValueError("Key must be at least 16 bytes long.")
    
    # Ensure key is exactly 16 bytes
    key_bytes = key_bytes[:16]  # Trim or pad to 16 bytes
    iv = key_bytes  # Using the same key as IV (insecure but matches the C# code)
    
    # Decode the Base64 encrypted text
    encrypted_bytes = base64.b64decode(encrypted_text)
    
    # Create AES cipher object
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    
    # Decrypt the data
    decrypted_bytes = cipher.decrypt(encrypted_bytes)
    
    # Remove padding (if necessary)
    decrypted_text = decrypted_bytes.rstrip(b'\0').decode('utf-8')  # Assuming null padding
    return decrypted_text

# try:
#     decrypted_text = decrypt_text(encrypted_text, key)
#     print("Decrypted text:", decrypted_text)
# except Exception as e:
#     print("Error:", str(e))
