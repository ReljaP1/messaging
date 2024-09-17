import socket
import threading
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import tkinter as tk

SERVER_IP = "127.0.0.1"
SERVER_PORT = 9999
KEY_SIZE = 32
IV_SIZE = 16
PASSWORD = b"shared_password"
SALT = b"abcdefgh12345678"
KEY_ITERATIONS = 100000

def derive_key(password, salt, iterations, key_size):
    backend = default_backend()
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=key_size, salt=salt, iterations=iterations, backend=backend)
    return kdf.derive(password)

def encrypt_aes_cbc(plaintext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    return encryptor.update(padded_data) + encryptor.finalize()

def decrypt_aes_cbc(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(padded_data) + unpadder.finalize()

def send_message(client_socket, key, message_entry, message_list):
    while True:
        message = message_entry.get()
        if not message:
            break
        iv = os.urandom(IV_SIZE)
        encrypted_message = encrypt_aes_cbc(message.encode(), key, iv)
        encrypted_message = iv + encrypted_message
        msg_len_bytes = len(encrypted_message).to_bytes(4, byteorder='big')
        client_socket.send(msg_len_bytes + encrypted_message)
        print(f"Ciphertext: {encrypted_message[IV_SIZE:]}")
        message_list.insert(tk.END, "You: " + message)
        message_entry.delete(0, tk.END)

def receive_message(client_socket, key, message_list, message_entry):
    while True:
        msg_len_bytes = client_socket.recv(4)
        if not msg_len_bytes:
            break

        msg_len = int.from_bytes(msg_len_bytes, byteorder='big')
        encrypted_msg = b""
        while len(encrypted_msg) < msg_len:
            encrypted_msg += client_socket.recv(msg_len - len(encrypted_msg))

        iv, encrypted_msg = encrypted_msg[:IV_SIZE], encrypted_msg[IV_SIZE:]
        decrypted_msg = decrypt_aes_cbc(encrypted_msg, key, iv)
        print(f"Alice: {decrypted_msg.decode(errors='replace')}")
        message_list.insert(tk.END, "Alice: " + decrypted_msg.decode(errors='replace'))

        
def handle_server(client_socket, key):
    root = tk.Tk()
    root.title("Chat from Alice")

    message_frame = tk.Frame(root)
    message_frame.pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    message_list = tk.Listbox(message_frame)
    message_list.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

    scrollbar = tk.Scrollbar(message_frame)
    scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

    message_list.config(yscrollcommand=scrollbar.set)
    scrollbar.config(command=message_list.yview)

    message_input_frame = tk.Frame(root)
    message_input_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=10, pady=10)

    message_label = tk.Label(message_input_frame, text="Message:")
    message_label.pack(side=tk.LEFT)

    message_entry = tk.Entry(message_input_frame)
    message_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

    message_entry.bind("<Return>", lambda event: send_message(client_socket, key, message_entry, message_list))

    send_button = tk.Button(message_input_frame, text="Send", command=lambda: send_message(client_socket, key, message_entry, message_list))
    send_button.pack(side=tk.RIGHT)

    send_thread = threading.Thread(target=send_message, args=(client_socket, key, message_entry, message_list))
    recv_thread = threading.Thread(target=receive_message, args=(client_socket, key, message_list, message_entry))

    send_thread.start()
    recv_thread.start()

    root.mainloop()

    client_socket.close()

def main():
    key = derive_key(PASSWORD, SALT, KEY_ITERATIONS, KEY_SIZE)

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((SERVER_IP, SERVER_PORT))
    server_handler = threading.Thread(target=handle_server, args=(client_socket, key))
    server_handler.start()

if __name__ == "__main__":
    main()
