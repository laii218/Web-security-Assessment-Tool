import hashlib
import os
import re
import threading
import tkinter as tk
from tkinter import filedialog


def new_window():
    # Define GUI
    root = tk.Tk()
    root.title("Brute Force Password Cracker")
    root.geometry("400x300")

    # Define GUI elements
    hash_label = tk.Label(root, text="Enter hash value to bruteforce:")
    hash_label.pack()
    hash_entry = tk.Entry(root,width=50)
    hash_entry.pack(expand=True, fill="x")

    # Define function to get file path
    def select_file():
        file_path = filedialog.askopenfilename()
        file_entry.delete(0, tk.END)
        file_entry.insert(0, file_path)

    file_label = tk.Label(root, text="Select file to bruteforce with:")
    file_label.pack()
    file_entry = tk.Entry(root)
    file_entry.pack()
    file_button = tk.Button(root, text="Browse...", command=select_file)
    file_button.pack()

    # Define program status label
    status_label = tk.Label(root, text="Ready to Crack!")
    status_label.pack()

    # Define result label
    result_label = tk.Label(root, text="")
    result_label.pack()

    # Define function to crack the hash
    def crack_hash():
        # Get user input for hash type, file path, and hash to decrypt
        file_path = file_entry.get()
        hash_to_decrypt = hash_entry.get()

        # Check if file path exists
        if not os.path.exists(file_path):
            result_label.config(text="File/Path Doesnt Exist")
            return

        # Identify hash type using regular expressions
        if re.match(r'^[0-9a-f]{32}$', hash_to_decrypt):
            hash_type = 'md5'
        elif re.match(r'^[0-9a-f]{40}$', hash_to_decrypt):
            hash_type = 'sha1'
        elif re.match(r'^[0-9a-f]{64}$', hash_to_decrypt):
            hash_type = 'sha256'
        elif re.match(r'^[0-9a-f]{128}$', hash_to_decrypt):
            hash_type = 'sha512'
        else:
            result_label.config(text="Unknown hash type")
            return

        # Open file and iterate over each line
        with open(file_path, 'r') as file:
            for line in file.readlines():
                # Hash the line using the corresponding hash function
                if hash_type == 'md5':
                    hash_object = hashlib.md5(line.strip().encode())
                elif hash_type == 'sha1':
                    hash_object = hashlib.sha1(line.strip().encode())
                elif hash_type == 'sha256':
                    hash_object = hashlib.sha256(line.strip().encode())
                elif hash_type == 'sha512':
                    hash_object = hashlib.sha512(line.strip().encode())
                else:
                    result_label.config(text="Unknown hash type")
                    return
                hashed_word = hash_object.hexdigest()

                # Check if the hashed word matches the hash to decrypt
                if hashed_word == hash_to_decrypt:
                    result_label.config(text='Found ' + hash_type.upper() + ' Password: ' + line.strip())
                    status_label.config(text="Password Cracked!")
                    return

        # If no match was found, print message
        result_label.config(text="Password Is Not In File.")
        status_label.config(text="Finished Cracking!")

    # Define GUI button to run the function
    crack_button = tk.Button(root, text="Crack Hash", command=lambda: threading.Thread(target=crack_hash).start())
    crack_button.pack()

    root.mainloop()
