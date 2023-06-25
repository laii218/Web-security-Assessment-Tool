import hashlib
import os
import re
import string
import random
import threading
import tkinter as tk
from tkinter import messagebox, filedialog
import customtkinter as ctk
from PIL import Image, ImageTk
from cryptography.fernet import Fernet


def password_operations():
	# create a window
	password_window = ctk.CTkToplevel()
	# set the title of the window
	password_window.title("passwordOperations")
	# set the size of the window
	password_window.geometry("500x500")
	# set the appearance mode
	ctk.set_appearance_mode("dark")
	# set the default color theme
	ctk.set_default_color_theme("dark-blue")
	# open the background image
	bckgrnd_img1 = Image.open('dark.png')
	# resize the image to fit the window size
	bckgrnd_img1 = bckgrnd_img1.resize((password_window.winfo_screenwidth(), password_window.winfo_screenheight()), Image.BICUBIC)
	# convert the image to a TkPhoto object
	bckgrnd_img1 = ImageTk.PhotoImage(bckgrnd_img1)
	# Create a Label widget with the image as background
	background_label1 = ctk.CTkLabel(password_window, image=bckgrnd_img1)
	# Place the Label widget of the window
	background_label1.place(x=0, y=0, relwidth=1, relheight=1)

	# create a label to display the title
	length_label = ctk.CTkLabel(master=password_window, text="Length:")
	# place the label in the center of the window
	length_label.pack()
	# create an entry to get the length of the password
	length_entry = ctk.CTkEntry(master=password_window)
	# place the entry in the center of the window
	length_entry.pack()
	# create a variable to store the state of the checkbox
	upper_case_var = ctk.IntVar()
	# create a checkbox to include uppercase
	upper_case_check = ctk.CTkCheckBox(master=password_window, text="Include Uppercase", variable=upper_case_var)
	# place the checkbox in the center of the window
	upper_case_check.place(relx=0.2, rely=0.3, anchor="center")
	# create a variable to store the state of the checkbox
	lower_case_var = ctk.IntVar()
	# create a checkbox to include lowercase
	lower_case_check = ctk.CTkCheckBox(master=password_window, text="Include Lowercase", variable=lower_case_var)
	# place the checkbox in the center of the window
	lower_case_check.place(relx=0.35, rely=0.3, anchor="center")
	# create a variable to store the state of the checkbox
	digits_var = ctk.IntVar()
	# create a checkbox to include digits
	digits_check = ctk.CTkCheckBox(master=password_window, text="Include Digits", variable=digits_var)
	# place the checkbox in the center of the window
	digits_check.place(relx=0.2, rely=0.2, anchor="center")
	# create a variable to store the state of the checkbox
	symbols_var = ctk.IntVar()
	# create a checkbox to include symbols
	symbols_check = ctk.CTkCheckBox(master=password_window, text="Include Symbols", variable=symbols_var)
	# place the checkbox in the center of the window
	symbols_check.place(relx=0.35, rely=0.2, anchor="center")
	# create a label to display the password history
	history_label = ctk.CTkLabel(master=password_window, text="password History:")
	# place the label in the center of the window
	history_label.place(relx=0.8, rely=0.15, anchor="center")
	# create a listbox to display the password history
	history_listbox = tk.Listbox(master=password_window, height=5)
	# place the listbox in the center of the window
	history_listbox.place(relx=0.8, rely=0.25, anchor="center")
	# configure the listbox to expand horizontally and vertically
	history_listbox.config(bg="black", fg="white")
	# create a label to display the result
	result_label = ctk.CTkLabel(master=password_window, text="")
	# configure the label to expand horizontally and vertically
	result_label.pack(expand=True, fill=tk.BOTH)
	# place the label in the center of the window
	result_label.place(relx=0.8, rely=0.35, anchor="center")

	def generate_password():
		# Get user input for password length and character sets
		password_length = int(length_entry.get())
		# Check if password length is at least 12 characters
		if password_length < 12:
			messagebox.showerror("Error", "Please enter a password length of at least 12 characters")
			return
		upper_case = bool(upper_case_var.get())
		lower_case = bool(lower_case_var.get())
		digits = bool(digits_var.get())
		symbols = bool(symbols_var.get())

		# Check if at least one character set is selected
		if not any([upper_case, lower_case, digits, symbols]):
			messagebox.showerror("Error", "Please select at least one character set")
			return
		selected_character_sets = sum([upper_case, lower_case, digits, symbols])
		if selected_character_sets < 3:
			messagebox.showerror("Error", "Please select at least three character sets")
			return

		# Define character sets based on user input
		character_set = ""
		if upper_case:
			character_set += string.ascii_uppercase
		if lower_case:
			character_set += string.ascii_lowercase
		if digits:
			character_set += string.digits
		if symbols:
			character_set += string.punctuation

		# Generate password and update GUI
		password = "".join(random.choice(character_set) for i in range(password_length))
		result_label.configure(text="Generated password: " + password)

		# Add password to history and update GUI
		history_listbox.insert(0, password)

		# Limit history listbox to 10 entries
		if history_listbox.size() > 10:
			history_listbox.delete(10, tk.END)

		# Save passwords to encrypted file
		key = Fernet.generate_key()
		cipher = Fernet(key)
		with open('passwords.txt', 'a') as file:
			file.write(cipher.encrypt(password.encode()).decode() + '\n')

		# Save encryption key to file
		with open('keys.txt', 'a') as key_file:
			key_file.write(key.decode() + '\n')
	# the variable to open the image of the button
	backgroundimage = Image.open("password.jpg")
	# resize the image
	backgroundimage = backgroundimage.resize((15, 15), Image.BICUBIC)
	# the image variable for background
	back_image = ctk.CTkImage(backgroundimage)

	# Define GUI button to run the function
	generate_button = ctk.CTkButton(master=password_window, image=back_image, text="Generate password", command=generate_password)
	# place the generate button
	generate_button.pack(side="bottom", pady=10)
	# place the generate button
	generate_button.place(relx=0.8, rely=0.68, anchor="center")

	# Define GUI elements
	hash_label = ctk.CTkLabel(master=password_window, text="Enter hash value to bruteforce:")
	hash_label.pack()
	hash_label.place(relx=0.5, rely=0.5, anchor="center")
	hash_entry = ctk.CTkEntry(master=password_window, width=50)
	hash_entry.place(relx=0.5, rely=0.55, anchor="center")
	hash_entry.configure(width=500)

	# Define function to get file path
	def select_file():
		# Open file dialog
		file_path = filedialog.askopenfilename()
		# Clear entry and insert file path
		file_entry.delete(0, tk.END)
		# Insert file path
		file_entry.insert(0, file_path)
	# Define GUI button to run the function
	file_label = ctk.CTkLabel(master=password_window, text="Select file to bruteforce with:")
	# place the file label
	file_label.pack()
	# place the file label
	file_label.place(relx=0.5, rely=0.63, anchor="center")
	# define the file entry
	file_entry = ctk.CTkEntry(master=password_window)
	# place the file entry
	file_entry.pack(expand=True, fill="x")
	# place the file entry
	file_entry.place(relx=0.5, rely=0.68, anchor="center")
	# define th variable to open the image
	backgroundimage2 = Image.open("file.png")
	# resize image
	backgroundimage2 = backgroundimage2.resize((15, 15), Image.BICUBIC)
	# the back image variable of the button
	back_image2 = ctk.CTkImage(backgroundimage2)
	# Define GUI button to run the function
	file_button = ctk.CTkButton(master=password_window, image=back_image2, text="Browse...", command=select_file)
	# Define GUI button to run the function
	file_button.pack(expand=True, fill="x")
	# Define GUI button to run the function
	file_button.place(relx=0.65, rely=0.68, anchor="center")

	# Define program status label
	status_label = ctk.CTkLabel(master=password_window, text="Ready to Crack!")
	status_label.pack(expand=True, fill="x")
	status_label.place(relx=0.5, rely=0.73, anchor="center")

	# Define result label
	result_label1 = ctk.CTkLabel(master=password_window, text="")
	result_label1.place(relx=0.5, rely=0.77, anchor="center")

	# Define function to crack the hash
	def crack_hash():
		# Get user input for hash type, file path, and hash to decrypt
		file_path = file_entry.get()
		hash_to_decrypt = hash_entry.get()

		# Check if file path exists
		if not os.path.exists(file_path):
			result_label.configure(text="File/Path Doesnt Exist")
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
			result_label1.configure(text="Unknown hash type")
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
					result_label1.configure(text="Unknown hash type")
					return
				hashed_word = hash_object.hexdigest()

				# Check if the hashed word matches the hash to decrypt
				if hashed_word == hash_to_decrypt:
					result_label1.configure(text='Found ' + hash_type.upper() + ' password: ' + line.strip())
					# configure the status label
					status_label.configure(text="password Cracked!")
					return

		# If no match was found, print message
		result_label.configure(text="password Is Not In File.")
		status_label.configure(text="Finished Cracking!")

	def back():
		password_window.destroy()
	# place the background image of the button
	backgroundimage1 = Image.open("passwd.png")
	backgroundimage1 = backgroundimage1.resize((15, 15), Image.BICUBIC)
	back_image1 = ctk.CTkImage(backgroundimage1)

	how_to_use = ctk.CTkLabel(master=password_window, text="How to use Hash Cracker:" + "\n" + "2. Enter the hash value" + "\n" + "3. Select the file to bruteforce with" + "\n" + "4. Click the crack hash button " + "\n" + "Generate Passwords:" + "\n" + "1. Select the length of the password(12 at least)" + "\n" + "2. select at least 3 checkboxes" + "\n" + "3. press on the generate password button")
	how_to_use.pack(side="bottom")
	how_to_use.configure(font=("Courier", 14), fg_color="#0B1320")
	# Define GUI button to run the function
	crack_button = ctk.CTkButton(master=password_window, image=back_image1, text="Crack Hash", command=lambda: threading.Thread(target=crack_hash).start())
	crack_button.pack(expand=True, fill="x")
	crack_button.place(relx=0.35, rely=0.68, anchor="center")
	# create the back button
	back_button = ctk.CTkButton(master=password_window, text="Back", command=back)
	# place the back button
	back_button.pack(expand=True, fill="x")
	# place the back button
	back_button.place(relx=0.2, rely=0.68, anchor="center")
	# run the main loop
	password_window.mainloop()
