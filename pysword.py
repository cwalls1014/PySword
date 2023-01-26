import tkinter as tk
import os
from hashlib import pbkdf2_hmac
from cryptography.fernet import Fernet
import base64
import random
import sqlite3
from cryptography.fernet import Fernet
import pyperclip
import tkinter.messagebox as messagebox

class PySword:
	def __init__(self, master):
		self.master = master
		master.title("PySword")
		self.label = tk.Label(master, text="Welcome to PySword!")
		self.label.grid(row=0,column=0,sticky='W')
		self.masterFile = "master"
		self.saltFile = "salt"
		self.keyFile = "key"
		
		self.lower_case_letters = ('a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j',
								   'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't',
								   'u', 'v', 'w', 'x', 'y', 'z')

		self.upper_case_letters = ('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'K',
								   'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U',
								   'V', 'W', 'X', 'Y', 'Z')

		self.numbers = ('0', '1', '2', '3', '4', '5', '6', '7', '8', '9')

		self.symbols = ('!', '@', '#', '$', '%', '&', '*', '?')

		self.characters = (self.lower_case_letters, self.upper_case_letters, self.numbers, self.symbols)

		if os.path.exists(self.masterFile):
			self.login_screen()
		else:
			#connect to the database
			self.conn = sqlite3.connect('accounts.db')
			#create a cursor object
			self.c = self.conn.cursor()
			#create the table
			self.c.execute('''CREATE TABLE Accounts (Website TEXT, User_Name TEXT, Salt BLOB, Password BLOB, Key BLOB)''')
			#commit the changes
			self.conn.commit()

			self.no_password_created()

	def login_screen(self):
		self.master_password_label = tk.Label(self.master, text="Enter Master Password:")
		self.master_password_label.grid(row=0, column=0, sticky='W')
		self.master_password_entry = tk.Entry(self.master)
		self.master_password_entry.focus()
		self.master_password_entry.config(show='*')
		self.master_password_entry.grid(row=0, column=1, sticky='W')
		self.master_password_entry.config(show='*')
		self.master_password_entry.bind('<Return>', self.check_password)
		self.submit_button = tk.Button(self.master, text="Submit", command=self.check_password)
		self.submit_button.grid(row=1, column=0, columnspan=2, pady=10)

	def no_password_created(self):
		self.create_master_password_label = tk.Label(self.master, text="No Master Password found. Please create one.")
		self.create_master_password_label.grid(row=0, column=0, sticky='W')
		self.create_master_password_entry = tk.Entry(self.master)
		self.create_master_password_entry.focus()
		self.create_master_password_entry.config(show='')
		self.create_master_password_entry.grid(row=1, column=0, columnspan=2, sticky='W')
		self.create_master_password_confirm_entry = tk.Entry(self.master)
		self.create_master_password_confirm_entry.grid(row=2, column=0, columnspan=2, sticky='W')
		self.create_master_password_confirm_entry.config(show='')
		self.create_master_password_confirm_entry.bind('<Return>', self.create_master_password)
		self.create_master_password_button = tk.Button(self.master, text="Create", command=self.create_master_password)
		self.create_master_password_button.grid(row=3, column=0, sticky='W')

	def create_master_password(self, event=None):
		master_password = self.create_master_password_entry.get()
		master_password_confirm = self.create_master_password_confirm_entry.get()
		if master_password == master_password_confirm:
			if len(master_password) < 15:
				self.show_error_message("Password must be at least 15 characters in length.")
				self.clear_error_message()
			else:   
				is_lower = [characters in self.lower_case_letters for characters in master_password]
				is_upper = [characters in self.upper_case_letters for characters in master_password]
				is_number = [characters in self.numbers for characters in master_password]
				is_symbol = [characters in self.symbols for characters in master_password]
				if any(is_lower) == True and any(is_upper) == True and any(is_number) == True and any(is_symbol) == True:
					#generate a random salt
					salt = self.generate_salt()
					#use the salt to derive a key from the password
					key = self.derive_key(master_password, salt)
					#encrypt the password
					encrypted_password = self.encrypt_password(master_password, key)
					#store the salt, encrypted password, and key
					with open(self.saltFile, 'wb') as file:
						file.write(salt)
					with open(self.masterFile, 'wb') as file:
						file.write(encrypted_password)
					with open(self.keyFile, 'wb') as file:
						file.write(key)

					self.show_main_menu()
				else:
					self.show_error_message("Passwords must include lowercase, uppercase, numbers, and special characters.")
					self.clear_error_message()
		else:
			self.show_error_message("Passwords do not match.")
			self.clear_error_message()

	def check_password(self, event=None):
		entered_password = self.master_password_entry.get()

		with open(self.masterFile, "rb") as encrypted_master_file:
			encrypted_master = encrypted_master_file.read()
		with open(self.keyFile, "rb") as key_file:
			key = key_file.read()

		decrypted_password = self.decrypt_password(encrypted_master, key)

		if entered_password == decrypted_password:
				self.show_main_menu()
		else:
			self.show_error_message("Incorrect master password.")
			self.clear_error_message()

	def show_main_menu(self):
		#connect to the database
		self.conn = sqlite3.connect('accounts.db')
		#create a cursor object
		self.c = self.conn.cursor()
		# clear the login screen
		self.remove_widgets()
		self.main_frame = tk.Frame(self.master)
		self.main_frame.grid(row=0, column=0,sticky='W')

		self.account_list = tk.Listbox(self.main_frame)
		self.account_list.grid(row=0, column=0,sticky='W')
		self.account_list.bind('<<ListboxSelect>>', self.show_account_info)
		self.load_accounts_to_list()

		self.account_info_frame = tk.Frame(self.main_frame)
		self.account_info_frame.grid(row=0, column=1,sticky='W')
		self.account_info_label = tk.Label(self.account_info_frame, text="Select an account to view its information.")
		self.account_info_label.grid(row=0, column=1,sticky='W')

		self.copy_password_button = tk.Button(self.account_info_frame, text="Copy Password", command=self.copy_password)
		self.copy_password_button.grid(row=0, column=2, sticky='W')

		self.button_frame = tk.Frame(self.master)
		self.button_frame.grid(row=1, column=0,columnspan=3,sticky='W')

		self.logout_button = tk.Button(self.button_frame, text="Logout", command=self.logout)
		self.logout_button.grid(row=0, column=0,sticky='W')

		self.add_button = tk.Button(self.button_frame, text="Add", command=self.add_account)
		self.add_button.grid(row=0, column=1,sticky='W')

		self.edit_button = tk.Button(self.button_frame, text="Edit", command=self.edit_account)
		self.edit_button.grid(row=0, column=2,sticky='W')

		self.delete_button = tk.Button(self.button_frame, text="Delete", command=self.delete_account)
		self.delete_button.grid(row=0, column=3,sticky='W')

		self.search_button = tk.Button(self.button_frame, text="Search", command=self.search_account)
		self.search_button.grid(row=0, column=4,sticky='W')
		self.search_entry = tk.Entry(self.button_frame)
		self.search_entry.focus()
		self.search_entry.grid(row=0, column=5,sticky='W')

	def search_account(self):
		self.c.execute("SELECT website FROM accounts ORDER BY website ASC")
		accounts = self.c.fetchall()
		if len(accounts) < 1:
			messagebox.showinfo("oops", "No accounts to search for!")
		else:
			account_name = self.search_entry.get()
			for account in accounts:
				account = ''.join(account)
				if account_name == account:
					index = self.account_list.get(0, 'end').index(account_name)
					self.account_list.activate(index)
					self.account_list.selection_clear(0, 'end')
					self.account_list.selection_set(index, last=index)
					self.account_list.see(index)
				else:
					messagebox.showinfo("oops", "Account does not exist!")

	def copy_password(self):
		selected_account = self.account_list.get(self.account_list.curselection()[0])
		info = self.get_account_info(selected_account)
		password = info.split("\n")[2].split(": ")[1]
		pyperclip.copy(password)
		messagebox.showinfo("Got it!", "Password copied to clipboard!")

	def add_account(self):
		# Open a new window for adding a password
		self.add_account_window = tk.Toplevel(self.master)
		self.add_account_window.title("Add Account")

		# Create input fields for website, username, and password
		website_label = tk.Label(self.add_account_window, text="Website:")
		website_label.grid(row=0,column=0,sticky='W')
		self.website_entry = tk.Entry(self.add_account_window)
		self.website_entry.focus()
		self.website_entry.grid(row=0,column=1,sticky='W')

		username_label = tk.Label(self.add_account_window, text="Username:")
		username_label.grid(row=1,column=0,sticky='W')
		self.username_entry = tk.Entry(self.add_account_window)
		self.username_entry.grid(row=1,column=1,sticky='W')

		password_label = tk.Label(self.add_account_window, text="Password:")
		password_label.grid(row=2,column=0,sticky='W')
		self.password_entry = tk.Entry(self.add_account_window)
		self.password_entry.config(show='*')
		self.password_entry.grid(row=2,column=1,sticky='W')

		# Create a button to generate a random password
		generate_password_button = tk.Button(self.add_account_window, text="Generate Password", command=self.generate_random_password)
		generate_password_button.grid(row=3,column=0,sticky='W')

		# Create buttons to cancel, add password
		add_account_button = tk.Button(self.add_account_window, text="Add Account", command=self.save_account)
		add_account_button.grid(row=3,column=1,sticky='W')
		cancel_button = tk.Button(self.add_account_window, text="Cancel", command=self.add_account_window.destroy)
		cancel_button.grid(row=3,column=2,sticky='W')

	def edit_account(self):
		# Open a new window for adding a password
		self.edit_account_window = tk.Toplevel(self.master)
		self.edit_account_window.title("Edit Account")

		# Create input fields for website, username, and password
		website_label = tk.Label(self.edit_account_window, text="Website:")
		website_label.grid(row=0,column=0,sticky='W')
		self.website_entry = tk.Entry(self.edit_account_window)
		self.website_entry.focus()
		self.website_entry.grid(row=0,column=1,sticky='W')

		username_label = tk.Label(self.edit_account_window, text="Username:")
		username_label.grid(row=1,column=0,sticky='W')
		self.username_entry = tk.Entry(self.edit_account_window)
		self.username_entry.grid(row=1,column=1,sticky='W')

		password_label = tk.Label(self.edit_account_window, text="Password:")
		password_label.grid(row=2,column=0,sticky='W')
		self.password_entry = tk.Entry(self.edit_account_window)
		self.password_entry.config(show='*')
		self.password_entry.grid(row=2,column=1,sticky='W')

		# Create a button to generate a random password
		generate_password_button = tk.Button(self.edit_account_window, text="Generate Password", command=self.generate_random_password)
		generate_password_button.grid(row=3,column=0,sticky='W')

		# Create buttons to cancel, edit account
		edit_account_button = tk.Button(self.edit_account_window, text="Edit Account", command=self.update_account)
		edit_account_button.grid(row=3,column=1,sticky='W')
		cancel_button = tk.Button(self.edit_account_window, text="Cancel", command=self.edit_account_window.destroy)
		cancel_button.grid(row=3,column=2,sticky='W')

		self.fill_in_entry_fields()

	def delete_account(self):
		selected_account = self.account_list.get(self.account_list.curselection()[0])
		self.c.execute("DELETE FROM accounts WHERE website=?", (selected_account,))
		messagebox.showinfo("Gone!", "Account has been deleted!")
		self.load_accounts_to_list()

	def save_account(self):
		website = self.website_entry.get()
		userName = self.username_entry.get()
		password = self.password_entry.get()
		# Make sure all fields are entered
		if website == '' or userName == '' or password == '':
			self.show_error_message("All fields required!")
			self.clear_error_message()
			return
		# Generate a random salt
		salt = self.generate_salt()
		# Use the salt to derive a key from the password
		key = self.derive_key(password, salt)
		# Encrypt the password
		encrypted_password = self.encrypt_password(password, key)
		# Store the salt, encrypted hash, and key
		self.c.execute("INSERT INTO Accounts (Website, User_Name, Salt, Password, Key) VALUES (?, ?, ?, ?, ?)", (website, userName, salt, encrypted_password, key.decode()))
		# Commit the changes
		self.conn.commit()
		self.add_account_window.destroy()
		self.load_accounts_to_list()

	def update_account(self):
		website = self.website_entry.get()
		userName = self.username_entry.get()
		password = self.password_entry.get()
		# Make sure all fields are entered
		if website == '' or userName == '' or password == '':
			self.show_error_message("All fields required!")
			self.clear_error_message()
			return
		# Generate a random salt
		salt = self.generate_salt()
		# Use the salt to derive a key from the password
		key = self.derive_key(password, salt)
		# Encrypt the password
		encrypted_password = self.encrypt_password(password, key)
		# Store the salt, encrypted hash, and key
		self.c.execute("UPDATE accounts SET website=?, user_name=?, password=?, key=? WHERE website=?", (website, userName, encrypted_password, key, website))
		# Commit the changes
		self.conn.commit()
		self.edit_account_window.destroy()
		self.load_accounts_to_list()

	""" BACKEND FUNCTIONALITY """

	def show_error_message(self, message):
		active_window = self.master.focus_get() # get the currently active window
		self.error_label = tk.Label(active_window, text=message, fg="red")
		self.error_label.grid(row=0, column=0, sticky='W')

	def clear_error_message(self):
		self.master.after(3000, self.error_label.destroy)

	def generate_salt(self):
		return os.urandom(16)

	def derive_key(self, password, salt):
		key = pbkdf2_hmac(hash_name='sha256', password=password.encode(), salt=salt, iterations=100000)
		return base64.urlsafe_b64encode(key)

	def encrypt_password(self, password, key):
		password = password.encode()
		return Fernet(key).encrypt(password)

	def decrypt_password(self, password, key):
		return Fernet(key).decrypt(password).decode()

	def decrypt_stored_password(self, encrypted_password, key):
		# decrypt the stored password
		f = Fernet(key)
		password = f.decrypt(encrypted_password)
		return password

	def logout(self):
		#close the connection
		self.conn.close()
		# clear the main menu screen
		self.remove_widgets()
		# show the login screen again
		self.login_screen()

	def remove_widgets(self):
		for widget in self.master.winfo_children():
			widget.destroy()

	def generate_random_password(self):
		password = []
		character_count = 0
		while character_count < 18:
			pick_character_type = random.choice(self.characters)
			pick_character = random.choice(pick_character_type)
			password.append(pick_character)
			character_count += 1
			if character_count % 6 == 0 and character_count < 18:
				password.append('-')
		self.password_entry.delete(0, tk.END)
		self.password_entry.insert(0, ''.join(password))

	def fill_in_entry_fields(self):
		selected_account = self.account_list.get(self.account_list.curselection()[0])
		self.c.execute("SELECT * FROM accounts WHERE website=?", (selected_account,))
		account_info = self.c.fetchone()
		self.website_entry.delete(0, tk.END)
		self.website_entry.insert(0, account_info[0])
		self.username_entry.delete(0, tk.END)
		self.username_entry.insert(0, account_info[1])
		self.password_entry.delete(0, tk.END)
		self.password_entry.insert(0, self.decrypt_password(account_info[3], account_info[4]))

	def get_account_info(self, account):
		self.c.execute("SELECT * FROM accounts WHERE website=?", (account,))
		account_info = self.c.fetchone()
		website = account_info[0]
		userName = account_info[1]
		encryptedPassword = account_info[3]
		key = account_info[4]

		# decrypt the encrypted password
		password = self.decrypt_password(encryptedPassword, key)
		
		return f"Website: {website}\nUsername: {userName}\nPassword: {password}"

	def load_accounts_to_list(self):
		self.account_list.delete(0, 'end')
		self.c.execute("SELECT website FROM accounts ORDER BY website ASC")
		accounts = self.c.fetchall()
		for account in accounts:
			self.account_list.insert('end', account[0])

	def show_account_info(self, event):
		selected = self.account_list.curselection()
		if len(selected) == 0:
			pass
		else:
			selected_account = self.account_list.get(self.account_list.curselection()[0])
			account_info = self.get_account_info(selected_account)
			self.account_info_label.config(text=account_info)

root = tk.Tk()
app = PySword(root)
root.mainloop()
