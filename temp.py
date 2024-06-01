import tkinter as tk
from passforge import CreateList

def recon_button_clicked():
  # Function for Recon button
  print("Recon button clicked!")

def create_wordlist_button_clicked():
  # Function for Create Wordlist button
  CreateList()

def bruteforce_login_button_clicked():
  # Function for Bruteforce Login button
  print("Bruteforce Login button clicked!")

# Create the main window with increased size
root = tk.Tk()
root.title("Security Toolkit")
root.geometry("400x300")  # Set window size (width x height)

# Create buttons with same size using width and height options
button_width = 15
button_height = 2

recon_button = tk.Button(root, text="Recon", command=recon_button_clicked, width=button_width, height=button_height)
create_wordlist_button = tk.Button(root, text="Create Wordlist", command=create_wordlist_button_clicked, width=button_width, height=button_height)
bruteforce_login_button = tk.Button(root, text="Bruteforce Login", command=bruteforce_login_button_clicked, width=button_width, height=button_height)

# Pack buttons with padding
recon_button.pack(pady=10)
create_wordlist_button.pack(pady=10)
bruteforce_login_button.pack(pady=10)

# Start the main event loop
root.mainloop()
