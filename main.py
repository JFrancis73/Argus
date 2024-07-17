import tkinter as tk
from passforge import CreateList
from person import find_person

def recon_button_clicked():
  # Function for Recon button
  print("Recon button clicked!")

def create_wordlist_button_clicked():
  # Function for Create Wordlist button
  CreateList()

def find_person_button_clicked():
  # Function for Find Person button
  find_person()

# Create the main window with increased size
root = tk.Tk()
root.title("Security Toolkit")
root.geometry("200x200")  # Set window size (width x height)

# Create buttons with same size using width and height options
button_width = 15
button_height = 2

#recon_button = tk.Button(root, text="Recon", command=recon_button_clicked, width=button_width, height=button_height)
find_person_button = tk.Button(root, text="Find Person", command=find_person_button_clicked, width=button_width, height=button_height)
create_wordlist_button = tk.Button(root, text="Create Wordlist", command=create_wordlist_button_clicked, width=button_width, height=button_height)

# Pack buttons with padding
#recon_button.pack(pady=10)
find_person_button.pack(pady=10)
create_wordlist_button.pack(pady=10)


# Start the main event loop
root.mainloop()
