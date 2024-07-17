from tkinter import *
from datetime import datetime
import subprocess
import os
import threading
import time

def CreateList():
	check = 0
	# Define function to validate date format
	def validate_date(text):
		try:
		    datetime.strptime(text, "%Y-%m-%d")
		    return True
		except ValueError:
		    return False

	# Create main window
	window = Tk()
	window.title("User Details")

	# Define variables to store user details
	login_url = StringVar(window)
	first_name = StringVar(window)
	last_name = StringVar(window)
	dob = StringVar(window)
	partner_first_name = StringVar(window)
	partner_last_name = StringVar(window)
	partner_dob = StringVar(window)
	child_first_name = StringVar(window)
	child_last_name = StringVar(window)
	child_dob = StringVar(window)
	father_first_name = StringVar(window)
	father_last_name = StringVar(window)
	father_dob = StringVar(window)
	mother_first_name = StringVar(window)
	mother_last_name = StringVar(window)
	mother_dob = StringVar(window)
	pet_name = StringVar(window)
	keywords = StringVar(window)

	# Create labels and entry fields
	Label(window, text="Login URL:").grid(row=0, column=0)
	Entry(window, textvariable=login_url).grid(row=0, column=1)

	Label(window, text="First Name:").grid(row=1, column=0)
	Entry(window, textvariable=first_name).grid(row=1, column=1)

	Label(window, text="Last Name:").grid(row=2, column=0)
	Entry(window, textvariable=last_name).grid(row=2, column=1)

	Label(window, text="Date of Birth:").grid(row=3, column=0)
	Entry(window, textvariable=dob).grid(row=3, column=1)

	# Add similar labels and entries for all remaining fields

	# Additional keywords entry
	Label(window, text="Additional Keywords:").grid(row=4, column=0)
	Entry(window, textvariable=keywords).grid(row=4, column=1)
	
	def submit_details():
		def display_window():
			"""
			Creates and manages a tkinter window with a message and two buttons.
			"""

			window = Tk()
			window.title("Wordlist Created!")

			# Larger font and navy color for the message
			label = Label(window, text="Wordlist created!", font=("Arial", 20, "bold"), fg="navy")
			label.pack(pady=20)  # Add padding above the label

			def close_window():
				window.destroy()

			close_button = Button(window, text="Close", command=close_window)
			close_button.pack(pady=10)

			def view_wordlist():
				with open("Curated_List.txt", "r") as file:
				    wordlist_data = file.read()

				# Create a new text widget and center data
				data_window = Toplevel(window)
				data_window.title("Wordlist Data")
				data_text = Text(data_window, font=("Arial", 12))
				data_text.pack(fill=BOTH, expand=True)
				data_text.insert(END, wordlist_data)

				# Center data horizontally (adjust as needed)
				data_text.tag_configure("center", justify=CENTER)
				data_text.see("end")  # Scroll to the end to ensure all content is visible
				data_text.tag_add("center", "1.0", "end")  # Apply centering tag

			view_button = Button(window, text="View", command=view_wordlist)
			view_button.pack()

			window.mainloop()

		global check
		# Access and process user input here
		# For example, print details to console
		print(f"First Name: {first_name.get()}")
		print(f"Last Name: {last_name.get()}")
		# ... and so on for other fields
		base_words = [first_name.get(),last_name.get(),] + keywords.get().split() #continue
		nums = dob.get()
		nums = [nums[:2],nums[:2]+nums[2:4],nums[4:]]
		base_words += nums
		print(base_words)
		with open("/tmp/base.txt","w") as file:
			for i in base_words:
			    file.write(i+"\n")
		#input(login_url.get())
		if login_url.get().strip() != "":
			os.system("cewl --with-numbers -a "+login_url.get().strip()+" >> /tmp/base.txt")
		os.system("python cupp/cupp.py -q -w /tmp/base.txt")
		os.system("python Wordlister/wordlister.py --cap --up --min 4 --max 16 --input cuppout.txt --output /tmp/templist.txt --perm 1")
		#os.system("source .venv/bin/activate")
		#wait = threading.Thread(target=wait_window, args = ("Training Model",))
		#wait.start()
		#os.system("cat rockyou_utf8.txt >> .tmp/templist.txt")
		#os.system("python models.py --training-data .tmp/templist.txt  --output-dir output --iters 200 --save-every 100")
		#check = 1
		#time.sleep(1.01)
		#wait = threading.Thread(target=wait_window, args = ("Generating Candidates",))
		#wait.start()
		#os.system("python sample.py --input-dir output --output GANout.txt --seq-length 12 --num-samples 100000")
		#os.system("uniq GANout.txt > UGANout.txt")
		os.system("john --wordlist=/tmp/templist.txt --rules --stdout | unique /tmp/JTRout.txt")
		os.system("cat /tmp/templist.txt > Curated_List.txt")
		os.system("cat /tmp/JTRout.txt >> Curated_List.txt")
		os.system("rm /tmp/JTRout.txt")
		check = 1
		display_window()
		window.close()

	
	Button(window, text="Generate Wordlist", command=submit_details).grid(row=5, column=1)

	def wait_window(msg):
		"""
	  	Creates and displays a training window.

	  	This function creates a tkinter window that displays "Training Model ." with animated periods.
	  	The window is centered, has a navy blue text color, a bold Arial font size 20, and closes
	  	automatically when the function exits.
	  	"""

	  	# Create the window
		window = Tk()
		window.title("Model Training")
		window.geometry("500x150")
		window.resizable(False, False)

	  	# Label for displaying training progress
		num_periods = 1
		message = f"{msg} {'.' * num_periods}"
		label = Label(
			  window,
			  text=message,
			  font=("Arial", 20, "bold"),
			  fg="navy",  # Set text color to navy
			  padx=10,  # Add internal padding (horizontal)
			  pady=50   # Add internal padding (vertical, top and bottom)
		  )
		label.pack(anchor=CENTER)  # Center the label

		def update_progress():
			global check
			if check ==1:
				window.destroy()
				check = 0
				return
			nonlocal num_periods, message  # Modify variables within the function

			num_periods = (num_periods + 1) % 6  # Ensures max of 5 periods
			message = f"{msg} {'.' * num_periods}"
			label.config(text=message)
			window.after(1000, update_progress)

		  # Start animation
			update_progress()

		  # Display the window and close automatically when the function exits
			window.mainloop()

		# Call the function to display the training window
		import tkinter as tk

		def display_window():
			"""
			Creates and manages a tkinter window with a message and two buttons.
			"""

			window = Tk()
			window.title("Wordlist Created!")

			# Larger font and navy color for the message
			label = Label(window, text="Wordlist created!", font=("Arial", 20, "bold"), fg="navy")
			label.pack(pady=20)  # Add padding above the label

			def close_window():
				window.destroy()

			close_button = Button(window, text="Close", command=close_window)
			close_button.pack(pady=10)

			def view_wordlist():
				with open("Curated_List.txt", "r") as file:
				    wordlist_data = file.read()

				# Create a new text widget and center data
				data_window = Toplevel(window)
				data_window.title("Wordlist Data")
				data_text = Text(data_window, font=("Arial", 12))
				data_text.pack(fill=BOTH, expand=True)
				data_text.insert(END, wordlist_data)

				# Center data horizontally (adjust as needed)
				data_text.tag_configure("center", justify=CENTER)
				data_text.see("end")  # Scroll to the end to ensure all content is visible
				data_text.tag_add("center", "1.0", "end")  # Apply centering tag

			view_button = Button(window, text="View", command=view_wordlist)
			view_button.pack()

			window.mainloop()


		# Submit button
		#Button(window, text="Generate", command=submit_details).grid(row=5, column=1)

		# Run the main event loop
		window.mainloop()
