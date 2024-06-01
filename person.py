from tkinter import *
import subprocess

def get_info():
  """
  This function collects data from the input fields and checkboxes when the "Search" button is clicked.
  """
  name = name_entry.get()
  username = username_entry.get()
  selected_sites = []
  if instagram_var.get() == 1:
    selected_sites.append("Instagram")
  if facebook_var.get() == 1:
    selected_sites.append("Facebook")
  if linkedin_var.get() == 1:
    selected_sites.append("LinkedIn")
  additional_sites = additional_text.get("1.0", END).strip()  # Get text from text field and remove whitespace
  if additional_sites:
    selected_sites.extend(additional_sites.split(","))  # Split comma-separated entries

  # Display collected data in the console for demonstration purposes
  print(f"Name: {name}")
  print(f"Username: {username}")
  print(f"Selected Sites: {', '.join(selected_sites)}")
  with open("/tmp/Person_recon.txt","w") as File:
  	File.write("Potential Matches:\n")
  for k in range(len(selected_sites)):
  	x = subprocess.run(["googler",name+" "+selected_sites[k],"-n","10","--noprompt","-C"],stdout=subprocess.PIPE,text=True)
  	print(x.stdout)
  	output = x.stdout.split("\n")
  	output = [i for i in output if i!=""]
  	for i in range(0,len(output),2):
  		if "profiles" in output[i].lower():
  			continue
  		flag = True
  		for j in range(len(name.split())):
  			if name.split()[j].lower() in output[i].lower():
  				continue
  			flag = False
  			break
  		if flag:
  			with open("/tmp/Person_recon.txt","a") as File:
  				File.write(output[i][3:]+": "+output[i+1]+"\n")
				
  print(x.stdout)
  #print(len(x.stdout.split("\n")))

# Create the main window
root = Tk()
root.title("Search User Information")

# Name input field
name_label = Label(root, text="Name:")
name_label.pack()
name_entry = Entry(root)
name_entry.pack()

# Username input field
username_label = Label(root, text="Username:")
username_label.pack()
username_entry = Entry(root)
username_entry.pack()

# Search sites label
search_label = Label(root, text="Sites to Search:")
search_label.pack()

# Checkboxes for social media sites
instagram_var = IntVar()
facebook_var = IntVar()
linkedin_var = IntVar()
instagram_check = Checkbutton(root, text="Instagram", variable=instagram_var)
facebook_check = Checkbutton(root, text="Facebook", variable=facebook_var)
linkedin_check = Checkbutton(root, text="LinkedIn", variable=linkedin_var)
instagram_check.pack()
facebook_check.pack()
linkedin_check.pack()

# Text field for additional websites
additional_label = Label(root, text="Additional Websites to Search(comma-separated):")
additional_label.pack()
additional_text = Text(root, height=1)
additional_text.pack()

# Search button
search_button = Button(root, text="Search", command=get_info)
search_button.pack()

# Run the main event loop
root.mainloop()
