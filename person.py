from tkinter import *
import subprocess
import re
from urllib.parse import urlparse
from txttohtml import create_html_table_from_txt

def find_person():
	def filter_google_results(output,selected_sites,name,username,urls_found):
		for i in range(0,len(output),2):
			if "profiles" in output[i].lower():
				continue
			flag = True
			parsed_url = urlparse(output[i+1])
			netloc = parsed_url.netloc  # Get hostname
			# Split hostname by dots to get website name (assuming single subdomain)
			if netloc:
				parts = netloc.split('.')
				if len(parts) == 2:  # Check for at least two parts (website name and TLD)
					website = parts[0]  # Return the first part (website name)
				elif len(parts) > 2:
					website = parts[1]
			for j in range(len(name.split())):
				if ((name != "" and (name.split()[j].lower() in output[i].lower() or name.split()[j].lower() in output[i+1].lower())) or (username!="" and (username.lower() in output[i].lower() or username.lower() in output[i+1].lower())) and website.lower() in selected_sites):
					continue
				flag = False
				break
			if flag and output[i+1] not in urls_found:
				with open("/tmp/Person_recon.txt","a") as File:
					File.write(output[i][3:]+": "+output[i+1]+"\n")
					urls_found.append(output[i+1])
		return urls_found

	def filter_duckduckgo_results(output,selected_sites,name,username,urls_found):
		for i in range(0,len(output),3):
			if "profiles" in output[i].lower():
				continue
			flag = True
			parsed_url = urlparse(output[i+1])
			netloc = parsed_url.netloc  # Get hostname
			# Split hostname by dots to get website name (assuming single subdomain)
			if netloc:
				parts = netloc.split('.')
				if len(parts) == 2:  # Check for at least two parts (website name and TLD)
					website = parts[0]  # Return the first part (website name)
				elif len(parts) > 2:
					website = parts[1]
			for j in range(len(name.split())):
				if ((name != "" and (name.split()[j].lower() in output[i].lower() or name.split()[j].lower() in output[i+1].lower())) or (username!="" and (username.lower() in output[i].lower() or username.lower() in output[i+1].lower())) and website.lower() in selected_sites):
					continue
				flag = False
				break
			if flag and output[i+1] not in urls_found:
				with open("/tmp/Person_recon.txt","a") as File:
					File.write(output[i][3:]+": "+output[i+1]+"\n")
					urls_found.append(output[i+1])
		return urls_found
	
	def get_info():
	  """
	  This function collects data from the input fields and checkboxes when the "Search" button is clicked.
	  """
	  urls_found  = []
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
	  selected_sites = [i.lower().strip() for i in selected_sites]
	
	  # Display collected data in the console for demonstration purposes
	  print(f"Name: {name}")
	  print(f"Username: {username}")
	  print(f"Selected Sites: {', '.join(selected_sites)}")
	  with open("/tmp/Person_recon.txt","w") as File:
	  	pass #File.write("Potential Matches:\n")
	  commands = []
	  for i in range(len(selected_sites)):
	  	if name.strip() != "":
	  		commands.extend([name+" "+selected_sites[i], 
	  										"\""+name+"\" "+selected_sites[i], ])
	  										#"\""+name+"\" \""+selected_sites[i]+"\"",
	  										#"\""+name+"\" site:"+selected_sites[i]])
	  	
	  	if username.strip() != "":
	  		commands.extend([username+" "+selected_sites[i], 
	  										"\""+username+"\" "+selected_sites[i], ])
	  										#"\""+username+"\" \""+selected_sites[i]+"\"",
	  										#"\""+username+"\" site:"+selected_sites[i]])
	  counter = 0
	  commands_per_site = 4 if username.strip()=="" or name.strip()=="" else 8
	  for command in commands:
	  	if counter % commands_per_site == 0:
	  		print("[+] Searching ",selected_sites[int(counter//commands_per_site)])
	  	counter += 1
	  	x = subprocess.run(["googler",command,"-n","10","--noprompt","-C"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	  	y = subprocess.run(["ddgr","-x",command,"-n","3","--noprompt","-C"],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
	  	output = x.stdout.split("\n")
	  	output1 = y.stdout.split("\n")
	  	print(y.stdout,end="")
	  	output = [i for i in output if i!=""]
	  	output1 = [i for i in output1 if i!=""] 
	  	urls_found = filter_google_results(output,selected_sites,name,username,urls_found)
	  	urls_found = filter_duckduckgo_results(output1,selected_sites,name,username,urls_found)
	  	create_html_table_from_txt("/tmp/Person_recon.txt","Output/recon_table.html")
	  result = subprocess.run(["firefox","Output/recon_table.html"])
	  """
	  	for i in range(0,len(output),2):
	  		if "profiles" in output[i].lower():
	  			continue
	  		flag = True
	  		parsed_url = urlparse(output[i+1])
	  		netloc = parsed_url.netloc  # Get hostname
	  		# Split hostname by dots to get website name (assuming single subdomain)
	  		if netloc:
	  			parts = netloc.split('.')
	  			if len(parts) == 2:  # Check for at least two parts (website name and TLD)
	  				website = parts[0]  # Return the first part (website name)
	  			elif len(parts) > 2:
	  				website = parts[1]
	  		for j in range(len(name.split())):
	  			if ((name != "" and (name.split()[j].lower() in output[i].lower() or name.split()[j].lower() in output[i+1].lower())) or (username!="" and (username.lower() in output[i].lower() or username.lower() in output[i+1].lower())) 	and website.lower() in selected_sites):
	  				continue
	  			flag = False
	  			break
	  		if flag and output[i+1] not in urls_found:
	  			with open("/tmp/Person_recon.txt","a") as File:
	  				File.write(output[i][3:]+": "+output[i+1]+"\n")
	  				urls_found.append(output[i+1])
	  				"""
		#sherlock = subprocess.run("sherlock
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
	instagram_var = IntVar(root)
	facebook_var = IntVar(root)
	linkedin_var = IntVar(root)
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
	
#find_person()
