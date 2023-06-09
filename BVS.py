#!/usr/bin/python3
import socket
import os
import re
import subprocess
import time
import datetime
from datetime import date
from datetime import datetime


# function to append results of scans to a file in a directory
def append_to_file(content, scan):
    # gets the current date to add to the name of the file
    today = date.today()
    # creates the directory
    os.makedirs("BVS_logs", exist_ok=True)
    # appends to the file within the file path listed below, if it doesn't exist it creates the file
    f = open(f"BVS_logs/{today}{scan}.txt", "a")
    f.write(f"{content}\n")
    f.close()


# Function to check if an IP address is valid
def is_valid_ip_address(ip):
    try:
        socket.inet_pton(socket.AF_INET, ip)  # Check IPv4 format
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)  # Check IPv6 format
            return True
        except socket.error:
            return False

# Function to get a valid port number from the user
def get_valid_port(prompt):
    # Loop until a valid port number is entered
    while True:
        port = input(prompt)
        try:
            # Attempt to convert the input to an integer
            port = int(port)
            # Check if the port number is within valid range
            if 1 <= port <= 65535:
                return port
            else:
                print("Invalid port number. Please enter a number between 1 and 65535.")
        except ValueError:
            print("Invalid input. Please enter a valid port number.")

# Function to get a valid choice from the user
def get_valid_choice(prompt):
    valid_choices = ["1", "2", "3"]
    while True:
        choice = input(prompt).strip()
        if choice in valid_choices:
            return choice
        else:
            print("Invalid choice. Please enter 1, 2, or 3.")

# Function to scan a single port on a host
def scan_single_port(host, port):
    # Creates a new socket object
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1)
        # Use the socket object to establish a TCP connection with host
        # If return value is 0 connect is established
        return s.connect_ex((host, port)) == 0

# Function to scan multiple ports on a host
def scan_multiple_ports(host, ports):
    open_ports = []
    # Iterates over a list of ports and calls scan_single_port to scan all ports
    for port in ports:
        if scan_single_port(host, port):
            open_ports.append(port)
    return open_ports

    # Function to scan a range of ports on a host
    def scan_range_ports(host, start_port, end_port):
        open_ports = scan_multiple_ports(host, range(start_port, end_port + 1))
        return open_ports

    print("This will scan for open ports.")

def portscan():
    # Get the host (IP address) from the user
    print("This will scan for open ports.")
    while True:
        host = input('Enter the host to scan (IP address): ').strip()

        if is_valid_ip_address(host):
            break  # Valid IP address, break out of the loop
        else:
            print('Invalid IP address format. Please enter a valid IP address.')

    # Get the choice from the user
    choice = get_valid_choice(
        'Do you want to scan (1) a single port, (2) multiple ports, or (3) a range of ports? ')

    if choice == '1':
        # Scan a single port
        port = get_valid_port('Enter the port number to scan: ')
        if scan_single_port(host, port):
            print(f'Port {port} is open')
            append_to_file(f"{host} has an open port of {port}.", "_portscan")
        else:
            print(f'Port {port} is closed')
            append_to_file(f"Port {port} is closed on {host}", "_portscan")

    elif choice == '2':
        # Scan multiple ports
        ports = []
        while True:
            port = input('Enter a port number to scan (r to run): ')
            if port == "r":
                break
            else:
                try:
                    port = int(port)
                    if 1 <= port <= 65535:
                        ports.append(port)
                    else:
                        print("Invalid port number. Please enter a number between 1 and 65535.")
                except ValueError:
                    print("Invalid input. Please enter a valid port number.")

        open_ports = scan_multiple_ports(host, ports)

        if open_ports:
            print(f'Open ports: {open_ports}')
            append_to_file(f"{host} has the open ports: {open_ports}", "_portscan")
        else:
            print('No open ports found.')
            append_to_file(f"No open ports found on {host}.", "_portscan")

    elif choice == '3':
        # Scan a range of ports
        start_port = get_valid_port('Enter the start port: ')
        end_port = get_valid_port('Enter the end port: ')

        open_ports = scan_range_ports(host, start_port, end_port)

        if open_ports:
            print(f'Open ports: {open_ports}')
            append_to_file(f"{host} has the open ports: {open_ports}", "_portscan")
        else:
            print('No open ports found.')
            append_to_file(f"No open ports found on {host}.", "_portscan")

    else:
        print('Invalid choice.')
    # Asks if you want to get a more detailed scan using nmap's vulners script with the ability to quit and go to the main menu
    resp = input("Enter y/n to do a more detailed scan, 'q' to quit or 'x' to return to main menu: ")
    while not (resp in ["q", "x", "y", "n"]):
        resp = input("Invalid input, please try again: ")
    if resp == "q":
        exit()
    elif resp == "x":
        main()
    elif resp == "y":
        # accounts for the different choices chosen at the beginning of the port scan
        if choice == "1":
            scan = subprocess.run(["nmap", "-sV", "--script", "vulners", "-p", f"{port}", f"{host}"],
                                  capture_output=True, text=True)
            out = str(scan.stdout)
            print(out)
            append_to_file(out, "_portscan")
        elif choice == "2":
            for i in ports:
                str(i)
            ports_join = ",".join(ports)
            scan = subprocess.run(["nmap", "-sV", "--script", "vulners", "-p", f"{ports_join}", f"{host}"],
                                  capture_output=True, text=True)
            out = str(scan.stdout)
            print(out)
            append_to_file(out, "_portscan")
        elif choice == "3":
            range_of_ports = f"{start_port}-{end_port}"
            scan = subprocess.run(["nmap", "-sV", "--script", "vulners", "-p", f"{range_of_ports}", f"{host}"],
                                  capture_output=True, text=True)
            out = str(scan.stdout)
            print(out)
            append_to_file(out, "_portscan")


# function that gets a list of available upgrades on your system
def aptupd():
    # print("You chose apt update and it worked. yay")
    print("This will check for out of date software packages:\n")
    print("Updating update list: ")
    os.system("sudo apt update")
    print("Upgradeable apps: ")
    os.system("apt list --upgradeable")
    append_to_file(os.system("apt list --upgradeable"), "_updatesAvail")


# function that gets a list of users within the sudo group
def list_sudo_users():
    # print("Users with Sudo permissions: ")
    # first bash command to read group file
    p1 = subprocess.Popen(["cat", "/etc/group"], stdout=subprocess.PIPE)
    # finds sudo group
    p2 = subprocess.run(['grep', "^sudo"], stdin=p1.stdout, capture_output=True)
    # ensures subprocess output is a workable string, this may not be necessary
    s1 = str(p2.stdout)
    # divides string into a nice list so we can get rid of unneeded text
    l1 = s1.split(":")
    # pulls out the user list
    sdusers = (l1[-1])
    # changes single line list into a column list
    userclean = sdusers.replace(",", "\n")
    # cleans up a stray \n' that was at the end of the list, left over from the original file formatting
    userclean = userclean.replace("\\n\'", "")
    ctime = datetime.now()
    userclean = str(f"The following users currently have Sudo Permissions as of {ctime}: \n{userclean}\n")
    # prints list
    print(userclean)
    append_to_file(userclean, "_sudoUsers")


# function that checks permissions of sensitive files such as the .ssh file and the shadow file
def get_permissions(file_path):
    try:
        # Attempt to run ls -ld command to get the permissions of the specified file or directory
        ls_output = subprocess.run(['ls', '-ld', file_path], capture_output=True, text=True)
        # Extract permissions from the command output
        permissions = ls_output.stdout.split()[0]
        return permissions
    except subprocess.CalledProcessError:
        return None

def permissions_check():
    # Get and print the permissions for the /etc/shadow file
    etc_shadow_permissions = get_permissions('/etc/shadow')
    print(f'Permissions for /etc/shadow: {etc_shadow_permissions}')

    # Iterate over the users in the /home directory
    home_dir = '/home'
    users = subprocess.run(['ls', '-1', home_dir], capture_output=True, text=True).stdout.splitlines()
    for user in users:
        # Check if the user has a .ssh directory
        ssh_dir = f'{home_dir}/{user}/.ssh'
        if subprocess.run(['test', '-d', ssh_dir]).returncode == 0:
            # If the .ssh directory exists, get and print its permissions
            ssh_permissions = get_permissions(ssh_dir)
            print(f'Permissions for {ssh_dir} (User: {user}): {ssh_permissions}')
            append_to_file(f'Permissions for {ssh_dir} (User: {user}): {ssh_permissions}', "_permissions")
        else:
            print(f'User {user} has no .ssh folder')


# function that checks for the word "password" within the users home directory
def find_password_files(root_dir):
    password_files = []
    # Runs command in terminal to run find command to search for files with password in name
    ls_output = subprocess.run(['find', root_dir, '-type', 'f', '-iname', '*password*'], capture_output=True,
                               text=True)
    # Split the output into individual file paths
    file_paths = ls_output.stdout.splitlines()
    for file_path in file_paths:
        # Add each file path to the list of password files
        password_files.append(file_path)
        # Append the list of password files to a seperate file for reference
    append_to_file(f"The files that contain passwords are: {password_files}\n", "_passwordFiles")
    return password_files

def file_name_password():
    home_dir = '/home'
    # Get a list of all users in the home directory
    users = subprocess.run(['ls', '-1', home_dir], capture_output=True, text=True).stdout.splitlines()
    for user in users:
        user_dir = os.path.join(home_dir, user)
        # Call the function to search for password files in the user directory
        password_files = find_password_files(user_dir)
        if password_files:
            print(f'Found password file(s) for user {user}:')
            for file_path in password_files:
                print(file_path)
                append_to_file(f"The file that contains passwords for {user} is: {file_path}", "_passwordFiles")
            print()
        else:
            print(f'No obvious password files found in {user} home directory.\n')
            append_to_file(f'No obvious password files found in {user} home directory.\n', "_passwordFiles")




# function that checks the passwords of all users and compares their hashes ton a wordlist using john the ripper
def pass_checker():
    # Checks to see if johntheripper is installed
    p1 = subprocess.Popen(["dpkg", "--list"], stdout=subprocess.PIPE)
    p2 = subprocess.run(['grep', 'john'], stdin=p1.stdout, capture_output=True)
    op2 = str(p2.stdout)

    # prompts user to install when not installed
    while "john" not in op2:
        i = input(
            "This scan utilizes the third party software johntheripper. This is not currently detected on your device. Would you like to install? (y/n): ")
        i = i.lower()
        while i not in ["y", "n"]:
            i = input("Invalid input. Would you like to install? (y/n): ")
        if i == "y":
            os.system("sudo apt install john")
        elif i == "n":
            print("Scan requires johntheripper. Returning to main menu...")
            time.sleep(2)
    # default shadow & passwd locations
    locshad = "/etc/shadow"
    locpwd = "/etc/passwd"

    # if shadow isn't in default, prompts user for file
    while not os.path.isfile(locshad):
        locshad = input("Default shadow file not found in /etc/. Please provide path to shadow file: ")
        # checks to see if file exists-will not detect if its not a shadow style file

    # verify passwd file is in default loc
    while not os.path.isfile(locpwd):
        locpwd = input("Default passwd file not found in /etc/. Please provide path to shadow file: ")

    # strings together and runs the unshadow command with the passwd and shadow locations
    unshcom = str(f"sudo unshadow {locpwd} {locshad} > unshad.txt")
    os.system(unshcom)

    # requests a wordlist
    loc = input("Johntheripper requires a wordlist file of common passwords. Please provide file (text file, one password per line: ")
    # error checks wordlist location input
    while not os.path.isfile(loc):
        loc = input("File not found. Please enter a valid file, or q to return to menu: ")
        if loc == "q":
            main()

    # strings together the wordlist portion of the john command
    com = str(f"--wordlist={loc}")

    # runs full john cracking command to crack any not-already-cracked passwords
    subprocess.run(["sudo", "john", com, "unshad.txt"], capture_output=True)

    # runs the john --show command to retrieve all cracked users with cracked passwords
    p1 = subprocess.run(["sudo", "john", "--show", "unshad.txt"], capture_output=True, text=True)

    # splits each line from command to an ordered list
    p1 = p1.stdout.splitlines()
    # first characters of last line of the command output describes number of cracked passwords
    nump = re.search("\d+", p1[-1])
    nump = nump.group(0)
    nump = int(nump)

    # if there are 0 cracked passwords, reports it. Otherwise, prints usernames of cracked passwords
    if nump == 0:
        print("No weak passwords found. Returning to main menu.\n")
        menu()
    else:
        print(f"{nump} weak password(s) found. The following users have weak passwords: ")
        i = 0
        for i in range(nump):
            line = p1[i].split(":")
            print(line[0])


# function that lists all existing users
def list_all_users():
    userlines=[]
    lusers=[]
    print("Existing Users: ")
    # greps passwd file for users with active logins
    locpwd="/etc/passwd"
    while not os.path.isfile(locpwd):
        locpwd=input("This module utilizes the passwd file. It was not found in the /etc/ directory. Please provide path to system passwd file: ")
    with open(locpwd) as f:
        for line in f.readlines():
            nonuser=re.search("false|nologin|sync",line)
            if not nonuser:
                userlines.append(line)
    for l in userlines:
        user=l.split(":")
        lusers.append(user[0])
    # sends results to file
    append_to_file(f"The existing users are: {lusers}", "_allUsers")
    # prints output to terminal
    for i in lusers:
        print(i)


# function that executes all scans
def run_all_opts():
    portscan()
    aptupd()
    list_sudo_users()
    list_all_users()
    permissions_check()
    file_name_password()
    pass_checker()


# Menu function
def menu():
    options = {
        "1": portscan,
        "2": aptupd,
        "3": list_sudo_users,
        "4": list_all_users,
        "5": permissions_check,
        "6": file_name_password,
        "7": pass_checker,
        "q": exit_program
    }
    print("\nWelcome to the Basic Vulnerability Scanner by Var-I/O Brothers\n")
    print("Main Menu:")
    print("1. Run port(s) scan.")
    print("2. Check application for updates.")
    print("3. List all the users who are in sudo group.")
    print("4. List all the existing users.")
    print("5. Check permissions for /etc/shadow and .ssh directories for all users.")
    print("6. Check to see if there are any obvious password files in users home directory.")
    print("7. Check password strength of all users.")
    print("q. Exit")
    choice = input("Enter your choice (separated by commas for multiple choices): ")
    choices = choice.split(",")
    choices = errcheck(choices, options)
    for _ in choices:
        options[_]()

    confirm = input("Return to the main menu? (y/n): ")
    while confirm.lower() not in ['y', 'n']:
        print("Invalid choice. Please enter 'y' or 'n'.")
        confirm = input("Return to the main menu? (y/n): ")

    if confirm.lower() == 'n':
        exit_program()
    else:
        menu()


# Exit program function
def exit_program():
    print("Exiting...")
    # Cleanup code here before exiting
    exit()


# function that error checks the menu choices
def errcheck(choices, options):
    # ensures dictionary remains in memory if they're sent back
    options = options
    # error checker loops through user inputted choices
    for c in choices:
        if c not in options.keys():
            # if they're not in the dictionary, asks them to re input their choices
            choice = input(f"Invalid choice: {c}\nPlease try again (or type q to quit): ")

            choices = choice.split(",")
            #loops back to error check new inputs
            errcheck(choices, options)
    # once their choices are all viable options, sends the proper lists of choices back to main
    return (choices)

def main():
    menu()

if __name__ == '__main__':
    main()
