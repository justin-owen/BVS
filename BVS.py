
import socket
import os
import subprocess
import time
import datetime
from datetime import date
from datetime import datetime


def append_to_file(content, scan):
    today = date.today()
    os.makedirs("BVS_logs", exist_ok=True)
    f = open(f"BVS_logs/{today}{scan}.txt", "a")
    f.write(f"{content}")
    f.close()

def portscan():
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
        while True:
            port = input(prompt)
            try:
                port = int(port)
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
            choice = input(prompt)
            if choice in valid_choices:
                return choice
            else:
                print("Invalid choice. Please enter 1, 2, or 3.")

    # Function to scan a single port on a host
    def scan_single_port(host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0

    # Function to scan multiple ports on a host
    def scan_multiple_ports(host, ports):
        open_ports = []
        for port in ports:
            if scan_single_port(host, port):
                open_ports.append(port)
        return open_ports

    # Function to scan a range of ports on a host
    def scan_range_ports(host, start_port, end_port):
        open_ports = scan_multiple_ports(host, range(start_port, end_port + 1))
        return open_ports

    print("This will scan for open ports.")

    # Get the host (IP address) from the user
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

    resp = input("Enter 'y' to do a more detailed scan, 'q' to quit or 'x' to return to main menu: ")
    while not (resp in ["q","x","y"]):
        resp=input("Invalid input, please try again: ")
    if resp == "q":
        exit()
    elif resp == "x":
        main()
    elif resp == "y":
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


def aptupd():
    # print("You chose apt update and it worked. yay")
    print("This will check for out of date software packages:\n")
    print("Updating update list: ")
    os.system("sudo apt update")
    print("Upgradeable apps: ")
    os.system("apt list --upgradeable")
    append_to_file(os.system("apt list --upgradeable"), "_updatesAvail")

def list_sudo_users():
    # !/usr/bin/python3
    #print("Users with Sudo permissions: ")
    #first bash command to read group file
    p1 = subprocess.Popen(["cat", "/etc/group"], stdout=subprocess.PIPE)
    #finds sudo group
    p2 = subprocess.run(['grep', "^sudo"], stdin=p1.stdout, capture_output=True)
    #ensures weird subprocess output is a workable string, this may not be necessary
    s1 = str(p2.stdout)
    #divides string into a nice list so we can get rid of unneeded text
    l1 = s1.split(":")
    #pulls out the user list
    sdusers = (l1[-1])
    #changes single line list into a column list
    userclean = sdusers.replace(",", "\n")
    #cleans up a stray \n' that was at the end of the list, left over from the original file formatting
    userclean = userclean.replace("\\n\'", "")
    ctime=datetime.now()
    userclean = str(f"The following users currently have Sudo Permissions as of {ctime}: \n{userclean}\n")
    #prints list
    print(userclean)
    append_to_file(userclean, "_sudoUsers")

def permissions_check():
    def get_permissions(file_path):
        try:
            ls_output = subprocess.run(['ls', '-ld', file_path], capture_output=True, text=True)
            permissions = ls_output.stdout.split()[0]
            return permissions
        except subprocess.CalledProcessError:
            return None

    def main():
        etc_shadow_permissions = get_permissions('/etc/shadow')
        print(f'Permissions for /etc/shadow: {etc_shadow_permissions}')

        home_dir = '/home'
        users = subprocess.run(['ls', '-1', home_dir], capture_output=True, text=True).stdout.splitlines()
        for user in users:
            ssh_dir = f'{home_dir}/{user}/.ssh'
            if subprocess.run(['test', '-d', ssh_dir]).returncode == 0:
                ssh_permissions = get_permissions(ssh_dir)
                print(f'Permissions for {ssh_dir} (User: {user}): {ssh_permissions}')
                append_to_file(f'Permissions for {ssh_dir} (User: {user}): {ssh_permissions}', "_permissions")
            else:
                print(f'User {user} has no .ssh folder')

    if __name__ == '__main__':
        main()


def file_name_password():
    def find_password_files(root_dir):
        password_files = []
        ls_output = subprocess.run(['find', root_dir, '-type', 'f', '-iname', 'password'], capture_output=True,
                                   text=True)
        file_paths = ls_output.stdout.splitlines()
        for file_path in file_paths:
            password_files.append(file_path)
        append_to_file(f"The files that contain passwords are: {password_files}", "_passwordFiles")
        return password_files

    def main():
        home_dir = '/home'
        users = subprocess.run(['ls', '-1', home_dir], capture_output=True, text=True).stdout.splitlines()
        for user in users:
            user_dir = os.path.join(home_dir, user)
            password_files = find_password_files(user_dir)
            if password_files:
                print(f'Found password file(s) for user {user}:')
                for file_path in password_files:
                    print(file_path)
                    append_to_file(f"The file that contains passwords for {user} is: {file_path}", "_passwordFiles")
                print()
            else:
                print(f'No obvious password files found in {user} home directory.')
                append_to_file(f'No obvious password files found in {user} home directory.', "_passwordFiles")

    if __name__ == '__main__':
        main()

def main():
    if os.getuid() != 0:
        print("You must run this as a user with sudo permissions")
        exit(1)
    print(
        "Welcome to the Basic Vulnerability Scanner!\nTo begin the scan choose from the following options by entering the numbers associated:\n"
        "1: Port scan\n2: Out of date software scan\n3: List all users with Sudo permissions\n4: List all existing users\n5: Check Permissions of /etc/shadow files and permissions of .ssh folders\n"
        "6: Look for obvious file named password\n7: all scans\n")
    while True:
        menu = input("Input: ")

        lmenu = menu.split(",")
        for i in lmenu:

            try:
                int(i)
            except:
                print("Please enter a valid number.")

        if "1" in lmenu:
            portscan()
            rorq()

        elif "2" in lmenu:
            aptupd()
            rorq()
        elif "3" in lmenu:
            list_sudo_users()
            rorq()
        elif "4" in lmenu:
            list_all_users()
            rorq()
        elif "5" in lmenu:
            permissions_check()
            rorq()
        elif "6" in lmenu:
            file_name_password()
            rorq()
        elif "7" in lmenu:
            portscan()
            aptupd()
            list_sudo_users()
            list_all_users()
            permissions_check()
            file_name_password()
            rorq()
        else:
            print("Please enter a valid number")

def list_all_users():
    print("Existing Users: ")
    p2 = subprocess.Popen(["grep", "-v", "false\|nologin\|sync", "/etc/passwd"], stdout=subprocess.PIPE)
    p3 = subprocess.run(['cut', "-d:", "-f1"], stdin=p2.stdout, capture_output=True)
    s1 = str(p3.stdout)
    output = s1.split("\\n")
    output[0] = output[0].strip("b\'")
    append_to_file(f"The existing users are: {output}")
    for i in output:
        if output[0]:
            string = i.strip("b\'")
            print(string)
        else:
            print(i)

main()

# Exit program function
def exit_program():
    print("Exiting...")
    # Add any cleanup code or additional functionality before exiting
    exit()

def errcheck(choices,options):
    options=options
    for c in choices:
        if c not in options.keys():
            choice = input(f"Invalid choice: {c}\nPlease try again (or type q to quit): ")
            choices = choice.split(",")
            errcheck(choices,options)
    return(choices)



def main():
    menu()
main()