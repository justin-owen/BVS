# This is a sample Python script.

# Press Shift+F10 to execute it or replace it with your code.
# Press Double Shift to search everywhere for classes, files, tool windows, actions, and settings.
import socket
import os


def portscan():
    def scan_single_port(host, port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(1)
            return s.connect_ex((host, port)) == 0

    def scan_multiple_ports(host, ports):
        open_ports = []
        for port in ports:
            if scan_single_port(host, port):
                open_ports.append(port)
        return open_ports

    def scan_range_ports(host, start_port, end_port):
        open_ports = scan_multiple_ports(host, range(start_port, end_port + 1))
        return open_ports

    if __name__ == '__main__':
        print("This will scan for open ports.")
        host = input('Enter the host to scan: ')

        # Get the user's choice of how many ports to scan.
        choice = input('Do you want to scan (1) a single port, (2) multiple ports, or (3) a range of ports? ')

        if choice == '1':
            # Get the port number to scan.
            port = int(input('Enter the port number to scan: '))

            if scan_single_port(host, port):
                print(f'Port {port} is open')
            else:
                print(f'Port {port} is closed')

        elif choice == '2':
            # Get a list of ports to scan.
            ports = []
            while True:
                port = input('Enter a port number to scan (r to run): ')
                if port == "r":
                    break
                else:
                    ports.append(int(port))

            open_ports = scan_multiple_ports(host, ports)

            if open_ports:
                print(f'Open ports: {open_ports}')
            else:
                print('No open ports found.')

        elif choice == '3':
            # Get the start and end ports to scan.
            start_port = int(input('Enter the start port: '))
            end_port = int(input('Enter the end port: '))

            open_ports = scan_range_ports(host, start_port, end_port)

            if open_ports:
                print(f'Open ports: {open_ports}')
            else:
                print('No open ports found.')

        else:
            print('Invalid choice.')


def aptupd():
    # print("You chose apt update and it worked. yay")
    print("This will check for out of date software packages:\n")
    print("Updating update list: ")
    os.system("sudo apt update")
    print("Upgradeable apps: ")
    os.system("apt list --upgradeable")


def main():
    print(
        "Welcome to the Basic Vulnerability Scanner!\nTo begin the scan choose from the following options by entering the numbers associated:\n"
        "1: Port scan\n2: Out of date software scan\n3: all scans\n")
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
            break
        elif "2" in lmenu:
            aptupd()
            break
        elif "3" in lmenu:
            portscan()
            aptupd()
            break
        else:
            print("Please enter a valid number")


main()
