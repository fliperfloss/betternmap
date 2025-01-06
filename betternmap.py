import signal
import sys
import platform
import subprocess
import threading
from colorama import Fore, init
import time
import os
import re

# Initialize colorama
init(autoreset=True)

# Global flag for exit condition
exit_program = False
scanning_in_progress = False

# Function to handle Ctrl+C gracefully
def signal_handler(sig, frame):
    global exit_program, scanning_in_progress
    if scanning_in_progress:
        print("\nScan aborted. Returning to the main menu...")
        exit_program = False  # Allow return to main menu
    else:
        print("\nScan is not in progress.")

# Register the signal handler
signal.signal(signal.SIGINT, signal_handler)

# Function to clear the screen (teleportation effect)
def clear_screen():
    if platform.system() == "Windows":
        os.system("cls")
    else:
        os.system("clear")

# ASCII loading screen with faster effect and blue/white color scheme
def fast_loading_screen():
    clear_screen()
    loading_text = '''
                                       
        __              __   _                ____                               __      
  _____/ /_  ___  _____/ /__(_)___  ____ _   / __/___  _____   ____  ____  _____/ /______
 / ___/ __ \/ _ \/ ___/ //_/ / __ \/ __ `/  / /_/ __ \/ ___/  / __ \/ __ \/ ___/ __/ ___/
/ /__/ / / /  __/ /__/ ,< / / / / / /_/ /  / __/ /_/ / /     / /_/ / /_/ / /  / /_(__  ) 
\___/_/ /_/\___/\___/_/|_/_/_/ /_/\__, /  /_/  \____/_/     / .___/\____/_/   \__/____/  
                                 /____/                    /_/                              
                                              
                 '''
    # Fast printing of each line with a very short delay and alternating colors
    for i, line in enumerate(loading_text.splitlines()):
        if i % 2 == 0:
            print(Fore.BLUE + line)  # Blue for even lines
        else:
            print(Fore.WHITE + line)  # White for odd lines
        time.sleep(0.1)  # Short delay (0.1 seconds per line)
    print(Fore.BLUE + """Running Scan...
                        Connection Completed Waiting For Results...
          """)

# Function to show the main menu logo with blue and white mix
def show_main_menu_logo():
    logo_text = r'''
    __         __  __                                 
   / /_  ___  / /_/ /____  _________ ___  ____ _____ 
  / __ \/ _ \/ __/ __/ _ \/ ___/ __ `__ \/ __ `/ __ \
 / /_/ /  __/ /_/ /_/  __/ /  / / / / / / /_/ / /_/ / 
/_.___/\___/\__/\__/\___/_/  /_/ /_/ /_/\__,_/ .___/ 
                                            /_/           '''
    clear_screen()
    for i, line in enumerate(logo_text.splitlines()):
        if i % 2 == 0:
            print(Fore.BLUE + line)  # Blue for even lines
        else:
            print(Fore.WHITE + line)  # White for odd lines
        time.sleep(0.1)  # Medium delay (0.3 seconds per line)

# Function to run a scan with a given command
def run_scan(command, ip=None):
    global exit_program, scanning_in_progress
    scanning_in_progress = True
    try:
        # Display the fast loading screen
        fast_loading_screen()

        # Check if the command is not empty or None
        if command:
            print(Fore.BLUE + f"Running command: {command}")

            # Run the scan in a subprocess
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if stderr:
                print(Fore.RED + "Error during scan:", stderr.decode())
            else:
                output = stdout.decode()
                print(Fore.BLUE + "Scan Completed Successfully.")
                print(output)

                # Ask the user if they want to save the results
                save_results = input(Fore.BLUE + "Would you like to save the results of the scan and the IP? (yes/no): ").strip().lower()

                if save_results == "yes":
                    file_name = input(Fore.BLUE + "Enter a file name to save results (e.g., results.txt): ").strip()
                    with open(file_name, "a") as file:
                        file.write(f"IP: {ip}\n{output}\n\n")
                    print(Fore.BLUE + f"Results saved to '{file_name}'.")
                elif save_results == "no":
                    print(Fore.BLUE + "Returning to the main menu...")
                else:
                    print(Fore.RED + "Invalid choice, returning to the main menu.")

                # Add a prompt to ensure the user sees the output
                input(Fore.BLUE + "\nPress Enter to return to the main menu...")

        else:
            print(Fore.RED + "Error: Invalid command!")

    except subprocess.CalledProcessError as e:
        print(f"Error running scan: {e}")
    finally:
        scanning_in_progress = False
        # Clear the screen after the scan if user presses Enter
        clear_screen()

# Function to handle IP address input with exit option
def get_ip_address():
    ip = ""
    while True:
        ip = input("\nEnter IP address to scan (or press 'q' to cancel): ").strip()
        if ip.lower() == 'q':
            print("\nExiting IP input...")
            break
        if ip:
            return ip

# Function for automatic scan with default command
def automatic_scan():
    ip = get_ip_address()
    if ip:
        # Simplified scan command to only include the --script vuln option
        full_command = f"nmap --script vuln -n -sS {ip}"
        run_scan(full_command, ip)

# Function for automatic scan with DNS resolution disabled
def automatic_scan_no_dns():
    ip = get_ip_address()
    if ip:
        full_command = f"nmap -n -T4 {ip}"
        run_scan(full_command, ip)

# Function for automatic stealth scan
def automatic_stealth_scan():
    ip = get_ip_address()
    if ip:
        full_command = f"nmap -sS -D RND:10 -T4 {ip}"
        run_scan(full_command, ip)

# Function to scan multiple IP addresses (up to 240) with automatic CIDR 0/24 option
def scan_ip_0_24():
    clear_screen()
    ips = input("\nEnter up to 240 IP addresses in CIDR format (e.g., 192.168.1.0/24): ").split()
    if len(ips) > 240:
        print("You can only scan up to 240 IP addresses at once.")
        return
    
    # Update the command to scan in CIDR format 0/24
    for ip in ips:
        print(Fore.BLUE + f"Running {ip} with 0/24...")
        full_command = f"nmap -T4 -sS -sU --script vuln -n {ip}/24"
        run_scan(full_command, ip)

# Function to show all Nmap commands
def show_all_nmap_commands():
    clear_screen()
    commands = [
        "All Nmap Commands:",
        "nmap 192.168.1.1              Scan a single IP",
        "nmap 192.168.1.1-254          Scan a range",
        "nmap -iL targets.txt          Scan targets from a file",
        "nmap -sS 192.168.1.1          TCP SYN scan",
        "nmap -sT 192.168.1.1          TCP Connect scan",
        "nmap -O 192.168.1.1           OS detection",
        "nmap -sU 192.168.1.1          UDP scan",
        "nmap -p 80 192.168.1.1        Scan port 80",
        "nmap -p 1-1000 192.168.1.1    Scan ports 1-1000",
        "nmap -sV 192.168.1.1          Version detection",
        "nmap -A 192.168.1.1           OS detection, version detection, script scanning, traceroute",
        "nmap -Pn 192.168.1.1          Disable ping scan"
    ]
    show_submenu(commands)

# Function to show OS scan commands
def show_os_scan_commands():
    clear_screen()
    commands = [
        "OS Scan Commands:",
        "nmap -O 192.168.1.1           Enable OS detection",
        "nmap -A 192.168.1.1           Aggressive scan with OS detection",
        "nmap --osscan-guess           Guess the OS if exact match is not found"
    ]
    show_submenu(commands)

# Function to show NSE script commands
def show_nse_script_commands():
    clear_screen()
    commands = [
        "NSE Script Commands:",
        "nmap --script=vuln 192.168.1.1  Run vulnerability scripts",
        "nmap --script=http-enum 192.168.1.1  Enumerate web services",
        "nmap --script=default 192.168.1.1  Run default scripts"
    ]
    show_submenu(commands)

# Function to show firewall scan commands
def show_firewall_scan_commands():
    clear_screen()
    commands = [
        "Firewall Scan Commands:",
        "nmap -Pn 192.168.1.1           Scan without ping",
        "nmap -f 192.168.1.1            Fragment packets",
        "nmap --mtu 24 192.168.1.1      Specify custom MTU"
    ]
    show_submenu(commands)

# Function to show the submenu with command options
def show_submenu(commands):
    print("\n".join(commands))
    input(Fore.BLUE + "\nPress Enter to return to the main menu...")

# Function to handle manual Nmap scan (option 1)
def normal_nmap_scan():
    ip = get_ip_address()
    if ip:
        command = input(Fore.BLUE + "Enter your Nmap command (omit the IP if already included): ").strip()
        # Check if the IP is already part of the command
        if ip in command:
            full_command = command  # Use the command as-is
        else:
            full_command = f"nmap {command} {ip}"  # Append the IP if not included
        run_scan(full_command, ip)

# Exiting loading screen with blue and white color scheme
def exiting_loading_screen():
    clear_screen()
    loading_text = '''
    __                                             
   / /_  __  _____     ____  __  ______________  __
  / __ \/ / / / _ \   / __ \/ / / / ___/ ___/ / / / 
 / /_/ / /_/ /  __/  / /_/ / /_/ (__  |__  ) /_/ /  
/_.___/\__, /\___/  / .___/\__,_/____/____/\__, / 
      /____/       /_/                    /____/ '''
    # Fast printing of each line with a short delay and alternating colors
    for i, line in enumerate(loading_text.splitlines()):
        if i % 2 == 0:
            print(Fore.BLUE + line)  # Blue for even lines
        else:
            print(Fore.WHITE + line)  # White for odd lines
        time.sleep(0.1)  # Short delay (0.1 seconds per line)
    
    # Display a final "Exiting..." message with a blue background and white text
    print(Fore.BLUE + Fore.WHITE + "aint go no bitches...\n")
    time.sleep(1)  # Wait for a second before program exit
    print("just joking")  # Final message
    sys.exit()  # Exit the program

# Function to run SSLScan on a given IP with command selection
def sslscan_scan():
    global scanning_in_progress
    ip = get_ip_address()
    if ip:
        scanning_in_progress = True
        try:
            print(Fore.BLUE + "\nChoose an SSLScan command:")
            print("1. Basic SSL Scan")
            print("2. Full SSL Scan")
            print("3. SSL Certificate Details")
            print("4. Manual SSLScan")
            choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

            # Define the SSLScan command based on the user's choice
            if choice == '1':
                command = f"sslscan {ip}"
            elif choice == '2':
                command = f"sslscan --full {ip}"
            elif choice == '3':
                command = f"sslscan --cert {ip}"
            elif choice == '4':
                command = input(Fore.BLUE + "Enter your SSLScan command: ").strip()
            else:
                print(Fore.RED + "Invalid choice. Exiting SSLScan.")
                return

            # Run the selected SSLScan command
            print(Fore.BLUE + f"Running {command}...")
            process = subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            stdout, stderr = process.communicate()

            if stderr:
                print(Fore.RED + "Error during SSLScan:", stderr.decode())
            else:
                output = stdout.decode()
                print(Fore.BLUE + "SSLScan Completed Successfully.")
                print(output)
                # Save SSL scan results to a file
                file_name = input(Fore.BLUE + "Enter file name to save the results: ").strip()
                with open(file_name, "a") as file:
                    file.write(f"IP: {ip}\n{output}\n\n")
                print(Fore.BLUE + f"Results saved to '{file_name}'.")

        except Exception as e:
            print(Fore.RED + f"Error running SSLScan: {e}")
        finally:
            scanning_in_progress = False
            clear_screen()

# Main Menu Loop
def main_menu():
    global exit_program
    while not exit_program:
        show_main_menu_logo()
        print(Fore.BLUE +        "V 0.2 biskit@ ")
        print("1. Start Nmap Scan")
        print("2. Start SSLScan")
        print("3. Show All Nmap Commands")
        print("4. Show OS Scan Commands")
        print("5. Show NSE Script Commands")
        print("6. Show Firewall Scan Commands")
        print("7. Exit")
        
        print(Fore.WHITE +"Ctrl+C To Exit Scans" )
        choice = input(Fore.BLUE + "\nEnter your choice: ").strip()

        if choice == '1':
            normal_nmap_scan()
        elif choice == '2':
            sslscan_scan()
        elif choice == '3':
            show_all_nmap_commands()
        elif choice == '4':
            show_os_scan_commands()
        elif choice == '5':
            show_nse_script_commands()
        elif choice == '6':
            show_firewall_scan_commands()
        elif choice == '7':
            print(Fore.BLUE + "Exiting the program...")
            exiting_loading_screen()
        else:
            print(Fore.RED + "Invalid choice, please try again.")

if __name__ == "__main__":
    main_menu()
