import os
import platform
import re #This imports the regular expression module, which allows working with regular expressions in Python.
import requests #This imports the requests module, which is commonly used to send HTTP requests in Python.
from bs4 import BeautifulSoup #This imports the BeautifulSoup class from the bs4 module, which is used for web scraping and parsing HTML.
import subprocess #This imports the subprocess module, which allows running external processes from within Python.
import dns.resolver  # Library for DNS record lookup
#This is github testing
from termcolor import colored
import getpass # Import the getpass module to hide user input
import sys 


# Function to check if a command-line tool is available
def check_tool_availability(tool_name):
    try:
        subprocess.run([tool_name, "--version"], capture_output=True, text=True)
        return True
    except FileNotFoundError:
        return False

# Function to check if required Python modules are available
def check_python_module(module_name):
    try:
        __import__(module_name)
        return True
    except ImportError:
        return False



nmap_command = "nmap" # This assigns the string "nmap" to the variable
session_logged_in = False  # Flag to track if a user is already logged in

# Dictionary to keep track of login attempts and lockout status
login_attempts = {}
security_questions = {"admin1": "What is your nickname?",
                      "admin2": "What is your pet's name?",
                      "super_admin": "What is your school's name?"}


# After the dictionary definition, you can add the correct answers
security_answers = {"admin1": "Joe",  # Replace "blue" with the actual answer
                    "admin2": "Fluffy",
                    "super_admin": "Gateway"}  # Replace "Fluffy" with the actual answer                      




def fetch_domain_info(domain):
    url = f"https://www.whois.com/whois/{domain}"
    alternative_whois_url = f"https://api.domaintools.com/whois/{domain}"  # Example alternative


    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        pre_tag = soup.find("pre")

        if pre_tag:
            registrar_info = pre_tag.text.strip()
            #formatted_info = format_whois_info(registrar_info)
            return registrar_info
        else:
            return None



# Function to display help from the text file
def display_help():
    try:
        with open("/home/isindu/Desktop/CMV2/help_guide.txt", "r") as file:
            help_text = file.read()
            print(colored(help_text, "yellow"))
    except FileNotFoundError:
        print(colored("Help guide file not found!", "red"))


#def lookup_dns_records(domain):
 # records = {}
  #resolver = dns.resolver.Resolver()

  #try:
   # # Use resolve instead of deprecated query
    #mx_records = resolver.resolve(domain, 'MX')
    #mx_data = [f"{record.exchange.text} ({record.priority})" for record in mx_records]
    #records['MX'] = mx_data

    # Uncomment and implement code to get additional records as needed:
    # ns_records = resolver.query(domain, 'NS')
    # records['NS'] = [record.text for record in ns_records]
    # a_records = resolver.query(domain, 'A')
    # records['A'] = [record.address for record in a_records]

  #except dns.resolver.NXDOMAIN:
   # print(f"Domain {domain} not found in DNS.")
  #except dns.resolver.Timeout:
   # print(f"DNS lookup timed out for {domain}.")
  #except Exception as e:
   # print(f"Error during DNS lookup: {e}")

  #return records

def save_to_file(output, filename=None):

    if not filename:
        filename=input("Enter the filename to save the output: ")
    try:
        with open(filename, "w") as file:
            file.write(str(output))  # Convert scan_output to a string before writing

        full_path = os.path.abspath(filename)
        print(colored(f"Output saved to: {full_path}","blue"))  # Print the full path where the file is saved
    except Exception as e:
        print(colored(f"Error saving output to file: {e}","red"))
    
def choose_user():
    while True:
        print(colored("\nWho are you?","yellow"))
        print("1- admin1")
        print("2- admin2")
        print("3- super_admin")
        choice = input("\nChoose an option (1/2/3): ")
        if choice == '1':
            return "admin1"
        elif choice == '2':
            return "admin2"
        elif choice == '3':
            return "super_admin"
        else:
            print(colored("Invalid choice!❌ Please enter 1, 2, or 3.", "red"))


def authenticate_user():
    global session_logged_in, user_role  # Add user_role to global variables

    if session_logged_in:
        if user_role == "admin":
            print(colored("You are already logged in. ✅", "green"))
            return "admin"
        elif user_role == "super_admin":
            print(colored("You are already logged in. ✅", "green"))
            return "super_admin"
    
    username = choose_user()

    max_attempts = 3

    for _ in range(max_attempts):
        

        if username not in login_attempts:
            login_attempts[username] = 0

        if login_attempts[username] >= max_attempts:
            print(colored("Your account is locked.🔒 Please answer the security question to unlock.", "red"))
            answer = input(colored(f"\nSecurity Question: {security_questions.get(username, '')}\nYour answer: ", "yellow"))
            if answer.lower() == security_answers.get(username, '').lower():
                print(colored("Account unlocked! You may try logging in again. ✅", "green"))
                login_attempts[username] = 0  # Reset login attempts
                continue
            else:
                print(colored("Incorrect answer!❌ Please contact the IT Department.", "red"))
                main()  # Return to the main menu
                return None

        password = getpass.getpass(f"\nEnter your password for {username}: ")

        if username == "admin1" and password == "password1":
            session_logged_in = True
            user_role = "admin"  # Update user_role
            return "admin"  # Return admin role
        elif username == "admin2" and password == "password2":
            session_logged_in = True
            user_role = "admin"  # Update user_role
            return "admin"  # Return admin role
        elif username == "super_admin" and password == "super_password":
            session_logged_in = True
            user_role = "super_admin"  # Update user_role
            return "super_admin"  # Return super admin role
        else:
            print(colored("Invalid credentials!❌  Please try again.", "red"))
            login_attempts[username] += 1

    print("\nExceeded maximum attempts!!!🚨 Account locked.")
    login_attempts[username] = max_attempts  # Lock the account indefinitely
    main()  # Return to the main menu


def parse_vulnerabilities(scan_results):
    vulnerability_list = re.findall(r"([A-Z0-9]+-\d+-\d+)\s+(\d\.\d)\b", scan_results)
    return vulnerability_list

def categorize_vulnerabilities(vulnerability_list, severity_level):
    categorized_vulnerabilities = []
    for vulnerability in vulnerability_list:
        base_score = float(vulnerability[1])
        if severity_level == "critical" and base_score >= 9.0:
            categorized_vulnerabilities.append(("CRITICAL", vulnerability[0]))
        elif severity_level == "high" and 7.0 <= base_score < 9.0:
            categorized_vulnerabilities.append(("HIGH", vulnerability[0]))
        elif severity_level == "medium" and 4.0 <= base_score < 7.0:
            categorized_vulnerabilities.append(("MEDIUM", vulnerability[0]))
        elif severity_level == "low" and 0.0 <= base_score < 4.0:
            categorized_vulnerabilities.append(("LOW", vulnerability[0]))
    return categorized_vulnerabilities   


scan_results = None  # Define a global variable to store scan results

def nmap_scan(target):
    global scan_results  # Access the global variable

    if nmap_command:
        print(colored("The scanning might take a few minutes to complete...", "magenta"))

        scan_results = subprocess.run([nmap_command, "-sV", "--script=vuln", target], capture_output=True, text=True)
        print(colored("\nNmap Scan Results:", "yellow"))
        print(scan_results.stdout)

        while True:
            save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
            if save_option == 'yes':
                filename = input("Enter the filename to save the output: ")
                with open(filename, "w") as file:
                    file.write(scan_results.stdout)  # Save original scan results
                print(colored(f"Output saved to: {os.path.abspath(filename)}", "blue"))
                break
            elif save_option == 'no':
                break
            else:
                print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

        while True:
            mitigation_option = input("\nDo you want to view precautions? (yes/no): ").lower()
            if mitigation_option == 'yes':
                try:
                    with open("/home/isindu/Desktop/CMV2/precaution.txt", "r") as file:
                        precaution_text = file.read()
                        print(colored("\nPrecaution Information:", "yellow"))
                        print(precaution_text)
                except FileNotFoundError:
                    print(colored("Precaution file not found!", "red"))
                break
            elif mitigation_option == 'no':
                break
            else:
                print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))


        while True:
            severity_filter = input("\nDo you want to filter vulnerabilities by severity level? (yes/no): ").lower()

            if severity_filter == "yes":
                vulnerabilities = parse_vulnerabilities(scan_results.stdout)
                while True:
                    severity_level = input("\nEnter the severity level (critical/high/medium/low): ").lower()
                    if severity_level in ["critical", "high", "medium", "low"]:
                        categorized_vulnerabilities = categorize_vulnerabilities(vulnerabilities, severity_level)
                        if categorized_vulnerabilities:
                            print(f"\n{severity_level.capitalize()} Severity Vulnerabilities:")
                            for severity, vulnerability in categorized_vulnerabilities:
                                colored_severity = colored(severity, 'red' if severity == 'CRITICAL' else 'yellow' if severity == 'HIGH' else 'blue' if severity == 'MEDIUM' else 'green')
                                print(f"Severity: {colored_severity} - {vulnerability}")
                            
                            save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                            if save_option == 'yes':
                                filename = input("Enter the filename to save the output: ")
                                save_to_file(categorized_vulnerabilities, filename)
                        else:
                            print(colored(f"No {severity_level.capitalize()} severity vulnerabilities found.", "cyan"))
                        break
                    else:
                        print(colored("Invalid severity level!❌ Please enter 'critical', 'high', 'medium', or 'low'.", "red"))
            elif severity_filter == "no":
                break
            else:
                print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

        return_to_menu()



def return_to_menu():
    while True:
        choice = input("\nDo you want to return to the main menu? (yes/no): ").lower()
        if choice == 'yes':
            main()  # Return to the main menu
        elif choice == 'no':
            print(colored("Exiting program...","magenta"))
            exit(0)
        else:
            print(colored("Invalid choice!❌ Please enter 'yes' or 'no'.","red"))

def capture_login_request():
   
    print(colored("\nInstructions:", "yellow"))
    print("Step 1 - Open Burpsuite on the host machine")
    print("Step 2 - Start a temporaray Project")
    print("Step 3 - Select the proxy tab and start the web browser")
    print("Step 4 - Navigate to the Vulnweb login page")
    print("Step 5 - Turn On Intercept and enter any login data")
    print("Step 6 - After that click send to intruder")
    print("Step 7 - At that page select the payload and start the attack")

    print(colored("\nWould you like a video guide for this? You can find the link in the '7. Exploitation' section of the help documentation.","red"))


    # Send a sample login request to capture it with Burp Suite
    login_url = "http://testphp.vulnweb.com/login.php"
    login_data = {"uname": "test_user", "pass": "test_pass", "submit": "Login"}
    requests.post(login_url, data=login_data)

   

def crack_passwords():
    print(colored("Starting password cracking...","yellow"))
    subprocess.run(["hydra", "-L", "/home/isindu/Desktop/usernames.txt", "-P", "/home/isindu/Desktop/password1.txt", "testphp.vulnweb.com", "http-post-form", "/login.php:uname=^USER^&pass=^PASS^:F=you must login"])





def main():
    print(colored(r"""
        _____                _          __  __       _       
       / ____|              | |        |  \/  |     (_)      
      | |     _ __ __ _  ___| | _____  | \  / | __ _ _ _ __  
      | |    | '__/ _` |/ __| |/ / __| | |\/| |/ _` | | '_ \ 
      | |____| | | (_| | (__|   <\__ \ | |  | | (_| | | | | |
       \_____|_|  \__,_|\___|_|\_\___/ |_|  |_|\__,_|_|_| |_|

    ""","cyan"))

    global session_logged_in , user_role
    if not session_logged_in:
        print(colored("🚨 NOTE: YOU HAVE 3 ATTEMPTS TO ENTER THE CREDENTIALS 🚨", "red"))

   

    # Authenticating the user
    user_role = authenticate_user()

    if user_role == "super_admin":
        print(colored("You have logged in as a SUPER ADMIN. 🛡️", "green"))

        # Print the privileges grid

        print("\n" + "-" * 55)
        print("|{:<26}|{:<26}|".format("     Admin Privileges","  Super Admin Privileges"))
        print("-" * 55)
        print("|{:<35}|{:<35}|".format(colored(" Reconnaissance","yellow"), colored(" Reconnaissance","yellow")))
        print("|{:<35}|{:<35}|".format(colored(" Scanning and Enumeration","green"), colored(" Scanning and Enumeration","green")))
        print("|{:<35}|{:<35}|".format(colored(" Vulnerability Scanning","blue"), colored(" Vulnerability Scanning","blue")))
        print("|{:<26}|{:<35}|".format("", colored(" Exploitation","magenta")))
        print("-" * 55)
        print(colored("\n 🚨REMINDER: EXPLOITATION PHASE IS ONLY FOR THE SUPER ADMIN!🚨","red"))

        print(colored("\nMAIN OPTIONS:","cyan"))
        print("r - Reconnaissance")
        print("s - Scanning & Service Enumeration")
        print("v - Vulnerability Scanning")
        print("e - Exploitation")

        print(colored("\nOTHER OPTIONS:","cyan"))
        print("h - Help Documentation") 
        print("q - Quit Program")

        valid_options = ['r', 's', 'v', 'e', 'h', 'q']

        while True:
            selection = input("\nEnter an option: ").lower()
            if selection in valid_options:
                break  # End of the while loop
            else:
                print(colored("Invalid option.❌ Please enter a valid option.", "red"))

        if selection == 'r':
            domain = input("\nEnter the domain name: ")
            domain_info = fetch_domain_info(domain)

            if domain_info:
                print(colored("\nDomain Information:","yellow"))
                print(domain_info)

                  # Call DNS record lookup function
            #dns_records = lookup_dns_records(domain)
            #if dns_records:
             #   print("\nDNS Records:")
              #  for record_type, record_data in dns_records.items():
               #     print(f"{record_type}: {', '.join(record_data)}")  # Join list elements with comma
        
                while True:
                    save_option = input("\nDo you want to save the output to a file? (yes/no) : ").lower()
                    if save_option == 'yes' or save_option == 'no':
                        break
                    else:
                        print(colored("Wrong input!❌ Please specify 'yes' or 'no'.", "red"))


                if save_option =='yes':
                        save_to_file(domain_info) 
            else:
                print(colored("Failed to retrieve domain information!","red"))

            return_to_menu()  # Prompt user to return to main menu after completing the task


        

        elif selection == 's':

            attempts = 3

            while attempts > 0:
                print(colored("\nChoose an option:","blue"))
                print(colored("  1 - Port Scanning","magenta"))
                print(colored("  2 - Service Enumeration","magenta"))
                option = input("\nEnter the number corresponding to your choice: ")

            
                if option == '1':
                    target = input("\nEnter the IP address or domain name to scan: ")
                    try:
                        if nmap_command:
                            # Perform port scanning
                            print(colored("\nPerforming Port Scanning...","cyan"))
                            scan_results = subprocess.run([nmap_command, "-F", target], capture_output=True, text=True)
                            print(colored("\nPort Scan Results:","yellow"))
                            print(scan_results.stdout)

                        # Ask whether to save the output
                            while True:
                                save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                                if save_option == 'yes' or save_option == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if save_option == 'yes':
                                save_to_file(scan_results.stdout)    
                            

                         # Prompt user to scan again
                            while True:
                                scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
                                if scan_again == 'yes' or scan_again == 'no':
                                    break
                            else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if scan_again == 'no':
                                break  # Exit the loop if the user doesn't want to scan again
                            else:
                                continue  # Continue to the next iteration of the loop if the user wants to scan again


                    except Exception as e:
                        print("Error during port scan:", e)

                elif option == '2':
                    target = input("\nEnter the IP address or domain name to scan: ")
                    try:
                        if nmap_command:
                            # Perform enumeration
                            print(colored("\nPerforming Service Enumeration...","cyan"))
                            enumeration_results = subprocess.run([nmap_command,"-sV", target], capture_output=True, text=True)
                            print(colored("\nEnumeration Results:","yellow"))
                            print(enumeration_results.stdout)

                            
                    # Ask whether to save the output
                            while True:
                                save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                                if save_option == 'yes' or save_option == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if save_option == 'yes':
                                save_to_file(enumeration_results.stdout)          

                        # Prompt user to scan again
                            while True:
                                scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
                                if scan_again == 'yes' or scan_again == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if scan_again == 'no':
                                break  # Exit the loop if the user doesn't want to scan again
                            else:
                                continue  # Continue to the next iteration of the loop if the user wants to scan again

                    except Exception as e:
                        print("Error during service enumeration:", e)

                else:
                    print(colored("Invalid option!❌ Please enter 1 or 2.","red"))
                    attempts -= 1
                    if attempts == 0:
                        print(colored("\nExceeded maximum attempts!!!🚨 Exiting...","red"))
                        return
            return_to_menu()  # Prompt user to return to the main menu after completing the task



        elif selection == 'v':

            try:
                target = input("\nEnter the IP address or domain name to scan: ")
                nmap_scan(target)
            except Exception as e:
                print("Error during vulnerability scanning:", e)
            return_to_menu() 

        elif selection == 'e':
                print(colored("\nChoose an option for Exploitation:", "blue"))
                print(colored("  1 - Capture Login Requests using Burpsuite", "magenta"))
                print(colored("  2 - Crack Passwords using Hydra", "magenta"))

                attempts = 3
                while attempts > 0:
            
                    option = input("\nEnter the number corresponding to your choice: ")

                    if option == '1' or option == '2':
                        if option == '1':
                            capture_login_request()
                        elif option == '2':
                            crack_passwords()
                        break  # Exit the loop if a valid option is entered
                    else:
                        print(colored("Invalid option!❌ Please enter 1 or 2.", "red"))
                        attempts -= 1

                return_to_menu()


        elif selection == 'h':
            display_help()  # Call the function to display help text

            return_to_menu()
  

        elif selection == 'q':
            print(colored("Exiting program...","magenta"))
            exit(0)


        else:
            print(colored("Invalid option.❌","red")) 
 

    if user_role == "admin":
        print(colored("You have logged in as an ADMIN. 🛡️", "green"))

        # Print the privileges grid

        print("\n" + "-" * 55)
        print("|{:<26}|{:<26}|".format("     Admin Privileges","  Super Admin Privileges"))
        print("-" * 55)
        print("|{:<35}|{:<35}|".format(colored(" Reconnaissance","yellow"), colored(" Reconnaissance","yellow")))
        print("|{:<35}|{:<35}|".format(colored(" Scanning and Enumeration","green"), colored(" Scanning and Enumeration","green")))
        print("|{:<35}|{:<35}|".format(colored(" Vulnerability Scanning","blue"), colored(" Vulnerability Scanning","blue")))
        print("|{:<26}|{:<35}|".format("", colored(" Exploitation","magenta")))
        print("-" * 55)
        print(colored("\n 🚨REMINDER: EXPLOITATION PHASE IS ONLY FOR THE SUPER ADMIN!🚨","red"))

        print(colored("\nMAIN OPTIONS:","cyan"))
        print("r - Reconnaissance")
        print("s - Scanning & Service Enumeration")
        print("v - Vulnerability Scanning")


        print(colored("\nOTHER OPTIONS:","cyan"))
        print("h - Help Documentation") 
        print("q - Quit Program")

        valid_options = ['r', 's', 'v', 'h', 'q']

        while True:
            selection = input("\nEnter an option: ").lower()
            if selection in valid_options:
                break  # End of the while loop
            else:
                print(colored("Invalid option.❌ Please enter a valid option.", "red"))

        if selection == 'r':
            domain = input("\nEnter the domain name: ")
            domain_info = fetch_domain_info(domain)

            if domain_info:
                print(colored("\nDomain Information:","yellow"))
                print(domain_info)

                  # Call DNS record lookup function
            #dns_records = lookup_dns_records(domain)
            #if dns_records:
             #   print("\nDNS Records:")
              #  for record_type, record_data in dns_records.items():
               #     print(f"{record_type}: {', '.join(record_data)}")  # Join list elements with comma
        
                while True:
                    save_option = input("\nDo you want to save the output to a file? (yes/no) : ").lower()
                    if save_option == 'yes' or save_option == 'no':
                        break
                    else:
                        print(colored("Wrong input!❌ Please specify 'yes' or 'no'.", "red"))


                if save_option =='yes':
                        save_to_file(domain_info) 
            else:
                print(colored("Failed to retrieve domain information!","red"))

            return_to_menu()  # Prompt user to return to main menu after completing the task


        

        elif selection == 's':

            attempts = 3

            while attempts > 0:
                print(colored("\nChoose an option:","blue"))
                print(colored("  1 - Port Scanning","magenta"))
                print(colored("  2 - Service Enumeration","magenta"))
                option = input("\nEnter the number corresponding to your choice: ")

            
                if option == '1':
                    target = input("\nEnter the IP address or domain name to scan: ")
                    try:
                        if nmap_command:
                            # Perform port scanning
                            print(colored("\nPerforming Port Scanning...","cyan"))
                            scan_results = subprocess.run([nmap_command, "-F", target], capture_output=True, text=True)
                            print(colored("\nPort Scan Results:","yellow"))
                            print(scan_results.stdout)

                        # Ask whether to save the output
                            while True:
                                save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                                if save_option == 'yes' or save_option == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if save_option == 'yes':
                                save_to_file(scan_results.stdout)    
                            

                         # Prompt user to scan again
                            while True:
                                scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
                                if scan_again == 'yes' or scan_again == 'no':
                                    break
                            else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if scan_again == 'no':
                                break  # Exit the loop if the user doesn't want to scan again
                            else:
                                continue  # Continue to the next iteration of the loop if the user wants to scan again


                    except Exception as e:
                        print("Error during port scan:", e)

                elif option == '2':
                    target = input("\nEnter the IP address or domain name to scan: ")
                    try:
                        if nmap_command:
                            # Perform enumeration
                            print(colored("\nPerforming Service Enumeration...","cyan"))
                            enumeration_results = subprocess.run([nmap_command,"-sV", target], capture_output=True, text=True)
                            print(colored("\nEnumeration Results:","yellow"))
                            print(enumeration_results.stdout)

                            
                    # Ask whether to save the output
                            while True:
                                save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                                if save_option == 'yes' or save_option == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if save_option == 'yes':
                                save_to_file(enumeration_results.stdout)          

                        # Prompt user to scan again
                            while True:
                                scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
                                if scan_again == 'yes' or scan_again == 'no':
                                    break
                                else:
                                    print(colored("Wrong input!❌ Please enter 'yes' or 'no'.", "red"))

                            if scan_again == 'no':
                                break  # Exit the loop if the user doesn't want to scan again
                            else:
                                continue  # Continue to the next iteration of the loop if the user wants to scan again

                    except Exception as e:
                        print("Error during service enumeration:", e)

                else:
                    print(colored("Invalid option!❌ Please enter 1 or 2.","red"))
                    attempts -= 1
                    if attempts == 0:
                        print(colored("\nExceeded maximum attempts!!!🚨 Exiting...","red"))
                        return
            return_to_menu()  # Prompt user to return to the main menu after completing the task



        elif selection == 'v':

            try:
                target = input("\nEnter the IP address or domain name to scan: ")
                nmap_scan(target)
            except Exception as e:
                print("Error during vulnerability scanning:", e)
            return_to_menu() 



        elif selection == 'h':
            display_help()  # Call the function to display help text

            return_to_menu()
  

        elif selection == 'q':
            print(colored("Exiting program...","magenta"))
            exit(0)


        else:
            print(colored("Invalid option.❌","red")) 

     




if __name__ == "__main__":
    nmap_command = "nmap" if check_tool_availability("nmap") else None
    termcolor_installed = check_python_module("termcolor")

    if not nmap_command:
        print(colored("Error: nmap is not installed. Please install it to use this tool.", "red"))
        sys.exit(1)

    if not termcolor_installed:
        print("Error: termcolor module is not installed. Please install it using pip.")
        sys.exit(1)

    session_logged_in = False
    user_role = None
    main()



                                                                                    
