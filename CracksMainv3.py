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


nmap_command = "nmap" # This assigns the string "nmap" to the variable
nikto_command = "nikto" # This assigns the string "nikto" to the variable



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
    


def authenticate_user():
    admins = {"admin1": "password1", "admin2": "password2"}
    super_admin = {"super_admin": "super_password"}

    for _ in range(3):  # Allowing 3 attempts
        username = input("\nEnter your username: ")
        password = getpass.getpass("Enter your password: ")

        if username in admins and admins[username] == password:
            return "admin"  # Return admin role
        elif username in super_admin and super_admin[username] == password:
            return "super_admin"  # Return super admin role
        else:
            print(colored("Invalid credentials. Please try again.", "red"))

    print("\nExceeded maximum attempts. Exiting...")
    return None  # Return None if authentication fails   

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
            severity_filter = input("\nDo you want to filter vulnerabilities by severity level? (yes/no): ").lower()

            if severity_filter == "yes":
                vulnerabilities = parse_vulnerabilities(scan_results.stdout)
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
                        print(f"No {severity_level.capitalize()} severity vulnerabilities found.")
                else:
                    print("Invalid severity level.")

            else:
                break  # Exit the loop if the user doesn't want to filter further

            print(colored("\nExiting vulnerability scanning...","magenta"))




def nikto_scan(target):
    if nikto_command:

        print(colored("The scanning might take a few minutes to complete...", 'magenta'))

        scan_results = subprocess.run([nikto_command, "-h", target], capture_output=True, text=True)
        print(colored("\nNikto Scan Results:", "yellow"))
        print(scan_results.stdout)

        save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
        if save_option == 'yes':
            # Save Nikto scan results to a file
            with open("nikto_vulnerability_scan_output.txt", "w") as file:
                file.write(scan_results.stdout)
            print(colored("Nikto scan results saved to nikto_vulnerability_scan_output.txt","blue"))

def return_to_menu():
    while True:
        choice = input("\nDo you want to return to the main menu? (yes/no): ").lower()
        if choice == 'yes':
            main()  # Return to the main menu
        elif choice == 'no':
            print(colored("Exiting program...","magenta"))
            return
        else:
            print(colored("Invalid choice. Please enter 'yes' or 'no'.","red"))


def main():
    print(colored(r"""
        _____                _          __  __       _       
       / ____|              | |        |  \/  |     (_)      
      | |     _ __ __ _  ___| | _____  | \  / | __ _ _ _ __  
      | |    | '__/ _` |/ __| |/ / __| | |\/| |/ _` | | '_ \ 
      | |____| | | (_| | (__|   <\__ \ | |  | | (_| | | | | |
       \_____|_|  \__,_|\___|_|\_\___/ |_|  |_|\__,_|_|_| |_|

    ""","cyan"))

    print(colored("NOTE : YOU HAVE 3 ATTEMPTS TO ENTER THE CREDENTIALS", "red"))

    # Authenticating the user
    user_role = authenticate_user()

    if user_role == "super_admin":
        print(colored("You have logged in as a SUPER ADMIN.", "green"))
    elif user_role == "admin":
        print(colored("You have logged in as an ADMIN.", "green"))
    else:
        return  # Exit if authentication fails

    selection = input("\nSelect an option (r - Reconnaissance, p - Port Scan & Service Enumeration , v - Vulnerability Scan, q - Quit) : ").lower()

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
        
            save_option=input("\nDo you want to save the output to a file? (yes/no) : ").lower()
            if save_option =='yes':
                    save_to_file(domain_info) 
        else:
            print(colored("Failed to retrieve domain information.","red"))

        return_to_menu()  # Prompt user to return to main menu after completing the task


        

    elif selection == 'p':

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
                        save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                        if save_option == 'yes':
                            save_to_file(scan_results.stdout)
                            

                        # Prompt user to scan again
                        scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
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
                        save_option = input("\nDo you want to save the output to a file? (yes/no): ").lower()
                        if save_option == 'yes':
                            save_to_file(enumeration_results.stdout)
                            

                     # Prompt user to scan again
                        scan_again = input("\nDo you want to scan again? (yes/no): ").lower()
                        if scan_again == 'no':
                            break  # Exit the loop if the user doesn't want to scan again
                        else:
                            continue  # Continue to the next iteration of the loop if the user wants to scan again

                except Exception as e:
                    print("Error during port scan:", e)

            else:
                print(colored("Invalid option! Please enter 1 or 2.","red"))
                attempts -= 1
                if attempts == 0:
                    print(colored("\nExceeded maximum attempts!!! Exiting...","red"))
                    return
        return_to_menu()  # Prompt user to return to the main menu after completing the task



    elif selection == 'v':

        try:
            while True:
                tool_selection = input("\nChoose the scanning tool (Nmap/Nikto): ").lower()
                if tool_selection == "nmap":
                    target = input("\nEnter the IP address or domain name to scan: ")
                    nmap_scan(target)

                    save_option = input("Do you want to save the output to a file? (yes/no): ").lower()
                    if save_option == 'yes':
                        save_to_file(scan_results.stdout)

                    break
             
                elif tool_selection == "nikto":
                    target = input("\nEnter the IP address or domain name to scan: ")
                    nikto_scan(target)

                    break
                    
                else:
                    print(colored("Invalid tool selection. Please choose either 'Nmap' or 'Nikto'.","red"))

        except Exception as e:
            print("Error during vulnerability scanning:", e)
        return_to_menu()  # Prompt user to return to main menu after completing the task



    elif selection == 'q':
        print(colored("Exiting program...","magenta"))
        return


    

    else:
            print(colored("Invalid option.","red"))        




    


if __name__ == "__main__":
    main()


                                                                                    
