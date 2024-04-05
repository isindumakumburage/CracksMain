import re #This imports the regular expression module, which allows working with regular expressions in Python.
import requests #This imports the requests module, which is commonly used to send HTTP requests in Python.
from bs4 import BeautifulSoup #This imports the BeautifulSoup class from the bs4 module, which is used for web scraping and parsing HTML.
import subprocess #This imports the subprocess module, which allows running external processes from within Python.
import dns.resolver  # Library for DNS record lookup
#This is github testing

nmap_command = "nmap" # This assigns the string "nmap" to the variable


def fetch_domain_info(domain):
    url = f"https://www.whois.com/whois/{domain}"
    alternative_whois_url = f"https://api.domaintools.com/whois/{domain}"  # Example alternative


    response = requests.get(url)

    if response.status_code == 200:
        soup = BeautifulSoup(response.content, 'html.parser')
        pre_tag = soup.find("pre")

        if pre_tag:
            registrar_info = pre_tag.text.strip()
            formatted_info = format_whois_info(registrar_info)
            return formatted_info
        else:
            return None


def lookup_dns_records(domain):
  records = {}
  resolver = dns.resolver.Resolver()

  try:
    # Use resolve instead of deprecated query
    mx_records = resolver.resolve(domain, 'MX')
    mx_data = [f"{record.exchange.text} ({record.priority})" for record in mx_records]
    records['MX'] = mx_data

    # Uncomment and implement code to get additional records as needed:
    # ns_records = resolver.query(domain, 'NS')
    # records['NS'] = [record.text for record in ns_records]
    # a_records = resolver.query(domain, 'A')
    # records['A'] = [record.address for record in a_records]

  except dns.resolver.NXDOMAIN:
    print(f"Domain {domain} not found in DNS.")
  except dns.resolver.Timeout:
    print(f"DNS lookup timed out for {domain}.")
  except Exception as e:
    print(f"Error during DNS lookup: {e}")

  return records



def format_whois_info(whois_text):
    formatted_info = {}

    patterns = [
        ("Domain Name:", "Domain_Name"),
        ("Registrar:", "Registrar"),
        ("Registration Date:", "Registration_Date"),
        ("Expiration Date:", "Expiration_Date"),
        ("Updated Date:", "Updated_Date"),
        # Add more patterns as needed
    ]

    for label, key in patterns:
        match = re.search(rf"{label}\s+(.+)", whois_text)
        if match:
            formatted_info[key] = match.group(1).strip()

    return formatted_info


def main():
    print(r"""
        _____                _          __  __       _       
       / ____|              | |        |  \/  |     (_)      
      | |     _ __ __ _  ___| | _____  | \  / | __ _ _ _ __  
      | |    | '__/ _` |/ __| |/ / __| | |\/| |/ _` | | '_ \ 
      | |____| | | (_| | (__|   <\__ \ | |  | | (_| | | | | |
       \_____|_|  \__,_|\___|_|\_\___/ |_|  |_|\__,_|_|_| |_|

    """)

    selection = input("Select an option (r - Reconnaissance, p - Port Scan): ").lower()

    if selection == 'r':
        domain = input("Enter the domain name: ")
        domain_info = fetch_domain_info(domain)

        if domain_info:
            print("Domain Information:")
            for key, value in domain_info.items():
                print(f"{key}: {value}")

                  # Call DNS record lookup function
            dns_records = lookup_dns_records(domain)
            if dns_records:
                print("\nDNS Records:")
                for record_type, record_data in dns_records.items():
                    print(f"{record_type}: {', '.join(record_data)}")  # Join list elements with comma
        else:
            print("Failed to retrieve domain information.")

        

    elif selection == 'p':
        target = input("Enter the IP address or domain name to scan: ")

        try:
            if nmap_command:
                scan_results = subprocess.run([nmap_command, "-F", target], capture_output=True, text=True)
                print(scan_results.stdout)

        except Exception as e:
            print("Error during port scan:", e)

    else:
        print("Invalid option. Exiting...")


if __name__ == "__main__":
    main()


                                                                                    
