import nmap

from util import get_info_from_user, check_user_answer
from validations import validate_ip, validate_scan_type

scanner = nmap.PortScanner()
 
print("nmap automation tool")
print("#"*50)

ALLOWED_VERIFY_ATTEMPTS = 3

get_ip_message = "Please, insert an IP address to scan: "

ip_addr = get_info_from_user(get_ip_message)

attempts = 0

while True:
    attempts += 1

    if attempts >= ALLOWED_VERIFY_ATTEMPTS:
        print("You have exceeded the number of attempts to verify the IP address.")
        print("Exiting the program.")
        exit(-1)
    if check_user_answer(ip_addr, "Invalid IP address", validate_ip):
        break
    
    ip_addr = get_info_from_user(get_ip_message)

print('#'*50)

get_scan_type_message = """Please, select an scan type:
1) SYN ACK Scan
2) UDP Scan
3) Comprehensive Scan\n\n"""

scan_type = get_info_from_user(get_scan_type_message)

scan_type_selection_attempts = 0

while True:
    scan_type_selection_attempts += 1

    if scan_type_selection_attempts >= ALLOWED_VERIFY_ATTEMPTS:
        print("You have exceeded the number of attempts to verify the scan type.")
        print("Exiting the program.")
        exit(-1)

    if check_user_answer(scan_type, "Invalid scan type", validate_scan_type):
        break

    scan_type = get_info_from_user(get_scan_type_message)


print("Nmap version: ", scanner.nmap_version())

match scan_type:
    case "1":
        print("SYN ACK Scan running")
        scanner.scan(ip_addr, '1-1024', '-v -sS')
    case "2":   
        print("UDP Scan running")
        scanner.scan(ip_addr, '1-1024', '-v -sU')
    case "3": 
        print("Comprehensive Scan running")
        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
    case _:
        print("Invalid scan type")
        exit(-1)


scan_types_protocol_mapping = {
    "1": "tcp",
    "2": "udp",
    "3": "tcp"
}

print(scanner.scaninfo())

state = scanner[ip_addr].state()

print("IP Status: ", state)

if (state == "down"):
    print("IP is down. Exiting the program.")
    exit(-1)

print(scanner[ip_addr].all_protocols())

print("Open ports", scanner[ip_addr][scan_types_protocol_mapping.get(scan_type)].keys())