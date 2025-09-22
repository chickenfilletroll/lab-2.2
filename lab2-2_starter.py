# lab2-2_starter.py

LOGFILE = "sample_auth_small.log"  # change filename if needed

def simple_parser(line):
    """
    looks for the substring ' port ' and returns the following port number.
    Returns None if no matching substring found.
    """
    if " port " in line:
        parts = line.split() # splits the line into tokens, seperates by spaces by default
        try:
            anchor = parts.index("port")    # Find the position of the token "port", our anchor
            port = parts[anchor+1]          # the port value will be next token, anchor+1
            return port.strip()             # strip any trailing punctuation

        except (ValueError, IndexError):
            return None

    return None

## This is the main block that will run first. 
## It will call any functions from above that we might need.
if __name__ == "__main__":

    with open(LOGFILE, "r") as f:
        for line in f:
            print (simple_parser(line.strip()))


## CREATING IP_PARSE FUNCTION

def ip_parse(line)

    """
    uses token (words) based extraction to find ip addresses in log files.
    looks for token "from" and returnd the following ip addrfess
    returns none if no ip found
    """

    if "from" in line:
        parts = line.split() # split line into words/ tokens
        try:
            anchor = parts.index("from") # find position of "from"
            ip = parts[anchor + 1] # gets next word (pos 12) which should be IP
            return ip.strip() # clean up any extra characters
        except (ValueError, IndexError):
            return None
    return None   

## READ FILE AND FIND UNIQUE IPS

def task1():
    unique_ips - set()  # set to store uniqyue IPS
    line_count = 0

    with open("sample_auth_small.log", "r") as file: # with open() safely opens and closes file
        for line in file:
            line_count += 1
            ip = ip_parse(line)
            if ip:
                unique_ips.add(ip)  # add IP to set (sets automatically handle duplicates)

# convert to sorted list
sorted_ips = sorted(unique_ips) # sorted() puts IPs in alphabetical order

print(f"Lines read: {line_count}")
print(f"unique IPs: {len(unique_ips)}")
print(f"first 10 IPs: {sorted_ips[:10]}")



## COUNt FAIL LOGIN ATTEMPTS

from colections import defaultdict

def task2():
    counts = defaultdict(int) # creates dictionary that starts with 0 for new keys, defaultdict(int) makes new entries with value 0 

    with open("sample_auth_snall.log", "r") as file:
        for line in file:
            if "Failed password" in line or "Invalid user" in line:
                ip = ip_parse(line)
                if ip:
                    counts[ip] += 1 # increment count for this very IP

    print("Failed login counts per IP:")
    for ip, count in counts.items():
        print(f"{ip}: {count}")                
