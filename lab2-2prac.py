
# Import necessary tools for the lab
from collections import defaultdict  # For easy counting
import time  # For measuring how long tasks take
import csv   # For saving data to CSV files

# The log file we'll be reading from
LOGFILE = "sample_auth_small.log"

# Function from the starter file that finds port numbers
def simple_parser(line):
    # Check if the line contains the word "port"
    if " port " in line:
        # Split the line into individual words
        parts = line.split()
        try:
            # Find which position the word "port" is at
            anchor = parts.index("port")
            # Get the word right after "port" (this should be the port number)
            port = parts[anchor+1]
            # Clean up any extra spaces and return the port number
            return port.strip()
        # If something goes wrong (like "port" not found or no number after it)
        except (ValueError, IndexError):
            return None
    # Return nothing if no "port" found in the line
    return None


# Task 1.1: Function to find IP addresses in log lines
def ip_parse(line):
    # Check if the line contains the word "from"
    if "from" in line:
        # Split the line into individual words
        parts = line.split()
        try:
            # Find which position the word "from" is at
            anchor = parts.index("from")
            # Get the word right after "from" (this should be the IP address)
            ip = parts[anchor + 1]
            # Clean up any extra spaces and return the IP
            return ip.strip()
        # If something goes wrong (like "from" not found or no IP after it)
        except (ValueError, IndexError):
            return None
    # Return nothing if no "from" found in the line
    return None



# Task 1.2: Find all unique IP addresses in the log file
def task1():
    # Create an empty set to store unique IPs (sets automatically remove duplicates)
    unique_ips = set()
    # Counter to track how many lines we read
    line_count = 0
    
    # Open the log file for reading
    with open("sample_auth_small.log") as f:
        # Read the file line by line
        for line in f:
            # Increase line counter by 1
            line_count += 1
            # Try to extract an IP address from this line
            ip = ip_parse(line)
            # If we found an IP, add it to our set
            if ip:
                unique_ips.add(ip)
    
    # Sort the IPs in alphabetical order
    sorted_ips = sorted(unique_ips)
    
    # Print results 
    print(f"Lines read: {line_count}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"First 10 IPs: {sorted_ips[:10]}")