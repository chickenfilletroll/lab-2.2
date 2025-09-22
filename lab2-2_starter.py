# lab2-2_starter.py

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

# Task 3: Function to find the top N IPs with most failed attempts
def top_n(counts, n=5):
    # Sort the IPs by their failure counts (highest to lowest)
    # Take only the first N results (top 5 by default)
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

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
    
    # Print the results as required by the lab
    print(f"Lines read: {line_count}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"First 10 IPs: {sorted_ips[:10]}")

# Task 2: Count how many failed login attempts each IP has
def task2():
    # Create a dictionary that starts counting at 0 for new IPs
    counts = defaultdict(int)
    
    # Open the log file for reading
    with open("sample_auth_small.log") as f:
        # Read the file line by line
        for line in f:
            # Only look at lines about failed logins
            if "Failed password" in line or "Invalid user" in line:
                # Try to extract an IP address from this line
                ip = ip_parse(line)
                # If we found an IP, increase its failure count by 1
                if ip:
                    counts[ip] += 1
    
    # Print the dictionary showing IPs and their failure counts
    print(counts)

# Task 3: Find the top 5 attackers and save results to a file
def task3():
    # Record the start time to measure how long this takes
    start = time.time()
    
    # Create a dictionary for counting (same as Task 2)
    counts = defaultdict(int)
    
    # Open the larger log file for reading
    with open("sample_auth_small.log") as f:
        # Read the file line by line
        for line in f:
            # Only look at lines about failed logins
            if "Failed password" in line or "Invalid user" in line:
                # Try to extract an IP address
                ip = ip_parse(line)
                # If found, increase its failure count
                if ip:
                    counts[ip] += 1
    
    # Get the top 5 IPs with most failed attempts
    top_attackers = top_n(counts, 5)
    
    # Print the top 5 in a nice format
    print("Top 5 attacker IPs:")
    # Number each IP starting from 1
    for rank, (ip, count) in enumerate(top_attackers, 1):
        print(f"{rank}. {ip} — {count}")
    
    # Save all the IP counts to a CSV file
    with open("failed_counts.txt", "w", newline='') as csvfile:
        # Create a CSV writer object
        writer = csv.writer(csvfile)
        # Write the header row
        writer.writerow(["ip", "failed_count"])
        # Write each IP and its count as a new row
        for ip, count in counts.items():
            writer.writerow([ip, count])
    
    # Record the end time and calculate how long it took
    end = time.time()
    print(f"Wrote failed_counts.txt")
    print(f"Elapsed: {end-start:.2f} seconds")

# This runs when you execute the script directly
if __name__ == "__main__":
    # Run Task 1: Find unique IPs
    task1()
    # Run Task 2: Count failed attempts per IP
    task2()
    # Run Task 3: Find top attackers and save to file
    task3()