# lab2-2_starter.py - Complete Lab 2.2 Solution

from collections import defaultdict
import time
import csv

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

def ip_parse(line):
    """
    Task 1.1: Write your own ip_parse(line) function using token-based extraction
    Looks for the token 'from' and returns the following IP address
    """
    if "from" in line:
        parts = line.split()  # Split the line into tokens
        try:
            anchor = parts.index("from")    # Find the position of the token "from"
            ip = parts[anchor + 1]          # The IP address will be the next token
            return ip.strip()               # Clean up any trailing punctuation
        except (ValueError, IndexError):
            return None
    return None

def top_n(counts, n=5):
    """
    Helper function for Task 3: Sort dictionary items and select top N entries
    """
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

def task1():
    """
    Task 1.2: Extract unique IPs from sample_auth_small.log
    """
    unique_ips = set()  # Use set() to keep unique items
    line_count = 0
    
    # Read each line in sample_auth_small.log
    with open("sample_auth_small.log", "r") as f:
        for line in f:
            line_count += 1
            ip = ip_parse(line)  # Extract IP addresses
            if ip:
                unique_ips.add(ip)  # Build set of unique IPs
    
    # Sort the unique IPs
    sorted_ips = sorted(unique_ips)
    
    # Print required output
    print(f"Lines read: {line_count}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"First 10 IPs: {sorted_ips[:10]}")

def task2():
    """
    Task 2: Count failed login attempts per IP
    Using defaultdict(int) to count occurrences
    Only count lines containing Failed password or Invalid user
    """
    counts = defaultdict(int)  # Create a dictionary to keep track of IPs
    
    with open("sample_auth_small.log", "r") as f:
        for line in f:
            if "Failed password" in line or "Invalid user" in line:
                # extract ip
                ip = ip_parse(line)
                if ip:
                    counts[ip] += 1
    
    # Print the counts for all IPs
    print("Failed login counts per IP:")
    print(counts)

def task3():
    """
    Task 3: Top 5 attacker IPs and export
    Run on mixed_logs_5000.log and time execution
    """
    # Start timing
    start = time.time()
    
    counts = defaultdict(int)
    
    # Try to use mixed_logs_5000.log, fall back to sample_auth_small.log if not found
    try:
        filename = "mixed_logs_5000.log"
        with open(filename, "r") as f:
            for line in f:
                if "Failed password" in line or "Invalid user" in line:
                    ip = ip_parse(line)
                    if ip:
                        counts[ip] += 1
    except FileNotFoundError:
        # Fall back to small file if large file not available
        filename = "sample_auth_small.log"
        with open(filename, "r") as f:
            for line in f:
                if "Failed password" in line or "Invalid user" in line:
                    ip = ip_parse(line)
                    if ip:
                        counts[ip] += 1
    
    # Get top 5 IPs by failed attempts
    top_attackers = top_n(counts, 5)
    
    # Print nicely formatted top 5
    print("Top 5 attacker IPs:")
    for rank, (ip, count) in enumerate(top_attackers, 1):
        print(f"{rank}. {ip} — {count}")
    
    # Write to CSV file with headers
    with open("failed_counts.txt", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "failed_count"])  # Headers
        for ip, count in counts.items():
            writer.writerow([ip, count])
    
    # End timing and print results
    end = time.time()
    print(f"\nWrote failed_counts.txt")
    print(f"Elapsed: {end - start:.2f} seconds")

## This is the main block that will run first. 
## It will call any functions from above that we might need.
if __name__ == "__main__":
    print("=== Task 1: Extract unique IPs ===")
    task1()
    
    print("\n=== Task 2: Count failed login attempts per IP ===")
    task2()
    
    print("\n=== Task 3: Top 5 attacker IPs and export ===")
    task3()