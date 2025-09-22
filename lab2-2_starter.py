# lab2-2_starter.py - Complete Solution

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
    Extract IP address from log line using token-based parsing
    Looks for the word 'from' and takes the next token as the IP address
    """
    if "from" in line:  # Check if line contains the anchor word 'from'
        parts = line.split()  # Split line into words (tokens) using spaces
        try:
            anchor = parts.index("from")  # Find position of 'from' in the token list
            ip = parts[anchor + 1]        # Get the next word after 'from' (the IP address)
            return ip.strip()             # Remove any extra spaces/punctuation and return IP
        except (ValueError, IndexError):
            return None  # Return None if we can't extract IP
    return None  # Return None if line doesn't contain 'from'

def top_n(counts, n=5):
    """
    Return the top N items from a dictionary by their values (counts)
    """
    # Sort dictionary items by value (count) in descending order and return top N
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

def task1():
    """
    Task 1: Extract unique IP addresses from the log file
    """
    unique_ips = set()  # Set automatically removes duplicates
    line_count = 0      # Counter for total lines read
    
    with open(LOGFILE, "r") as file:
        for line in file:
            line_count += 1          # Increment line counter
            ip = ip_parse(line)      # Extract IP from current line
            if ip:                   # If IP was successfully extracted
                unique_ips.add(ip)   # Add to set (duplicates automatically ignored)
    
    # Convert set to sorted list for consistent ordering
    sorted_ips = sorted(unique_ips)
    
    # Print results as required by the lab
    print(f"Lines read: {line_count}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"First 10 IPs: {sorted_ips[:10]}")
    
    return unique_ips

def task2():
    """
    Task 2: Count failed login attempts per IP address
    """
    # defaultdict(int) creates dictionary where new keys automatically get value 0
    counts = defaultdict(int)
    
    with open(LOGFILE, "r") as file:
        for line in file:
            # Check if line indicates a failed login attempt
            if "Failed password" in line or "Invalid user" in line:
                ip = ip_parse(line)  # Extract IP from failed login line
                if ip:               # If IP extraction successful
                    counts[ip] += 1  # Increment count for this IP
    
    print("Failed login counts per IP:")
    # Print each IP with its failure count
    for ip, count in counts.items():
        print(f"{ip}: {count}")
    
    return counts  # Return counts dictionary for use in Task 3

def task3():
    """
    Task 3: Find top 5 attackers and export results to CSV
    """
    start_time = time.time()  # Record start time for performance measurement
    
    # Count failed attempts (same logic as Task 2)
    counts = defaultdict(int)
    with open(LOGFILE, "r") as file:
        for line in file:
            if "Failed password" in line or "Invalid user" in line:
                ip = ip_parse(line)
                if ip:
                    counts[ip] += 1
    
    # Get top 5 IPs with most failed attempts using the top_n function
    top_attackers = top_n(counts, 5)
    
    # Print formatted results
    print("Top 5 attacker IPs:")
    # enumerate(..., 1) gives rank starting from 1 instead of 0
    for rank, (ip, count) in enumerate(top_attackers, 1):
        print(f"{rank}. {ip} — {count}")
    
    # Export all IP counts to CSV file
    with open("failed_counts.txt", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)           # Create CSV writer object
        writer.writerow(["ip", "failed_count"])  # Write header row
        # Write each IP and its count as a row
        for ip, count in counts.items():
            writer.writerow([ip, count])
    
    end_time = time.time()  # Record end time
    # Calculate and print execution time
    elapsed_time = end_time - start_time
    print(f"\nWrote failed_counts.txt")
    print(f"Elapsed: {elapsed_time:.2f} seconds")

def test_with_larger_file():
    """
    Bonus: Test with the larger file as mentioned in Task 3
    """
    global LOGFILE
    original_logfile = LOGFILE  # Save original filename
    
    # Test with larger file
    LOGFILE = "mixed_logs_5000.log"  # Change to your larger file name
    
    try:
        print("\n" + "="*50)
        print("Testing with larger file:", LOGFILE)
        print("="*50)
        
        start_time = time.time()
        
        # Count failed attempts in larger file
        counts = defaultdict(int)
        with open(LOGFILE, "r") as file:
            for line in file:
                if "Failed password" in line or "Invalid user" in line:
                    ip = ip_parse(line)
                    if ip:
                        counts[ip] += 1
        
        # Get top 5 from larger file
        top_attackers = top_n(counts, 5)
        
        print("Top 5 attacker IPs from larger file:")
        for rank, (ip, count) in enumerate(top_attackers, 1):
            print(f"{rank}. {ip} — {count}")
        
        end_time = time.time()
        elapsed_time = end_time - start_time
        print(f"Elapsed with larger file: {elapsed_time:.2f} seconds")
        
    except FileNotFoundError:
        print(f"Large file {LOGFILE} not found. Skipping large file test.")
    
    finally:
        LOGFILE = original_logfile  # Restore original filename

## This is the main block that will run first. 
## It will call any functions from above that we might need.
if __name__ == "__main__":
    # Run the three main tasks
    print("=== Task 1: Extract Unique IPs ===")
    task1()
    
    print("\n=== Task 2: Count Failed Logins per IP ===")
    task2()
    
    print("\n=== Task 3: Top 5 Attackers and Export ===")
    task3()
    
    # Optional: Test with larger file
    test_with_larger_file()