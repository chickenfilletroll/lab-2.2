# lab2-3task3.py
from datetime import timedelta # used to reperesnt time intervals (e.g., 10 minutes)
import json # not used here, often used to save/laod data 
from collections import defaultdict # used to create dictionary with default values
from datetime import datetime # used to work with date and time
from collections import Counter # used to count occurrences of items in a list

LOGFILE = "sample_auth_small.log" # log file to analyze

def parse_auth_line(line):
    """
    Parse an auth log line and return (timestamp, ip, event_type)
    Example auth line:
    Mar 10 13:58:01 host1 sshd[1023]: Failed password for invalid user admin from 203.0.113.45 port 52344 ssh2
    We will:
     - parse timestamp (assume year 2025)
     - extract IP (token after 'from')
     - event_type: 'failed' if 'Failed password', 'accepted' if 'Accepted password', else 'other'
    """
    parts = line.split() # splits line into tokens
    # timestamp: first 3 tokens 'Mar 10 13:58:01'
    ts_str = " ".join(parts[0:3]) # joins first three tokens to get timestamp 
    try:
        ts = datetime.strptime(f"2025 {ts_str}", "%Y %b %d %H:%M:%S")
    except Exception:
        ts = None       # tries to parse  timestamp, assuming year 2025
    ip = None  # starts with no ip address found
    event_type = "other" # initializes ip and event_type variables

    if "Failed password" in line:
        event_type = "failed" # if lines says failed password, mark as failed
    elif "Accepted password" in line or "Accepted publickey" in line:
        event_type = "accepted"     # if lines says accepted password, mark as accepted
    if " from " in line: 
        try:
            idx = parts.index("from") # find word from
            ip = parts[idx+1] # word after from is the ip address
        except (ValueError, IndexError):
            ip = None       # if from is in lines, tries to get ip address (token after 'from'), else ip=None
    return ts, ip, event_type   # gives back timestamp, ip, event_type


# This runs when you execute the script directly
if __name__ == "__main__":
    per_ip_timestamps = defaultdict(list) # makes dictionary where each ip maps to list of timestamps
    with open(LOGFILE) as f:    # opens log file for reading
        for line in f:         # goes through each line in the file
            ts, ip, event = parse_auth_line(line) # parses line to get timestamp, ip, event type
            if ts and ip and event == "failed":   # checks that ts and ip are not null, and that event=="failed"
                per_ip_timestamps[ip].append(ts) # add timestamp to list for that ip

# Detect brute-force attempts: 5 or more failed logins within 10 minutes
incidents = []  # makes list to hold detected incidents
window = timedelta(minutes=10) # sets time window to 10 minutes
for ip, times in per_ip_timestamps.items(): # for each ip and its list of timestamps
    times.sort() # sort the timestamps in order
    n = len(times) # how many timestamps are there for this ip
    i = 0   # start with first timestamp
    while i < n:    # while we havent gone through all timestamps
        j = i   # start second pointer  
        # move j forward as long as time difference is within the window
        while j + 1 < n and (times[j+1] - times[i]) <= window: 
            j += 1
        count = j - i + 1   # how many timestamps are in this window
        if count >= 5:  # if 5 or more timestamps in this window, we have an incident
            incidents.append({ #record this incident
                "ip": ip, # the ip address
                "count": count, # how many failed logins
                "first": times[i].isoformat(), # timestamp of first failed login in this window
                "last": times[j].isoformat() # timestamp of last failed login in this window
            })
            # skip past this cluster to avoid overlapping reports:
            i = j + 1
        else:
            i += 1 #otherwise, just move i forward by one (move to next timestamp)

# print each brute-force incident found
for incident in incidents:
    print(incident) # show details of the incident

# Count total failed attempts per IP
failed_counts = {ip: len(times) for ip, times in per_ip_timestamps.items()}

# Sort IPs by failed count, descending
top_ips = sorted(failed_counts.items(), key=lambda x: x[1], reverse=True)

# Save summary to output report
with open("top_attackers_report.txt", "w") as f:
    f.write("IP\tFailed_Attempts\n")
    for ip, count in top_ips:
        f.write(f"{ip}\t{count}\n")

print("Top attacker summary saved to top_attackers_report.txt")

# --- Optional: Plot bar chart of top 10 attacker IPs ---
import matplotlib.pyplot as plt

# Get top 10 IPs and their counts
top10 = top_ips[:10]
ips = [ip for ip, count in top10]
counts = [count for ip, count in top10]

plt.figure(figsize=(10,5))
plt.bar(ips, counts)
plt.title("Top 10 attacker IPs")
plt.xlabel("IP")
plt.ylabel("Failed attempts")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("top_attackers.png")
plt.show()

print("Bar chart saved to top_attackers.png")
