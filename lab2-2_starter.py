# lab2-2_starter.py

from collections import defaultdict
import time
import csv

LOGFILE = "sample_auth_small.log"

def simple_parser(line):
    if " port " in line:
        parts = line.split()
        try:
            anchor = parts.index("port")
            port = parts[anchor+1]
            return port.strip()
        except (ValueError, IndexError):
            return None
    return None

def ip_parse(line):
    if "from" in line:
        parts = line.split()
        try:
            anchor = parts.index("from")
            ip = parts[anchor + 1]
            return ip.strip()
        except (ValueError, IndexError):
            return None
    return None

def top_n(counts, n=5):
    return sorted(counts.items(), key=lambda kv: kv[1], reverse=True)[:n]

def task1():
    unique_ips = set()
    line_count = 0
    
    with open("sample_auth_small.log") as f:
        for line in f:
            line_count += 1
            ip = ip_parse(line)
            if ip:
                unique_ips.add(ip)
    
    sorted_ips = sorted(unique_ips)
    
    print(f"Lines read: {line_count}")
    print(f"Unique IPs: {len(unique_ips)}")
    print(f"First 10 IPs: {sorted_ips[:10]}")

def task2():
    counts = defaultdict(int)
    
    with open("sample_auth_small.log") as f:
        for line in f:
            if "Failed password" in line or "Invalid user" in line:
                ip = ip_parse(line)
                if ip:
                    counts[ip] += 1
    
    print(counts)

def task3():
    start = time.time()
    
    counts = defaultdict(int)
    
    with open("mixed_logs_5000.log") as f:
        for line in f:
            if "Failed password" in line or "Invalid user" in line:
                ip = ip_parse(line)
                if ip:
                    counts[ip] += 1
    
    top_attackers = top_n(counts, 5)
    
    print("Top 5 attacker IPs:")
    for rank, (ip, count) in enumerate(top_attackers, 1):
        print(f"{rank}. {ip} — {count}")
    
    with open("failed_counts.txt", "w", newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["ip", "failed_count"])
        for ip, count in counts.items():
            writer.writerow([ip, count])
    
    end = time.time()
    print(f"Wrote failed_counts.txt")
    print(f"Elapsed: {end-start:.2f} seconds")

if __name__ == "__main__":
    task1()
    task2()
    task3()