# analyzer.py

def analyze_file(file_path):
    import re
    from collections import Counter

    # -------- Patterns --------
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    url_pattern = r"\"(?:GET|POST) (.*?) HTTP"
    status_pattern = r"\" (\d{3}) "

    # -------- Counters --------
    ip_counts = Counter()
    url_counts = Counter()
    status_counts = Counter()

    failed = 0
    success = 0
    total = 0

    with open(file_path, "r", errors="ignore") as file:
        for line in file:
            total += 1
            line_lower = line.lower()

            # Detect failed login
            if any(x in line_lower for x in ["failed", "invalid user", "authentication failure"]):
                failed += 1

            # Detect success login
            if any(x in line_lower for x in ["accepted password", "login successful", "session opened"]):
                success += 1

            # Extract IP
            ips = re.findall(ip_pattern, line)
            for ip in ips:
                ip_counts[ip] += 1

            # Extract URL
            url_match = re.search(url_pattern, line)
            if url_match:
                url_counts[url_match.group(1)] += 1

            # Extract status code
            status_match = re.search(status_pattern, line)
            if status_match:
                status_counts[status_match.group(1)] += 1

    # -------- Detection --------
    attackers = [(ip, c) for ip, c in ip_counts.items() if c > 20]
    suspicious = [(ip, c) for ip, c in ip_counts.items() if 8 < c <= 20]

    return {
        "total": total,
        "failed": failed,
        "success": success,
        "top_ips": ip_counts.most_common(5),
        "top_urls": url_counts.most_common(5),
        "status_codes": status_counts,
        "attackers": attackers,
        "suspicious": suspicious
    }