"""
Python Security Dashboard
Author: Crystal Frasier
Company: Quantum Technologies

Reads the results from the security log analyzer and displays
a summary dashboard for security analysts.
"""

import os
from collections import Counter


REPORT_FILE = "incident_response_report.md"
LOG_FILE = "sample_auth.log"


def load_log_data(log_file):
    """Load authentication log data."""
    users = []
    failed_logins = 0
    successful_logins = 0

    if not os.path.exists(log_file):
        print(f"Error: {log_file} not found.")
        return users, failed_logins, successful_logins

    with open(log_file, "r") as file:
        for line in file:
            if "User:" in line:
                username = line.split("User:")[1].split()[0]
                users.append(username)

            if "FAILED LOGIN" in line:
                failed_logins += 1

            if "LOGIN SUCCESS" in line:
                successful_logins += 1

    return users, failed_logins, successful_logins


def display_dashboard():
    """Display security dashboard."""

    users, failed, successful = load_log_data(LOG_FILE)

    print("=" * 60)
    print("        PYTHON SECURITY DASHBOARD")
    print("=" * 60)

    print(f"Successful Logins : {successful}")
    print(f"Failed Logins     : {failed}")
    print(f"Total Events      : {successful + failed}")

    print("\nTop User Activity")
    print("-" * 60)

    counts = Counter(users)

    for user, total in counts.most_common():
        print(f"{user:<20} {total}")

    print("\nThreat Level")

    if failed >= 10:
        level = "HIGH"
    elif failed >= 5:
        level = "MEDIUM"
    else:
        level = "LOW"

    print(f"Current Threat Level: {level}")

    print("\nIncident Report")

    if os.path.exists(REPORT_FILE):
        print("Available")
    else:
        print("Not Found")

    print("=" * 60)


if __name__ == "__main__":
    display_dashboard()
