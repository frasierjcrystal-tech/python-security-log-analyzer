"""
Python Security Log Analyzer
Author: Crystal Frasier
Company: Quantum Technologies

This program analyzes authentication log files to identify
failed login attempts and suspicious activity.
"""

from collections import Counter


def analyze_log(file_name):
    failed_attempts = 0
    usernames = []

    try:
        with open(file_name, "r") as log_file:
            for line in log_file:

                if "FAILED LOGIN" in line.upper():
                    failed_attempts += 1

                if "USER:" in line.upper():
                    username = line.split("User:")[-1].strip()
                    usernames.append(username)

        print("=" * 50)
        print("PYTHON SECURITY LOG ANALYZER")
        print("=" * 50)
        print(f"Total Failed Logins: {failed_attempts}")

        if usernames:
            print("\nUser Login Counts:")
            counts = Counter(usernames)

            for user, count in counts.items():
                print(f"  {user}: {count}")

        print("\nAnalysis Complete.")

    except FileNotFoundError:
        print(f"Error: '{file_name}' was not found.")


if __name__ == "__main__":
    analyze_log("sample_auth.log")
