"""
Python Security Log Analyzer
Author: Crystal Frasier
Company: Quantum Technologies

Analyzes authentication logs, identifies failed and successful logins,
flags possible brute-force activity, assigns a risk level, and exports
a security summary report.
"""

from collections import Counter
from datetime import datetime
from pathlib import Path


BRUTE_FORCE_THRESHOLD = 3
LOG_FILE = "sample_auth.log"
REPORT_FILE = "security_analysis_report.txt"


def extract_username(line: str) -> str | None:
    """Extract the username from a log entry containing 'User:'."""
    marker = "User:"
    if marker not in line:
        return None

    remainder = line.split(marker, 1)[1].strip()
    if not remainder:
        return None

    return remainder.split()[0]


def determine_risk_level(
    total_failed: int,
    brute_force_accounts: dict[str, int],
) -> str:
    """Assign a risk level based on failed logins and brute-force indicators."""
    if brute_force_accounts or total_failed >= 10:
        return "HIGH"
    if total_failed >= 5:
        return "MEDIUM"
    return "LOW"


def analyze_log(file_name: str) -> dict:
    """Analyze an authentication log and return structured findings."""
    failed_users: list[str] = []
    successful_users: list[str] = []
    total_lines = 0

    log_path = Path(file_name)

    if not log_path.exists():
        raise FileNotFoundError(f"'{file_name}' was not found.")

    with log_path.open("r", encoding="utf-8") as log_file:
        for raw_line in log_file:
            line = raw_line.strip()

            if not line:
                continue

            total_lines += 1
            username = extract_username(line)

            if "FAILED LOGIN" in line.upper() and username:
                failed_users.append(username)

            if "LOGIN SUCCESS" in line.upper() and username:
                successful_users.append(username)

    failed_counts = Counter(failed_users)
    successful_counts = Counter(successful_users)

    brute_force_accounts = {
        user: count
        for user, count in failed_counts.items()
        if count >= BRUTE_FORCE_THRESHOLD
    }

    risk_level = determine_risk_level(
        total_failed=len(failed_users),
        brute_force_accounts=brute_force_accounts,
    )

    return {
        "analysis_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "log_file": file_name,
        "total_entries": total_lines,
        "total_failed": len(failed_users),
        "total_successful": len(successful_users),
        "failed_counts": failed_counts,
        "successful_counts": successful_counts,
        "brute_force_accounts": brute_force_accounts,
        "risk_level": risk_level,
    }


def format_report(results: dict) -> str:
    """Create a readable security analysis report."""
    lines = [
        "=" * 60,
        "PYTHON SECURITY LOG ANALYZER",
        "=" * 60,
        f"Analysis Time:       {results['analysis_time']}",
        f"Log File:            {results['log_file']}",
        f"Total Log Entries:   {results['total_entries']}",
        f"Successful Logins:   {results['total_successful']}",
        f"Failed Logins:       {results['total_failed']}",
        f"Overall Risk Level:  {results['risk_level']}",
        "",
        "FAILED LOGIN COUNTS",
        "-" * 60,
    ]

    if results["failed_counts"]:
        for user, count in results["failed_counts"].most_common():
            lines.append(f"{user:<20} {count}")
    else:
        lines.append("No failed logins detected.")

    lines.extend(
        [
            "",
            "SUCCESSFUL LOGIN COUNTS",
            "-" * 60,
        ]
    )

    if results["successful_counts"]:
        for user, count in results["successful_counts"].most_common():
            lines.append(f"{user:<20} {count}")
    else:
        lines.append("No successful logins detected.")

    lines.extend(
        [
            "",
            "BRUTE-FORCE ALERTS",
            "-" * 60,
        ]
    )

    if results["brute_force_accounts"]:
        for user, count in results["brute_force_accounts"].items():
            lines.append(
                f"ALERT: User '{user}' recorded {count} failed login attempts."
            )
    else:
        lines.append(
            f"No accounts reached the threshold of "
            f"{BRUTE_FORCE_THRESHOLD} failed attempts."
        )

    lines.extend(
        [
            "",
            "RECOMMENDED ACTIONS",
            "-" * 60,
            "1. Review accounts with repeated authentication failures.",
            "2. Enable multi-factor authentication for privileged accounts.",
            "3. Apply account lockout controls after repeated failures.",
            "4. Continue monitoring authentication logs.",
            "5. Escalate confirmed brute-force activity for investigation.",
            "",
            "Analysis complete.",
            "=" * 60,
        ]
    )

    return "\n".join(lines)


def save_report(report: str, output_file: str) -> None:
    """Save the analysis report to a text file."""
    Path(output_file).write_text(report, encoding="utf-8")


def main() -> None:
    try:
        results = analyze_log(LOG_FILE)
        report = format_report(results)

        print(report)
        save_report(report, REPORT_FILE)

        print(f"\nReport saved to: {REPORT_FILE}")

    except FileNotFoundError as error:
        print(f"Error: {error}")
    except OSError as error:
        print(f"File processing error: {error}")


if __name__ == "__main__":
    main()
