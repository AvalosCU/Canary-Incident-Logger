from master_log import log_master_event
import sys

def get_threat_level(command):
    command = command.lower()

    if "nano" in command or "rm" in command or "mv" in command:
        return "High"
    elif "cat" in command or "less" in command or "open" in command:
        return "Medium"
    else:
        return "Low"

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("No command given")
        sys.exit(1)

    command = sys.argv[1]
    threat_level = get_threat_level(command)

    log_master_event(
        source="terminal",
        event=command,
        target="secret.txt",
        threat_level=threat_level
    )
