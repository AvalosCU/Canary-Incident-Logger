from datetime import datetime
import getpass
import socket
import csv
import os

MASTER_LOG_TXT = os.path.expanduser("~/canary/master_log.txt")
MASTER_LOG_CSV = os.path.expanduser("~/canary/master_log.csv")
COUNTER_FILE = os.path.expanduser("~/canary/trigger_count.txt")

def get_next_trigger_id():
    if not os.path.isfile(COUNTER_FILE):
        with open(COUNTER_FILE, "w") as f:
            f.write("0")

    with open(COUNTER_FILE, "r") as f:
        count = int(f.read().strip() or 0)

    count += 1

    with open(COUNTER_FILE, "w") as f:
        f.write(str(count))

    return count

def log_master_event(source, event, target, threat_level):
    trigger_id = get_next_trigger_id()
    timestamp = str(datetime.now())
    user = getpass.getuser()
    host = socket.gethostname()

    txt_line = (
        f"trigger_id={trigger_id} | time={timestamp} | user={user} | "
        f"host={host} | source={source} | event={event} | "
        f"target={target} | threat={threat_level}\n"
    )

    with open(MASTER_LOG_TXT, "a") as f:
        f.write(txt_line)

    file_exists = os.path.isfile(MASTER_LOG_CSV) and os.path.getsize(MASTER_LOG_CSV) > 0

    with open(MASTER_LOG_CSV, "a", newline="") as f:
        writer = csv.writer(f)

   
        if not file_exists:
            writer.writerow([
                "trigger_id",
                "timestamp",
                "user",
                "host",
                "source",
                "event",
                "target",
                "threat_level"
            ])

        writer.writerow([
            trigger_id,
            timestamp,
            user,
            host,
            source,
            event,
            target,
            threat_level
        ])

    print("=" * 50)
    print("CANARY ALERT")
    print(f"Trigger #{trigger_id}")
    print(f"Source: {source}")
    print(f"Event: {event}")
    print(f"Target: {target}")
    print(f"Threat Level: {threat_level}")
    print("=" * 50)
