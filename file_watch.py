from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from datetime import datetime
import os
import time
import getpass
import socket
import csv

WATCH_PATH = os.path.expanduser("~/secret.txt")
LOG_FILE = os.path.expanduser("~/canary/file_access_log.txt")
CSV_FILE = os.path.expanduser("~/canary/file_access_log.csv")

class CanaryHandler(FileSystemEventHandler):

    def log_event(self, event_type, src_path):
        timestamp = str(datetime.now())
        user = getpass.getuser()
        host = socket.gethostname()

        with open(LOG_FILE, "a") as f:
            f.write(f"{timestamp} | user={user} | host={host} | event={event_type} | path={src_path}\n")

        file_exists = os.path.isfile(CSV_FILE)

        with open(CSV_FILE, "a", newline="") as f:
            writer = csv.writer(f)

            if not file_exists:
                writer.writerow(["timestamp", "user", "host", "event_type", "path"])

            writer.writerow([timestamp, user, host, event_type, src_path])

        print(f"⚠️ Canary file event detected: {event_type} -> {src_path}")

    def on_modified(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == os.path.abspath(WATCH_PATH):
            self.log_event("modified", event.src_path)

    def on_deleted(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == os.path.abspath(WATCH_PATH):
            self.log_event("deleted", event.src_path)

    def on_moved(self, event):
        if not event.is_directory and os.path.abspath(event.src_path) == os.path.abspath(WATCH_PATH):
            self.log_event("moved", event.src_path)


if __name__ == "__main__":
    watch_folder = os.path.dirname(WATCH_PATH)

    event_handler = CanaryHandler()
    observer = Observer()
    observer.schedule(event_handler, watch_folder, recursive=False)
    observer.start()

    print(f"Watching: {WATCH_PATH}")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()

    observer.join()
