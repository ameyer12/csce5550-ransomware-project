import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

# Define a connection and cursor for SQLite
connection = sqlite3.connect('monitored_events.db', timeout=5, check_same_thread=False)
cursor = connection.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS monitored_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    event_type TEXT NOT NULL,
    path TEXT NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
)
''')
connection.commit()

def send_email(subject, body):
    sender_email = "" # Replace with the sender email
    sender_password = ""  # Replace with your email password
    recipient_email = ""  # Replace with administrator's email

    # Set up email server
    server = smtplib.SMTP('smtp.gmail.com', 587) 
    server.starttls()  # Enable TLS
    server.login(sender_email, sender_password)

    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject

    msg.attach(MIMEText(body, 'plain'))

    # Send the email
    server.send_message(msg)
    server.quit()

class MyEventHandler(FileSystemEventHandler):
    def __init__(self, connection, observer, debounce_time=0.35):
        self.connection = connection  # SQLite database connection
        self.cursor = self.connection.cursor()  # Cursor for executing SQL commands
        self.observer = observer # Observer instance to manage file system events
        self.debounce_time = debounce_time
        self.last_event_time = 0
        self.threshold = 2
        self.time_window = 5
        self.file_modified_count = 0  # Counter for modified files
        self.file_add_count = 0  # Counter for added files
        self.file_remove_count = 0  # Counter for removed files

    # Method to monitor modified, added, and deleted file events
    def on_any_event(self, event) -> None:
        current_time = time.time()

        # If the path ends in a suspicious file extension (i.e., .enc)
        if event.src_path.endswith(".enc") or (hasattr(event, 'dest_path') and event.dest_path.endswith(".enc")):
            print(f"Suspicious event detected (encryption file): {event}")
            
            # Log event in database
            self.cursor.execute('''
                INSERT INTO monitored_events (event_type, path)
                VALUES (?, ?)
            ''', (event.event_type, getattr(event, 'dest_path', event.src_path)))
            self.connection.commit()

            # Send alert email to sytem administrator
            send_email("Potential Ransomware Attack Detected", f"Suspicious activity logged in database: {event}")

            self.observer.stop()  # Stop the observer to terminate further events
            return
        
        # Ensure events don't occur within debounce time (this prevents looping additions to monitored_events db)
        if current_time - self.last_event_time > self.debounce_time:
            self.last_event_time = current_time
            
            # Increment the respective counters
            if event.event_type == "modified":
                self.file_modified_count += 1
            elif event.event_type == "created":
                self.file_add_count += 1
            elif event.event_type == "deleted":
                self.file_remove_count += 1

            # If any counter exceeds threshold
            if (self.file_modified_count >= self.threshold or
                self.file_add_count >= self.threshold or
                self.file_remove_count >= self.threshold):

                print(f"Suspicious event detected (rapid activity): {event}")
                
                # Log in database
                self.cursor.execute('''
                    INSERT INTO monitored_events (event_type, path)
                    VALUES (?, ?)
                ''', (event.event_type, event.src_path))
                self.connection.commit()
                
                # Send alert email
                send_email("Potential Ransomware Attack Detected", f"Suspicious activity logged in database: {event}")

                self.observer.stop()  # Stop the observer to terminate further events

            if current_time - self.last_event_time >= self.time_window:
                self.file_modified_count = 0
                self.file_add_count = 0
                self.file_remove_count = 0

# Initialize observer
observer = Observer()
event_handler = MyEventHandler(connection, observer)

# Start observing the directory
observer.schedule(event_handler, "/path/to/critical/directory", recursive=True)
observer.start()

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()
finally:
    observer.join()
    connection.close()  # Close the database connection
