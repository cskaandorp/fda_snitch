import hashlib
import os
import platform
import sqlite3
import socket
import time
from datetime import datetime
from pathlib import Path


create_table = """
    CREATE TABLE IF NOT EXISTS logs (
        id integer PRIMARY KEY,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        connected integer,
        hash text
    ); """

class Snitch:
    def __init__(
            self,
            sleep=1,
            database_path=None,
            url=None,
            with_sound=True):
        
        conn = None
        self.sleep = sleep
        self.uri = "./log.sqlite" if database_path is None else database_path
        self.url = "www.google.com" if url is None else url
        self.with_sound = with_sound

        try:
            conn, cursor = self._connect_db()
            cursor.execute(create_table)
        finally:
            if conn:
                conn.close()

    def _connect_db(self):
        conn = sqlite3.connect(self.uri)
        return conn, conn.cursor()

    def _ping(self):
        try:
            socket.create_connection((self.url, 80), timeout=5)
            return True
        except OSError:
            return False

    def beep(self):
        if platform.system() == 'Windows':
            import winsound
            winsound.Beep(1000, 500)  # Frequency, Duration in ms
        elif platform.system() == 'Darwin':  # macOS
            os.system('afplay /System/Library/Sounds/Ping.aiff')
        
    def run_snitch(self):
        conn, cursor = self._connect_db()
        last_ping = None

        while(True):
            
            # create hash of file
            with open(Path(__file__).resolve(),"rb") as f:
                hash = hashlib.md5(f.read()).hexdigest()
            
            # current timestamp
            now = datetime.now()

            # try to reach out to google.nl
            connected = self._ping()

            if last_ping is None:
                last_ping = connected

            if connected != last_ping and self.with_sound:
                try:
                    # beep twice
                    self.beep()
                    self.beep()
                finally:
                    pass
                
            # reset
            last_ping = connected

            # inject in database
            cursor.execute(
                """
                INSERT INTO logs (timestamp, connected, hash)
                VALUES (?, ?, ?)
                """,
                (now, int(connected), hash),
            )
            conn.commit()

            time.sleep(self.sleep)
