import hashlib
import pkg_resources
import sqlite3
import time
import urllib.request
from datetime import datetime
from pathlib import Path

import simpleaudio as sa

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
            sleep=2,
            database_path=None,
            url=None,
            with_sound=True,
            repeat_sound=2):
        
        conn = None
        self.sleep = sleep
        self.uri = "./log.sqlite" if database_path is None else database_path
        self.url = "https://google.com" if url is None else url
        self.last_ping = None
        self.with_sound = with_sound
        self.repeat_sound = 2 if not(isinstance(repeat_sound, int)) else repeat_sound

        # load sound file
        path = pkg_resources.resource_filename(__name__, "assets/censor-beep-2.wav")
        self.sound = sa.WaveObject.from_wave_file(path)

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
            response = urllib.request.urlopen(self.url)
            response.read() # probably not necessary
            return True
        except urllib.error.URLError:
            return False
        except Exception:
            return False

    def run_snitch(self):
        conn, cursor = self._connect_db()
        while(True):
            
            # create hash of file
            with open(Path(__file__).resolve(),"rb") as f:
                hash = hashlib.md5(f.read()).hexdigest()
            
            # current timestamp
            now = datetime.now()

            # try to reach out to google.nl
            connected = int(self._ping())

            if self.last_ping is None:
                self.last_ping = connected

            if connected != self.last_ping and self.with_sound:
                # play sound
                for _ in range(self.repeat_sound):
                    playing = self.sound.play()
                    playing.wait_done()
                    time.sleep(0.5)

            # reset
            self.last_ping = connected

            # inject in database
            cursor.execute(f"""
                INSERT INTO logs (timestamp, connected, hash)
                VALUES 
                ('{now}', {connected}, '{hash}')
                """)
            conn.commit()

            time.sleep(self.sleep)
