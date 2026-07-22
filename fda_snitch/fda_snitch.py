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
        seq integer,
        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
        connected integer,
        hash text,
        prev_chain text,
        chain text
    ); """

# Columns added after the first release. Existing databases created by
# earlier versions only have (id, timestamp, connected, hash), so we add
# any missing ones on start-up instead of crashing with "no such column".
migrations = {
    "seq": "integer",
    "prev_chain": "text",
    "chain": "text",
}

# Anchor value for the very first row of a chain.
GENESIS = "genesis"

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
            self._migrate(cursor)
            conn.commit()
        finally:
            if conn:
                conn.close()

    def _connect_db(self):
        conn = sqlite3.connect(self.uri)
        return conn, conn.cursor()

    def _migrate(self, cursor):
        existing = {row[1] for row in cursor.execute("PRAGMA table_info(logs)")}
        for name, coltype in migrations.items():
            if name not in existing:
                # name/coltype are fixed internal identifiers, not user input.
                cursor.execute(f"ALTER TABLE logs ADD COLUMN {name} {coltype}")

    @staticmethod
    def _chain(seq, timestamp, connected, src_hash, prev_chain):
        # Tamper-evident chain: each row commits to the row before it, so a
        # changed, deleted, or truncated row breaks every following chain value.
        # Static so verify() reuses the exact same computation as run_snitch().
        payload = "|".join([
            str(seq),
            timestamp,
            str(int(connected)),
            src_hash,
            prev_chain,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    @classmethod
    def verify(cls, database_path):
        """Walk the hash chain in a log database and report the first break.

        Returns a dict:
            ok    -- True only if the chain is intact and seqs are contiguous
            rows  -- number of chained rows checked
            error -- None, or a human-readable description of the first problem
            seq   -- seq of the first problem row (None if ok)
            gaps  -- list of missing seq numbers (i.e. deleted rows)
        """
        conn = sqlite3.connect(database_path)
        try:
            rows = conn.execute(
                "SELECT seq, timestamp, connected, hash, prev_chain, chain "
                "FROM logs WHERE seq IS NOT NULL ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

        result = {"ok": False, "rows": len(rows), "error": None,
                  "seq": None, "gaps": []}

        if not rows:
            result["error"] = "no chained rows found (empty or pre-chain log)"
            return result

        prev_chain = GENESIS
        expected_seq = None
        for seq, timestamp, connected, src_hash, stored_prev, stored_chain in rows:
            # linkage: this row must point at the previous row's chain value
            if stored_prev != prev_chain:
                result["error"] = ("chain link broken (row edited, reordered, "
                                    "or a preceding row deleted)")
                result["seq"] = seq
                return result
            # recompute: the row's own fields must reproduce its chain value
            if cls._chain(seq, timestamp, connected, src_hash, stored_prev) != stored_chain:
                result["error"] = "chain hash mismatch (row contents altered)"
                result["seq"] = seq
                return result
            # seq contiguity: a missing number means a row was deleted
            if expected_seq is not None and seq > expected_seq:
                result["gaps"].extend(range(expected_seq, seq))
            expected_seq = seq + 1
            prev_chain = stored_chain

        if result["gaps"]:
            result["error"] = ("sequence gap(s): rows missing at seq "
                               + ", ".join(map(str, result["gaps"])))
            result["seq"] = result["gaps"][0]
        else:
            result["ok"] = True
        return result

    def _load_chain_state(self, cursor):
        # Resume the chain across restarts so a kill/restart leaves a visible
        # gap in seq/timestamp rather than silently starting a fresh chain.
        try:
            row = cursor.execute(
                "SELECT seq, chain FROM logs "
                "WHERE seq IS NOT NULL ORDER BY id DESC LIMIT 1"
            ).fetchone()
        except sqlite3.OperationalError:
            row = None
        if row and row[0] is not None:
            return row[0], row[1] or GENESIS
        return 0, GENESIS

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
        seq, prev_chain = self._load_chain_state(cursor)
        last_ping = None

        while(True):

            # A monitor that dies is worse than one that skips a beat, so a
            # transient failure (db lock, disk hiccup, network stack error)
            # must not kill the loop. seq only advances on a committed row, so
            # a skipped iteration never leaves a phantom gap in the chain.
            try:
                next_seq = seq + 1

                # create hash of file
                with open(Path(__file__).resolve(), "rb") as f:
                    src_hash = hashlib.sha256(f.read()).hexdigest()

                # current timestamp (stored and hashed as the same string)
                now = datetime.now().isoformat()

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

                # link this row to the previous one
                chain = self._chain(next_seq, now, connected, src_hash, prev_chain)

                # inject in database
                cursor.execute(
                    """
                    INSERT INTO logs (seq, timestamp, connected, hash, prev_chain, chain)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (next_seq, now, int(connected), src_hash, prev_chain, chain),
                )
                conn.commit()

                # only advance once the row is safely committed
                seq = next_seq
                prev_chain = chain
            except Exception:
                pass

            time.sleep(self.sleep)
