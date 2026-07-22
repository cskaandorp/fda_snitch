import hashlib
import os
import platform
import re
import sqlite3
import socket
import subprocess
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
        clip_hash text,
        clip_len integer,
        prev_chain text,
        chain text
    ); """

# Per-student metadata (name, etc.). Keeps the log tied to a person.
create_meta = """
    CREATE TABLE IF NOT EXISTS meta (
        key text PRIMARY KEY,
        value text
    ); """

# Columns added after the first release. Existing databases created by
# earlier versions only have (id, timestamp, connected, hash), so we add
# any missing ones on start-up instead of crashing with "no such column".
migrations = {
    "seq": "integer",
    "prev_chain": "text",
    "chain": "text",
    "clip_hash": "text",
    "clip_len": "integer",
}

# Anchor value for the very first row of a chain.
GENESIS = "genesis"

class Snitch:
    def __init__(
            self,
            sleep=1,
            database_path=None,
            url=None,
            with_sound=True,
            student=None):

        # Ask who is being monitored before anything starts. Blank -> "anon",
        # so a skipped prompt never stops the exam from beginning.
        if student is None:
            try:
                student = input("Student name: ")
            except EOFError:
                student = ""
        self.student = (student or "").strip()
        self.slug = self._slug(self.student)
        # The whole chain hangs off a name-derived root, so every row transitively
        # depends on the student's identity: change the name and the chain breaks.
        self.root = self._root(self.student)

        conn = None
        self.sleep = sleep
        # Personalise the database name so each student gets their own file.
        self.uri = f"./log_{self.slug}.sqlite" if database_path is None else database_path
        self.url = "www.google.com" if url is None else url
        self.with_sound = with_sound

        try:
            conn, cursor = self._connect_db()
            cursor.execute(create_table)
            cursor.execute(create_meta)
            self._migrate(cursor)
            # First writer wins: preserve the identity the log was created with
            # even if a later run supplies a different name for the same file.
            cursor.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('student', ?)",
                (self.student,),
            )
            conn.commit()
        finally:
            if conn:
                conn.close()

        print(f"[fda_snitch] monitoring active for "
              f"{self.student or 'anon'} -> {self.uri}")

    @staticmethod
    def _slug(name):
        # Filesystem-safe, lower-case handle for the database filename.
        slug = re.sub(r"[^A-Za-z0-9]+", "_", (name or "").strip()).strip("_").lower()
        return slug or "anon"

    @staticmethod
    def _root(student):
        # Chain anchor derived from the student's name (replaces the generic
        # GENESIS seed). Empty name still yields a stable, name-bound root.
        seed = "fda_snitch:" + (student or "").strip()
        return hashlib.sha256(seed.encode("utf-8")).hexdigest()

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
    def _chain(seq, timestamp, connected, src_hash, clip_hash, clip_len, prev_chain):
        # Tamper-evident chain: each row commits to the row before it, so a
        # changed, deleted, or truncated row breaks every following chain value.
        # Static so verify() reuses the exact same computation as run_snitch().
        payload = "|".join([
            str(seq),
            timestamp,
            str(int(connected)),
            src_hash,
            clip_hash or "",
            "" if clip_len is None else str(int(clip_len)),
            prev_chain,
        ])
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def _read_clipboard(self):
        # Return the current clipboard text, or None if empty, non-text, or
        # unavailable. Dependency-free and native per platform: pbpaste on
        # macOS, a small ctypes call on Windows (avoiding a ~500ms powershell
        # spawn every tick). The caller only ever hashes this — the content
        # itself is never stored.
        system = platform.system()
        try:
            if system == 'Darwin':
                out = subprocess.run(
                    ['pbpaste'], capture_output=True, timeout=5)
                if out.returncode != 0:
                    return None
                text = out.stdout.decode('utf-8', 'replace')
                return text or None
            elif system == 'Windows':
                return self._win_clipboard()
        except Exception:
            return None
        return None

    @staticmethod
    def _win_clipboard():
        # Read CF_UNICODETEXT from the Windows clipboard via ctypes. restypes
        # are set to c_void_p so 64-bit HANDLEs are not truncated. Returns None
        # if the clipboard is busy, empty, or holds non-text (e.g. an image).
        import ctypes
        CF_UNICODETEXT = 13
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        user32.GetClipboardData.restype = ctypes.c_void_p
        kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
        kernel32.GlobalLock.restype = ctypes.c_void_p
        kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
        if not user32.OpenClipboard(0):
            return None
        try:
            if not user32.IsClipboardFormatAvailable(CF_UNICODETEXT):
                return None
            handle = user32.GetClipboardData(CF_UNICODETEXT)
            if not handle:
                return None
            ptr = kernel32.GlobalLock(handle)
            if not ptr:
                return None
            try:
                text = ctypes.c_wchar_p(ptr).value
            finally:
                kernel32.GlobalUnlock(handle)
            return text or None
        finally:
            user32.CloseClipboard()

    @classmethod
    def verify(cls, database_path, student=None):
        """Walk the hash chain in a log database and report the first break.

        Pass ``student`` to assert whose log this should be: the chain is then
        re-rooted from that name, so a log swapped in from another student (or
        stripped of its identity) fails at the very first row.

        Returns a dict:
            ok      -- True only if the chain is intact and seqs are contiguous
            rows    -- number of chained rows checked
            error   -- None, or a human-readable description of the first problem
            seq     -- seq of the first problem row (None if ok)
            gaps    -- list of missing seq numbers (i.e. deleted rows)
            student -- the name stored in the log (None for legacy logs)
        """
        conn = sqlite3.connect(database_path)
        try:
            stored = None
            try:
                r = conn.execute(
                    "SELECT value FROM meta WHERE key='student'"
                ).fetchone()
                stored = r[0] if r else None
            except sqlite3.OperationalError:
                stored = None  # legacy log without a meta table
            rows = conn.execute(
                "SELECT seq, timestamp, connected, hash, clip_hash, clip_len, "
                "prev_chain, chain FROM logs WHERE seq IS NOT NULL ORDER BY id"
            ).fetchall()
        finally:
            conn.close()

        result = {"ok": False, "rows": len(rows), "error": None,
                  "seq": None, "gaps": [], "student": stored}

        # Caller asserted a name that disagrees with the log's own record.
        if (student is not None and stored is not None
                and student.strip() != stored.strip()):
            result["error"] = (f"student mismatch: log is for {stored!r}, "
                               f"expected {student!r}")
            return result

        # Which identity roots the chain? Prefer the asserted name, then the
        # stored one; fall back to the generic seed for pre-identity logs.
        identity = student if student is not None else stored
        root = cls._root(identity) if identity is not None else GENESIS

        if not rows:
            result["error"] = "no chained rows found (empty or pre-chain log)"
            return result

        prev_chain = root
        expected_seq = None
        for (seq, timestamp, connected, src_hash, clip_hash, clip_len,
                stored_prev, stored_chain) in rows:
            # linkage: this row must point at the previous row's chain value
            if stored_prev != prev_chain:
                result["error"] = ("chain link broken (row edited, reordered, "
                                    "or a preceding row deleted)")
                result["seq"] = seq
                return result
            # recompute: the row's own fields must reproduce its chain value
            if cls._chain(seq, timestamp, connected, src_hash, clip_hash,
                          clip_len, stored_prev) != stored_chain:
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
            return row[0], row[1] or self.root
        return 0, self.root

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
        last_clip_hash = None

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

                # detect new clipboard contents. We record only a hash and a
                # length when the clipboard *changes* since the previous tick,
                # never the content itself. A cleared clipboard resets the
                # baseline so re-copying the same text is logged again.
                clip_hash = None
                clip_len = None
                clip = self._read_clipboard()
                if clip is not None:
                    h = hashlib.sha256(clip.encode("utf-8")).hexdigest()
                    if h != last_clip_hash:
                        clip_hash = h
                        clip_len = len(clip)
                    last_clip_hash = h
                else:
                    last_clip_hash = None

                # link this row to the previous one
                chain = self._chain(next_seq, now, connected, src_hash,
                                    clip_hash, clip_len, prev_chain)

                # inject in database
                cursor.execute(
                    """
                    INSERT INTO logs (seq, timestamp, connected, hash, clip_hash, clip_len, prev_chain, chain)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (next_seq, now, int(connected), src_hash,
                     clip_hash, clip_len, prev_chain, chain),
                )
                conn.commit()

                # only advance once the row is safely committed
                seq = next_seq
                prev_chain = chain
            except Exception:
                pass

            time.sleep(self.sleep)
