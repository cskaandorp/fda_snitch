# fda_snitch

A lightweight **exam-integrity monitor** for supervised (Jupyter) exams.

While it runs, it keeps a tamper-evident log of two things on the student's
machine:

- **Internet connectivity** — whether the machine can reach the network, sampled
  every second, with an **audible beep** the moment connectivity goes up or down.
- **Clipboard activity** — when the clipboard content *changes* (a copy/paste of
  external material), it records a fingerprint and length **but never the content
  itself**.

Every entry is linked into a hash chain, so a log that has been edited, had rows
deleted, or was swapped between students **fails verification**. It is primarily a
**deterrent** — the beep and the "it keeps a record" reputation discourage going
online or pasting answers — backed by a log you can check afterwards.

> **Honest scope.** This is a deterrent and a tamper-evidence tool, not
> surveillance and not unbreakable. A determined student with administrator
> rights can ultimately defeat any tool running on their own machine. Its job is
> to make casual cheating risky and obvious, and to give you a checkable record.
> The real invigilation is still the proctor in the room.

---

## Installation

```bash
pip install fda_snitch
```

No external dependencies — it uses only the Python standard library. Works on
**macOS** and **Windows**, Python 3.6+.

---

## Quick start (for the teacher / proctor)

The student runs two cells in their exam notebook.

**Cell 1 — start monitoring:**

```python
from fda_snitch import Snitch

snitch = Snitch()          # prompts: Student name:
```

Entering a name (e.g. `Alice Smith`) prints:

```
[fda_snitch] monitoring active for Alice Smith -> ./log_alice_smith.sqlite
```

**Cell 2 — run it (this cell stays running for the whole exam):**

```python
snitch.run_snitch()        # runs until the cell is interrupted (Kernel → Interrupt)
```

That's it. A per-student database `log_alice_smith.sqlite` is created next to the
notebook and fills up as the exam proceeds. At the end, collect that file.

> **Tip:** to run the monitor *without* blocking the notebook, start it in a
> background thread:
> ```python
> import threading
> threading.Thread(target=snitch.run_snitch, daemon=True).start()
> ```

---

## Recommended for graded exams: tamper-proof mode

By default the log detects **casual** tampering. To make it **unforgeable** — so a
student cannot rebuild a convincing log even if they read this source code — give
the tool a secret key that only you hold. Each log entry then becomes an HMAC that
cannot be reproduced without the key.

Set one secret per exam (or per student) in the environment **before** launching
the student's notebook, so it never appears in the notebook itself:

```bash
export FDA_SNITCH_KEY='pick-a-long-random-per-exam-secret'
# now launch Jupyter
```

Nothing else changes for the student. Keep the secret; you'll need it to verify.

> The key does live on the student's machine while monitoring runs, so someone
> with admin rights *could* extract it. It defeats offline forgery by everyone who
> won't go that far — which is nearly everyone — and raises the bar for the rest.

---

## After the exam: verifying a log

Run this on your own machine, on the file you collected:

```python
from fda_snitch import Snitch

result = Snitch.verify(
    "log_alice_smith.sqlite",
    student="Alice Smith",              # assert whose log this should be
    secret="pick-a-long-random-per-exam-secret",  # omit if you didn't use a key
)
print(result)
```

`verify()` returns a dictionary:

| Key         | Meaning |
|-------------|---------|
| `ok`        | `True` only if the chain is intact, contiguous, and (if keyed) the key matches. This is your headline answer. |
| `error`     | `None`, or a description of the **first** problem found. |
| `seq`       | The sequence number of the first problem row. |
| `rows`      | How many entries were checked. |
| `gaps`      | Sequence numbers of **deleted** rows, if any. |
| `student`   | The name stored in the log. |
| `code_hash` | Fingerprint of the code that produced the log. |
| `keyed`     | Whether the log carries a key binding. |

**Examples of what it catches:**

```python
Snitch.verify("log_alice_smith.sqlite", student="Alice Smith", secret=KEY)
# {'ok': True,  'error': None, ...}                      -> intact

Snitch.verify("log_alice_smith.sqlite", student="Bob Jones")
# {'ok': False, 'error': "student mismatch: log is for 'Alice Smith'..."}

Snitch.verify("log_alice_smith.sqlite", secret="wrong-key")
# {'ok': False, 'error': 'wrong secret (key does not match this log)'}

Snitch.verify("log_alice_smith.sqlite")          # keyed log, no key given
# {'ok': False, 'error': 'log is keyed; pass secret= ...'}
```

Editing any value, deleting or reordering rows, swapping in another student's log,
or (in keyed mode) forging entries all produce `ok: False`.

### Reading the connectivity and clipboard events

The data lives in the `logs` table of the SQLite file:

```python
import sqlite3
con = sqlite3.connect("log_alice_smith.sqlite")

# moments the network went up/down
for row in con.execute(
    "SELECT timestamp, connected FROM logs ORDER BY id"):
    ...

# clipboard-change events (fingerprint + size, never the text)
for ts, clip_len in con.execute(
    "SELECT timestamp, clip_len FROM logs WHERE clip_hash IS NOT NULL ORDER BY id"):
    print(ts, "clipboard changed,", clip_len, "characters")
```

A large clipboard change during an air-gapped exam, or a burst of connectivity, is
the kind of signal worth a closer look.

---

## What is recorded (and what is not)

Each row of the `logs` table holds: a sequence number, a UTC timestamp, the
connectivity state, the code fingerprint, and — only when the clipboard changed —
a **SHA-256 hash and character count** of the new clipboard contents. Plus the
hash-chain link that ties it to the previous row.

- The clipboard **text is never stored** — only its hash and length. You can tell
  *that* something was copied and *how big* it was, and spot the same thing pasted
  twice (same hash), but not read it.
- The student's name and the code fingerprint are stored in a small `meta` table.

Because this monitors students, tell them it is running and what it records.

---

## What it can and cannot catch

**Catches / deters:** going online or losing connection (with a beep and a log),
copying external material to the clipboard, and after-the-fact editing, deletion,
truncation, or swapping of the log.

**Does not catch:** a second device or phone, material typed by hand, drag-and-drop
that bypasses the clipboard, or *where* copied content came from. Clipboard polling
sees content *entering* the clipboard, so a copy and a paste look the same, and a
copy→paste→clear that happens within a single one-second tick can be missed
(shorten `sleep` to narrow that window).

---

## Configuration reference

`Snitch(sleep=1, database_path=None, url=None, with_sound=True, student=None, secret=None)`

| Argument        | Default             | Meaning |
|-----------------|---------------------|---------|
| `sleep`         | `1`                 | Seconds between samples. |
| `database_path` | `./log_<name>.sqlite` | Where to write the log. |
| `url`           | `www.google.com`    | Host used for the connectivity check (port 80). |
| `with_sound`    | `True`              | Beep on a connectivity change. |
| `student`       | prompt              | Student name; if omitted, you are asked. Blank → `anon`. |
| `secret`        | `FDA_SNITCH_KEY`    | Enable tamper-proof (HMAC) mode. |

`Snitch.verify(database_path, student=None, expected_code_hash=None, secret=None)`
— returns the result dictionary described above. Pass `expected_code_hash` to also
assert the official code produced the log (get the reference hash by running
`python -c "from fda_snitch import Snitch; print(Snitch._hash_source())"` from a
trusted install of the same version).

---

## Platform notes

- **macOS** — fully exercised.
- **Windows** — connectivity, logging, beep and chain work the same. The clipboard
  reader uses a native `ctypes` call; verify it on a representative machine before
  a high-stakes exam with:
  ```bash
  python -c "from fda_snitch import Snitch; print(repr(Snitch._win_clipboard()))"
  ```
  (copy some text first; it should print that text).

---

## License

See repository.
```
