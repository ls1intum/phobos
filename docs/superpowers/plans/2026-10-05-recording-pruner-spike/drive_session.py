"""Spike only. Types one interactive Python session into a real terminal and checks each step.

An interactive bash runs in a pseudo-terminal, with job control, and starts the launcher given on
the command line (python3 bare, under the recorder, or under phobos.sh). The session then reads,
writes, creates, deletes, moves, talks to its own loopback servers over TCP and UDP, starts child
processes, is interrupted with Ctrl+C and suspended with Ctrl+Z and resumed with fg, and
optionally fetches an HTTPS page. Each step prints a marker that the echo of the typed line cannot
contain, so a step passes only when it ran. Prints one JSON summary line.
"""

from __future__ import annotations

import argparse
import json
import os
import pty
import re
import select
import sys
import time

# The steps, each a line typed into the Python prompt and the marker its output must show.
STEPS = (
    ("import os, socket, threading, tempfile, subprocess, time", None),
    ('print("OK-" + "R1", len(open("/etc/hostname").read()) > 0)', "OK-R1 True"),
    ('print("OK-" + "R2", len(open("/opt/java/openjdk/release").read()) > 0)', "OK-R2 True"),
    (('fd, p = tempfile.mkstemp(dir="/var/tmp/testing-dir"); os.write(fd, b"x"); os.close(fd); '
     'os.replace(p, "/var/tmp/testing-dir/out.txt"); '
     'print("OK-" + "W1", open("/var/tmp/testing-dir/out.txt").read())'), "OK-W1 x"),
    (('d = "/var/tmp/testing-dir/cache/" + str(os.getpid()); os.makedirs(d); '
     'open(d + "/entry", "w").write("y"); print("OK-" + "W2")'), "OK-W2"),
    ('os.unlink("/var/tmp/testing-dir/old.txt"); print("OK-" + "D1")', "OK-D1"),
    (('q = tempfile.mktemp(dir="/tmp"); open(q, "w").write("m"); '
     'os.rename(q, "/var/tmp/testing-dir/moved.txt"); print("OK-" + "M1")'), "OK-M1"),
    (('srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(); '
     'port = srv.getsockname()[1]; '
     't = threading.Thread(target=lambda: srv.accept()[0].sendall(b"hello")); t.start(); '
     'c = socket.create_connection(("127.0.0.1", port)); print("OK-" + "N1", c.recv(5)); '
     't.join(); c.close(); srv.close()'), "OK-N1 b'hello'"),
    (('u = socket.socket(type=socket.SOCK_DGRAM); u.bind(("127.0.0.1", 0)); '
     'v = socket.socket(type=socket.SOCK_DGRAM); v.sendto(b"ping", u.getsockname()); '
     'print("OK-" + "U1", u.recv(4)); u.close(); v.close()'), "OK-U1 b'ping'"),
    ('print("OK-" + "P1", subprocess.run(["ls", "/usr/share/doc"], capture_output=True).returncode)',
     "OK-P1 0"),
    (('print("OK-" + "P2", subprocess.run(["/var/tmp/testing-dir/tool.sh"], '
     'capture_output=True).stdout)'), "OK-P2 b'tool\\n'"),
)

# The step that needs a network and a resolver, added with --network.
NETWORK_STEP = (('import http.client; h = http.client.HTTPSConnection("example.org", timeout=20); '
                'h.request("HEAD", "/"); print("OK-" + "E1", h.getresponse().status > 0)'),
                "OK-E1 True")

# How long one step may take before the session counts as failed.
STEP_SECONDS = 60


class Terminal:
    """A pseudo-terminal running an interactive bash, read with a timeout."""

    def __init__(self, transcript: str):
        pid, descriptor = pty.fork()
        if pid == 0:
            os.environ["PS1"] = "SHELL$ "
            os.environ["TERM"] = "dumb"
            os.execvp("bash", ["bash", "--norc", "--noprofile", "-i"])
        self.pid = pid
        self.descriptor = descriptor
        self.buffer = ""
        self.transcript = transcript
        with open(transcript, "w", encoding="utf-8"):
            pass

    def send(self, text: str) -> None:
        """Types text into the terminal."""
        os.write(self.descriptor, text.encode())

    def expect(self, pattern: str, seconds: float = STEP_SECONDS) -> bool:
        """Waits until the output after the last match holds the pattern."""
        deadline = time.monotonic() + seconds
        compiled = re.compile(pattern)
        while time.monotonic() < deadline:
            match = compiled.search(self.buffer)
            if match:
                self.buffer = self.buffer[match.end():]
                return True
            ready, _, _ = select.select([self.descriptor], [], [], 0.2)
            if ready:
                try:
                    chunk = os.read(self.descriptor, 65536).decode("utf-8", "replace")
                except OSError:
                    return False
                with open(self.transcript, "a", encoding="utf-8") as handle:
                    handle.write(chunk)
                self.buffer += chunk
        return False


def run(launcher: str, with_network: bool, transcript: str) -> dict:
    """Runs the session and answers which steps passed and how long each took."""
    terminal = Terminal(transcript)
    result = {"launcher": launcher, "steps": {}, "passed": True}
    started = time.monotonic()
    terminal.expect(r"SHELL\$ ")
    terminal.send(launcher + "\r")
    if not terminal.expect(r">>> ", 120):
        result["passed"] = False
        result["steps"]["start"] = "no prompt"
        return result
    steps = list(STEPS) + ([NETWORK_STEP] if with_network else [])
    for line, marker in steps:
        step_started = time.monotonic()
        terminal.send(line + "\r")
        ok = terminal.expect(re.escape(marker)) if marker else True
        ok = ok and terminal.expect(r">>> ")
        result["steps"][marker or "import"] = round(time.monotonic() - step_started, 3) if ok else "FAILED"
        result["passed"] = result["passed"] and ok
    result["steps"]["ctrl-c"] = interrupt(terminal)
    result["steps"]["ctrl-z"] = suspend(terminal)
    terminal.send("exit()\r")
    result["steps"]["exit"] = terminal.expect(r"SHELL\$ ")
    result["total_seconds"] = round(time.monotonic() - started, 3)
    result["passed"] = (result["passed"] and result["steps"]["ctrl-c"]["interrupted"]
                        and result["steps"]["ctrl-z"] and result["steps"]["exit"])
    terminal.send("exit\r")
    return result


def interrupt(terminal: Terminal) -> dict:
    """Ctrl+C during a sleep must interrupt Python and leave the prompt working. Whether the
    traceback, which Python writes to stderr, reached the terminal, and whether stderr still
    does afterwards, is reported apart, because under phobos.sh stderr passes through a relay."""
    started = time.monotonic()
    terminal.send("time.sleep(60)\r")
    time.sleep(1)
    terminal.send("\x03")
    traceback_shown = terminal.expect(r"KeyboardInterrupt", 5)
    terminal.send('print("OK-" + "C1", round(time.monotonic()))\r')
    prompt_works = terminal.expect(r"OK-C1", 10)
    interrupted = prompt_works and time.monotonic() - started < 30
    terminal.expect(r">>> ", 5)
    terminal.send('import sys; sys.stderr.write("OK-" + "E2\\n")\r')
    stderr_works = terminal.expect(r"OK-E2", 5)
    terminal.expect(r">>> ", 5)
    return {"interrupted": interrupted, "traceback_shown": traceback_shown,
            "stderr_after": stderr_works}


def suspend(terminal: Terminal) -> bool:
    """Ctrl+Z must stop the job in bash, and fg must bring the same Python back."""
    terminal.expect(r">>> ", 5)
    terminal.send("\x1a")
    if not terminal.expect(r"Stopped", 10):
        return False
    terminal.expect(r"SHELL\$ ", 5)
    terminal.send("fg\r")
    time.sleep(1)
    terminal.send('\rprint("OK-" + "Z1")\r')
    return terminal.expect(r"OK-Z1", 15)


def main() -> int:
    """Parses the arguments and prints the summary."""
    parser = argparse.ArgumentParser()
    parser.add_argument("--launcher", required=True)
    parser.add_argument("--network", action="store_true")
    parser.add_argument("--transcript", required=True)
    arguments = parser.parse_args()
    result = run(arguments.launcher, arguments.network, arguments.transcript)
    print(json.dumps(result))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    sys.exit(main())
