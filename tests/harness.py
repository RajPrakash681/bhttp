"""Process and file-system fixtures shared by the test modules."""
import os
import random
import re
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
BSERVE = os.path.abspath(os.path.join(REPO, os.environ.get("BSERVE", "build/debug/bserve")))
BCURL = os.path.abspath(os.path.join(REPO, os.environ.get("BCURL", "build/debug/bcurl")))

SANITIZER_MARKERS = ("AddressSanitizer", "LeakSanitizer", "UndefinedBehaviorSanitizer",
                     "runtime error:")

BIG_SIZE = 100000      # > 6 frames of 16384
EXACT_SIZE = 32768     # exactly 2 frames


def sanitizer_env():
    env = dict(os.environ)
    env.setdefault("UBSAN_OPTIONS", "print_stacktrace=1:halt_on_error=1")
    env.setdefault("ASAN_OPTIONS", "halt_on_error=1")
    return env


def sanitizer_lines(text):
    return [line for line in text.splitlines() if any(m in line for m in SANITIZER_MARKERS)]


def make_site(base):
    """A document root with the sample site plus test fixtures; returns its path.

    base/secret.txt lies outside the root and must never be served.
    """
    root = os.path.join(base, "www")
    shutil.copytree(os.path.join(REPO, "www"), root)
    with open(os.path.join(base, "secret.txt"), "w") as f:
        f.write("outside the root\n")
    rng = random.Random(1234)
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(bytes(rng.getrandbits(8) for _ in range(BIG_SIZE)))
    with open(os.path.join(root, "exact.bin"), "wb") as f:
        f.write(bytes(rng.getrandbits(8) for _ in range(EXACT_SIZE)))
    open(os.path.join(root, "empty.txt"), "w").close()
    os.mkdir(os.path.join(root, "sub"))
    with open(os.path.join(root, "sub", "index.html"), "w") as f:
        f.write("<p>sub index</p>\n")
    with open(os.path.join(root, ".hidden"), "w") as f:
        f.write("hidden\n")
    with open(os.path.join(root, "%2e%2e"), "w") as f:
        f.write("a file literally named %2e%2e\n")
    with open(os.path.join(root, "with space.txt"), "w") as f:
        f.write("spaces are fine\n")
    with open(os.path.join(root, "noread.txt"), "w") as f:
        f.write("no permission\n")
    os.chmod(os.path.join(root, "noread.txt"), 0)
    os.symlink(os.path.join(base, "secret.txt"), os.path.join(root, "link-out"))
    os.symlink("hello.txt", os.path.join(root, "link-in"))
    os.mkfifo(os.path.join(root, "fifo"))
    return root


def remove_site(base):
    noread = os.path.join(base, "www", "noread.txt")
    if os.path.exists(noread):
        os.chmod(noread, 0o644)
    shutil.rmtree(base, ignore_errors=True)


class Server(object):
    """bserve on a free port, with its stderr captured in a log file."""

    def __init__(self, root, idle=None):
        self.root = root
        self.idle = idle
        self.log_path = os.path.join(os.path.dirname(root), "bserve-%d.log" % id(self))
        self.proc = None
        self.port = None
        self._log = None

    def start(self):
        args = [BSERVE]
        if self.idle is not None:
            args += ["-t", str(self.idle)]
        args += [self.root, "0"]
        self._log = open(self.log_path, "ab")
        self.proc = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                     stderr=self._log, start_new_session=True,
                                     env=sanitizer_env())
        m = self.wait_for(r"listening on 0\.0\.0\.0:(\d+)")
        self.port = int(m[0].group(1))
        return self

    def log(self):
        with open(self.log_path, "r", errors="replace") as f:
            return f.read()

    def wait_for(self, pattern, count=1, timeout=10.0, since=0):
        """The first `count` matches of pattern in the log (after offset `since`)."""
        deadline = time.time() + timeout
        while True:
            matches = list(re.finditer(pattern, self.log()[since:], re.M))
            if len(matches) >= count:
                return matches
            if time.time() > deadline:
                raise AssertionError("log never matched %r x%d:\n%s" % (pattern, count, self.log()))
            if self.proc.poll() is not None:
                raise AssertionError("bserve exited (%s):\n%s" % (self.proc.returncode, self.log()))
            time.sleep(0.02)

    def peer_lines(self, port):
        """Log lines for the client connection whose local port is `port`."""
        tag = "127.0.0.1:%d " % port
        return [line for line in self.log().splitlines() if tag in line]

    def stop(self):
        if self.proc and self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            self.proc.wait(timeout=10)
        if self._log:
            self._log.close()


class SiteServerCase(object):
    """Mixin: one bserve per test class, over a fresh fixture site."""

    idle = None

    @classmethod
    def setUpClass(cls):
        cls.base = tempfile.mkdtemp(prefix="bhttp-test-")
        cls.root = make_site(cls.base)
        cls.server = Server(cls.root, idle=cls.idle).start()

    @classmethod
    def tearDownClass(cls):
        cls.server.stop()
        bad = sanitizer_lines(cls.server.log())
        remove_site(cls.base)
        if bad:
            raise AssertionError("sanitizer reports in the bserve log:\n" + "\n".join(bad))

    def file_bytes(self, name):
        with open(os.path.join(self.root, name), "rb") as f:
            return f.read()


def run_bcurl(*args, timeout=60):
    """(exit status, stdout bytes, stderr text); fails on sanitizer output."""
    proc = subprocess.run([BCURL] + list(args), stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          timeout=timeout, env=sanitizer_env())
    err = proc.stderr.decode("utf-8", "replace")
    bad = sanitizer_lines(err)
    if bad:
        raise AssertionError("sanitizer reports from bcurl:\n" + err)
    return proc.returncode, proc.stdout, err


class FakeServer(object):
    """A scripted bhttp server for testing bcurl.

    `handler(conn)` runs for every accepted connection; `accepted` counts them.
    """

    def __init__(self, handler):
        self.handler = handler
        self.accepted = 0
        self.errors = []
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def _run(self):
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            self.accepted += 1
            conn.settimeout(10)
            try:
                self.handler(conn)
            except Exception as e:  # reported by the test
                self.errors.append(e)
            finally:
                conn.close()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=5)
        self.sock.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
