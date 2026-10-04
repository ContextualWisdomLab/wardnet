"""Finite same-process-group custody for POSIX offline smoke fixtures.

Settlement means an exact supervisor wait and an empty group observation, not
physical grandchild waits or containment of children that deliberately setsid.
Permanent OS failure and interruption during an unreturned native Popen spawn
are outside this cooperative fixture contract. Uncertainty retains the root.
"""
import contextlib
import os
import selectors
import shutil
import signal
import subprocess
import tempfile
import time


class SettlementError(RuntimeError):
    """The caller must retain its fixture because settlement is unproved."""


# Keep the returned owner on uncertainty and refuse further fixture launches.
_unresolved = []


@contextlib.contextmanager
def owned_root(*, prefix, dir):
    """Dispose only an exclusively created root with established settlement."""
    root = tempfile.mkdtemp(prefix=prefix, dir=dir)
    retain = False
    try:
        yield root
    except SettlementError:
        retain = True
        raise
    finally:
        if not retain and not _unresolved:
            shutil.rmtree(root)


def members(group):
    output = subprocess.check_output(
        ['ps', '-axo', 'pid,ppid,pgid'], text=True, timeout=3
    )
    rows = []
    for line in output.splitlines()[1:]:
        fields = line.split()
        if len(fields) != 3 or not all(field.isdigit() for field in fields):
            raise SettlementError('invalid process observation')
        if int(fields[2]) == group:
            rows.append(int(fields[0]))
    return rows


def run(args, *, input, env, timeout, root):
    """Preserve the primary error after bounded same-group settlement."""
    if _unresolved:
        raise SettlementError('previous fixture unsettled; no new launch')
    assert args == ['bash', '-s'] and timeout > 0
    child = None
    primary = None
    settled = False
    result = None
    with contextlib.ExitStack() as resources:
        # Register returned descriptors before further fallible acquisitions.
        fds = []
        for _ in range(2):
            for fd in os.pipe():
                fds.append(fd)
                resources.callback(os.close, fd)
        status_read, status_write, release_read, release_write = fds
        source = resources.enter_context(tempfile.TemporaryFile(dir=root))
        stdout = resources.enter_context(tempfile.TemporaryFile(dir=root))
        stderr = resources.enter_context(tempfile.TemporaryFile(dir=root))
        source.write(input)
        source.seek(0)
        wrapper = '''
trap ':' TERM
bash -s
result=$?
trap '' TERM
printf '%s\\n' "$result" >&"$1"
IFS= read -r -t 15 release <&"$2"
exit "$result"
'''
        try:
            child = subprocess.Popen(
                ['bash', '-c', wrapper, 'smoke-owner', str(status_write), str(release_read)],
                stdin=source, stdout=stdout, stderr=stderr, env=env,
                pass_fds=(status_write, release_read), start_new_session=True,
            )
            deadline = time.monotonic() + timeout
            with selectors.DefaultSelector() as selector:
                selector.register(status_read, selectors.EVENT_READ)
                if not selector.select(max(0, deadline - time.monotonic())):
                    raise subprocess.TimeoutExpired(args, timeout)
                os.set_blocking(status_read, False)
                raw = os.read(status_read, 32)
                if not raw.endswith(b'\n') or not raw[:-1].isdigit():
                    raise SettlementError('invalid supervisor result')
                result = int(raw[:-1])
        except BaseException as exc:
            primary = exc
        finally:
            cleanup_error = None
            if child is not None:
                try:
                    # The leader pins the group until release or escalation.
                    # There are no signals after the exact wait below.
                    os.killpg(child.pid, signal.SIGTERM)
                    deadline = time.monotonic() + 3
                    remaining = members(child.pid)
                    while any(pid != child.pid for pid in remaining) and time.monotonic() < deadline:
                        time.sleep(.01)
                        remaining = members(child.pid)
                    if any(pid != child.pid for pid in remaining):
                        os.killpg(child.pid, signal.SIGKILL)
                    else:
                        os.write(release_write, b'release\n')
                except BaseException as exc:
                    cleanup_error = exc
                # Signal/observation failure cannot skip an exact wait attempt.
                try:
                    child.wait(timeout=3)
                    deadline = time.monotonic() + 3
                    while members(child.pid) and time.monotonic() < deadline:
                        time.sleep(.01)
                    if members(child.pid):
                        raise SettlementError('subtree settlement unknown')
                    if cleanup_error is None:
                        settled = True
                except BaseException as exc:
                    if cleanup_error is None:
                        cleanup_error = exc
                if not settled:
                    _unresolved.append(child)
            else:
                settled = True
            if cleanup_error is not None and primary is None:
                primary = cleanup_error
        if not settled:
            raise SettlementError('subtree settlement unknown; retain fixture') from primary
        if primary is not None:
            raise primary
        stdout.seek(0)
        stderr.seek(0)
        return subprocess.CompletedProcess(args, result, stdout.read(), stderr.read())
