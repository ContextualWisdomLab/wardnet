"""Native finite fixture controls, not arbitrary process escape containment."""
import os
import pathlib
import shutil
import shlex
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import smoke_subtree


class SmokeSubtreeTests(unittest.TestCase):
    def setUp(self):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix='wardnet-subtree-', dir=os.environ.get('TMPDIR')))
        self.env = {'PATH': os.defpath, 'TMPDIR': str(self.root)}
        self.addCleanup(shutil.rmtree, self.root)

    def run_shell(self, script, timeout=6.0):
        return smoke_subtree.run(['bash', '-s'], input=script.encode(), env=self.env,
                                 timeout=timeout, root=self.root)

    def test_normal_nonzero_output_parity(self):
        result = self.run_shell("printf out; printf err >&2; exit 42\n")
        self.assertEqual((result.returncode, result.stdout, result.stderr), (42, b'out', b'err'))

    def test_timeout_propagates_after_settlement(self):
        with self.assertRaises(subprocess.TimeoutExpired) as raised:
            self.run_shell('sleep 30\n', timeout=.2)
        self.assertEqual(raised.exception.timeout, .2)
        self.assertEqual(smoke_subtree._unresolved, [])

    def test_leader_first_background_child_is_settled(self):
        marker = self.root / 'child'
        result = self.run_shell(f'sleep 30 &\nprintf "%s" "$!" > "{marker}"\nexit 0\n')
        self.assertEqual(result.returncode, 0)
        self.assert_absent(int(marker.read_text()))

    def test_term_ignoring_background_child_requires_escalation(self):
        marker = self.root / 'child'
        actor = self.root / 'ignore_term.py'
        actor.write_text('import os,pathlib,signal,sys,time\nsignal.signal(signal.SIGTERM,signal.SIG_IGN)\npathlib.Path(sys.argv[1]).write_text(str(os.getpid()))\ntime.sleep(30)\n')
        result = self.run_shell(f'{shlex.quote(sys.executable)} {shlex.quote(str(actor))} {shlex.quote(str(marker))} &\nwhile [ ! -s "{marker}" ]; do sleep .01; done\nexit 0\n')
        self.assertEqual(result.returncode, 0)
        self.assert_absent(int(marker.read_text()))

    def assert_absent(self, pid):
        with self.assertRaises(ProcessLookupError):
            os.kill(pid, 0)

    def test_unknown_settlement_retains_fixture(self):
        retained = None
        try:
            with self.assertRaises(smoke_subtree.SettlementError):
                with smoke_subtree.owned_root(prefix='wardnet-retain-', dir=self.root) as root:
                    retained = pathlib.Path(root)
                    raise smoke_subtree.SettlementError('synthetic uncertainty')
            assert retained is not None
            self.assertTrue(retained.is_dir())
        finally:
            if retained is not None:
                shutil.rmtree(retained)

    def test_normal_fixture_is_removed(self):
        with smoke_subtree.owned_root(prefix='wardnet-remove-', dir=self.root) as root:
            created = pathlib.Path(root)
            self.assertTrue(created.is_dir())
        self.assertFalse(created.exists())

    def test_signal_failure_still_attempts_wait_and_fences_next_launch(self):
        class Child:
            pid = 123456789
            waited = False
            def wait(self, timeout):
                self.waited = True
                return 0
        child = Child()
        previous = list(smoke_subtree._unresolved)
        try:
            with patch.object(smoke_subtree.subprocess, 'Popen', return_value=child), \
                    patch.object(smoke_subtree.selectors, 'DefaultSelector', side_effect=RuntimeError('primary')), \
                    patch.object(smoke_subtree.os, 'killpg', side_effect=PermissionError('signal')), \
                    patch.object(smoke_subtree, 'members', return_value=[]):
                with self.assertRaises(smoke_subtree.SettlementError) as raised:
                    self.run_shell('exit 0\n')
                self.assertIsInstance(raised.exception.__cause__, RuntimeError)
                self.assertTrue(child.waited)
                self.assertEqual(smoke_subtree._unresolved, [child])
                with self.assertRaises(smoke_subtree.SettlementError):
                    self.run_shell('exit 0\n')
        finally:
            smoke_subtree._unresolved[:] = previous


if __name__ == '__main__':
    unittest.main()
