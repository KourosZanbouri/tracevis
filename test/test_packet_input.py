"""The interactive packet-entry path (backlog §2.9).

`--packet-input-method interactive` had no coverage at all, and the fallback it
was supposed to have was unreachable: the stdlib console call sat after an
unconditional `raise NotImplementedError`, so anyone without IPython — which is
not in `requirements.txt`, and is exactly what a restricted environment is
likely to lack — was told the console was unsupported.
"""
import io
import subprocess
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

from scapy.all import IP, TCP

from utils.packet_input import BADPacketException, FirewallException, InputPacketInfo

IPYTHON_EMBED = "IPython.terminal.embed"


def without_ipython():
    """Make `from IPython.terminal.embed import ...` raise ImportError.

    A None entry in `sys.modules` is the documented way to block an import, and
    it works whether or not IPython is installed in the environment running the
    tests — which matters, because it is installed in this one.
    """
    return mock.patch.dict(sys.modules, {IPYTHON_EMBED: None})


def stdlib_console(assign=None):
    """Stand in for `code.interact`, optionally assigning `p` as a user would."""
    def _interact(banner=None, local=None):
        if assign is not None:
            local["p"] = assign
    return mock.patch("code.interact", side_effect=_interact)


def with_ipython(assign=None):
    """Patch in a stand-in for `InteractiveShellEmbed`.

    Returns the patch and a dict the fake fills in, so a test can assert on the
    banner and namespace the shell was handed.
    """
    record = {}

    class Shell:
        def __init__(self, banner1=None, user_ns=None):
            record["banner"] = banner1
            record["namespace"] = user_ns
            # Real IPython builds its own `user_ns` seeded from what it is
            # given, rather than writing through the caller's dict. Copying
            # here is what makes reading `ipshell.user_ns` back afterwards
            # load-bearing instead of incidental.
            self.user_ns = dict(user_ns)

        def __call__(self):
            if assign is not None:
                self.user_ns["p"] = assign

    patch = mock.patch.dict(
        sys.modules, {IPYTHON_EMBED: mock.Mock(InteractiveShellEmbed=Shell)})
    return patch, record


def read(**kwargs):
    with redirect_stdout(io.StringIO()) as out:
        packet = InputPacketInfo._read_interactive_packet(**kwargs)
    return packet, out.getvalue()


class TestStdlibConsoleFallback(unittest.TestCase):
    def test_a_packet_built_without_ipython_is_accepted(self):
        wanted = IP(dst="1.1.1.1") / TCP(dport=443)
        with without_ipython(), stdlib_console(assign=wanted):
            packet, _ = read()
        self.assertEqual(packet.dst, "1.1.1.1")

    def test_the_absence_of_ipython_is_reported_not_raised(self):
        """It used to raise NotImplementedError naming IPython as mandatory."""
        with without_ipython(), stdlib_console(assign=IP()):
            _, out = read()
        self.assertIn("IPython not found", out)

    def test_the_stdlib_console_actually_receives_the_banner(self):
        with without_ipython(), stdlib_console(assign=IP()) as interact:
            read()
        self.assertIn('variable "p"', interact.call_args.kwargs["banner"])


class TestInteractiveNamespace(unittest.TestCase):
    """`IP(dst=…)/TCP()` has to work as the banner says it does.

    The namespace was the reader's own `locals()` — `cls`, `show`, `banner` and
    the scapy *module* — so a user following the banner got a NameError and had
    to discover `scapy.all.IP(...)` instead.
    """

    def test_scapy_layers_are_in_scope(self):
        namespace = InputPacketInfo._interactive_namespace()
        for name in ("IP", "TCP", "UDP", "DNS", "Raw"):
            self.assertIn(name, namespace, name)

    def test_the_readers_own_locals_are_not(self):
        namespace = InputPacketInfo._interactive_namespace()
        for name in ("cls", "self", "show", "banner", "namespace"):
            self.assertNotIn(name, namespace, name)

    def test_a_packet_can_be_built_from_the_namespace_alone(self):
        namespace = InputPacketInfo._interactive_namespace()
        exec("p = IP(dst='9.9.9.9')/TCP(dport=53)", namespace)
        self.assertEqual(namespace["p"].dst, "9.9.9.9")

    def test_each_call_gets_a_fresh_namespace(self):
        """The console mutates it; leaking `p` between calls would silently
        reuse the previous run's packet."""
        first = InputPacketInfo._interactive_namespace()
        first["p"] = IP()
        self.assertNotIn("p", InputPacketInfo._interactive_namespace())


class TestPacketValidation(unittest.TestCase):
    def test_leaving_without_assigning_p_says_so(self):
        """This used to be a KeyError swallowed by a bare `except:` and
        reported as IPython being unavailable."""
        with without_ipython(), stdlib_console(assign=None):
            with self.assertRaises(BADPacketException) as caught:
                read()
        self.assertIn("assign the packet", str(caught.exception))

    def test_assigning_something_that_is_not_a_packet_says_so(self):
        with without_ipython(), stdlib_console(assign=42):
            with self.assertRaises(BADPacketException) as caught:
                read()
        self.assertIn("int", str(caught.exception))

    def test_a_non_ipv4_packet_is_still_rejected(self):
        with without_ipython(), stdlib_console(assign=TCP()):
            with self.assertRaises(BADPacketException) as caught:
                read()
        self.assertIn("IPv4", str(caught.exception))


class TestIPythonPathIsUnchanged(unittest.TestCase):
    """The fallback must not cost anything when IPython *is* installed."""

    def test_the_embedded_shell_is_used_when_available(self):
        patch, _ = with_ipython(assign=IP(dst="8.8.8.8"))
        with patch, mock.patch("code.interact") as interact:
            packet, _ = read()
        self.assertEqual(packet.dst, "8.8.8.8")
        interact.assert_not_called()

    def test_the_shell_gets_the_scapy_namespace_and_the_banner(self):
        patch, record = with_ipython(assign=IP())
        with patch:
            read()
        self.assertIn("IP", record["namespace"])
        self.assertIn('variable "p"', record["banner"])

    def test_a_shell_left_without_p_is_reported_the_same_way(self):
        patch, _ = with_ipython(assign=None)
        with patch, self.assertRaises(BADPacketException) as caught:
            read()
        self.assertIn("assign the packet", str(caught.exception))


if __name__ == "__main__":
    unittest.main()


class FakeIptables:
    """Stand-in for `subprocess.run(['iptables', ...])`.

    `fail` maps an iptables operation (`-A`, `-C`, `-D`, `-L`) to the exception
    that operation raises; anything else succeeds. Records the operations run.
    """

    def __init__(self, **fail):
        self.fail = {f"-{op}": exc for op, exc in fail.items()}
        self.ops = []

    def __call__(self, argv, **kwargs):
        op = argv[1]
        self.ops.append(op)
        if op in self.fail:
            raise self.fail[op]


def refused(op):
    return subprocess.CalledProcessError(1, ["iptables", op])


class TestFirewallRule(unittest.TestCase):
    """Backlog §3.4: bare `except:` around the RST-DROP rule.

    The add and remove paths caught their own "cannot be verified" exception
    and replaced it with a vaguer one, and a rule added but unverified was
    left installed, dropping every outgoing RST on the host until reboot.
    """

    def run_with(self, fake, method):
        with mock.patch("utils.packet_input.subprocess.run", fake):
            return getattr(InputPacketInfo, method)()

    def test_add_then_verify(self):
        fake = FakeIptables()
        self.assertTrue(self.run_with(fake, "_add_firewal_out_drop_rule"))
        self.assertEqual(fake.ops, ["-A", "-C"])

    def test_a_refused_add_says_so_and_keeps_the_cause(self):
        fake = FakeIptables(A=refused("-A"))
        with self.assertRaises(FirewallException) as caught:
            self.run_with(fake, "_add_firewal_out_drop_rule")
        self.assertIn("Adding DROP rule failed", str(caught.exception))
        self.assertIsInstance(caught.exception.__cause__,
                              subprocess.CalledProcessError)

    def test_an_unverified_add_is_reported_as_unverified(self):
        """This message was swallowed and replaced by "Adding ... failed"."""
        fake = FakeIptables(C=refused("-C"))
        with self.assertRaises(FirewallException) as caught:
            self.run_with(fake, "_add_firewal_out_drop_rule")
        self.assertEqual(str(caught.exception), "Added DROP rule cannot be verified")

    def test_an_unverified_add_is_taken_back_out(self):
        """`__exit__` never runs when `__enter__` raises."""
        fake = FakeIptables(C=refused("-C"))
        with self.assertRaises(FirewallException):
            self.run_with(fake, "_add_firewal_out_drop_rule")
        self.assertEqual(fake.ops, ["-A", "-C", "-D"])

    def test_a_failed_take_back_points_at_the_leftover_rule(self):
        fake = FakeIptables(C=refused("-C"), D=refused("-D"))
        with self.assertRaises(FirewallException) as caught:
            self.run_with(fake, "_add_firewal_out_drop_rule")
        self.assertIn("iptables -L OUTPUT", str(caught.exception))

    def test_a_failed_remove_points_at_the_leftover_rule(self):
        fake = FakeIptables(D=refused("-D"))
        with self.assertRaises(FirewallException) as caught:
            self.run_with(fake, "_remove_firewal_out_drop_rule")
        self.assertIn("Removing DROP rule failed", str(caught.exception))
        self.assertIn("iptables -L OUTPUT", str(caught.exception))

    def test_a_remove_that_leaves_the_rule_is_unverified(self):
        fake = FakeIptables()          # -D succeeds and -C still finds the rule
        with self.assertRaises(FirewallException) as caught:
            self.run_with(fake, "_remove_firewal_out_drop_rule")
        self.assertIn("cannot be verified", str(caught.exception))

    def test_a_clean_remove(self):
        fake = FakeIptables(C=refused("-C"))
        self.assertTrue(self.run_with(fake, "_remove_firewal_out_drop_rule"))

    def test_iptables_not_installed_is_not_present(self):
        fake = FakeIptables(L=FileNotFoundError("iptables"))
        self.assertFalse(self.run_with(fake, "_iptables_exists"))

    def test_an_unexpected_error_is_not_swallowed(self):
        """A bare `except:` turned a bug in this code into "iptables absent"."""
        fake = FakeIptables(L=RuntimeError("bug"))
        with self.assertRaises(RuntimeError):
            self.run_with(fake, "_iptables_exists")
