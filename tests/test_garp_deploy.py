"""gb-garp nach dem Resume (Plan 2026-10-12, R7): Skript gegen Fake-Befehle im PATH, Unit und Installer."""

import os
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKRIPT = ROOT / "bin/gb-garp"

# ip zählt seine Aufrufe; ab dem FAKE_ADRESSE_AB-ten liegt FAKE_ADRESSE am Interface.
FAKE_IP = r'''#!/bin/bash
n=$(( $(cat "$GB_TEST/ip.n" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$GB_TEST/ip.n"
printf 'ip %s\n' "$*" >> "$GB_TEST/log"
if (( n <= ${FAKE_IP_FEHLER_BIS:-0} )); then
    echo 'Device does not exist.' >&2
    exit 1
fi
# Zwischen FAKE_LUECKE_VON und FAKE_LUECKE_BIS fehlt die Adresse wieder (NM baut eno1 nach dem Resume ab).
if (( n >= ${FAKE_LUECKE_VON:-0} && n <= ${FAKE_LUECKE_BIS:--1} )); then
    exit 0
fi
if (( n >= FAKE_ADRESSE_AB )); then
    printf '2: %s    inet %s/24 brd 192.0.2.255 scope global dynamic noprefixroute %s\\       valid_lft 86000sec preferred_lft 86000sec\n' "$6" "$FAKE_ADRESSE" "$6"
fi
'''
# arping und sleep protokollieren nur; FAKE_EXIT_ARPING setzt den Exit-Code von arping, ab dem
# FAKE_ARPING_OK_AB-ten Aufruf gelingt arping wieder.
FAKE = r'''#!/bin/bash
name=${0##*/}
printf '%s %s\n' "$name" "$*" >> "$GB_TEST/log"
n=$(( $(cat "$GB_TEST/$name.n" 2>/dev/null || echo 0) + 1 ))
echo "$n" > "$GB_TEST/$name.n"
(( n < ${FAKE_ARPING_OK_AB:-1000000} )) || exit 0
var=FAKE_EXIT_${name^^}
exit "${!var:-0}"
'''


def read(path):
    return (ROOT / path).read_text()


def direktiven(text):
    """Unit-Datei als {Schlüssel: [Werte]} ohne Kommentare."""
    result = {}
    for line in text.splitlines():
        if "=" in line and not line.startswith(("#", ";", "[")):
            key, value = line.split("=", 1)
            result.setdefault(key.strip(), []).append(value.strip())
    return result


class GarpSkriptTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)
        self.fake = self.base / "bin"
        self.fake.mkdir()
        for name, code in (("ip", FAKE_IP), ("arping", FAKE), ("sleep", FAKE)):
            (self.fake / name).write_text(code)
            (self.fake / name).chmod(0o755)

    def lauf(self, *args, adresse="192.0.2.10", ab=1, **env):
        umgebung = {"PATH": "%s:/usr/bin:/bin" % self.fake, "GB_TEST": str(self.base),
                    "FAKE_ADRESSE": adresse, "FAKE_ADRESSE_AB": str(ab)}
        umgebung.update(env)
        return subprocess.run([str(SKRIPT)] + list(args), env=umgebung, capture_output=True, text=True, timeout=30)

    def log(self):
        path = self.base / "log"
        return path.read_text().splitlines() if path.exists() else []

    GARP = ["arping -q -U -c 3 -w 4 -I eno1 192.0.2.10", "arping -q -A -c 2 -w 3 -I eno1 192.0.2.10"]
    # Zweite Runde nach NMs verspätetem Abbau der WOL-Karte und dem Link-Aufbau.
    NACHRUNDE = ["sleep 10", "ip -4 -o addr show dev eno1"] + GARP

    def test_ausfuehrbar_mit_strenger_shell(self):
        self.assertTrue(os.access(str(SKRIPT), os.X_OK))
        text = SKRIPT.read_text()
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertIn("\nset -euo pipefail\n", text)
        self.assertEqual(subprocess.run(["bash", "-n", str(SKRIPT)]).returncode, 0)

    def test_adresse_liegt_sofort_an(self):
        run = self.lauf("eno1", "192.0.2.10")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log(), ["ip -4 -o addr show dev eno1"] + self.GARP + self.NACHRUNDE)

    def test_adresse_kommt_spaet(self):
        run = self.lauf("eno1", "192.0.2.10", ab=4)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log(), ["ip -4 -o addr show dev eno1", "sleep 1"] * 3
                         + ["ip -4 -o addr show dev eno1"] + self.GARP + self.NACHRUNDE)

    def test_adresse_kommt_nie(self):
        run = self.lauf("eno1", "192.0.2.10", ab=1000)
        self.assertEqual(run.returncode, 1)
        self.assertIn("192.0.2.10", run.stderr)
        self.assertIn("eno1", run.stderr)
        log = self.log()
        # Höchstens 60 s warten: 61 Prüfungen, 60 Pausen, kein GARP ohne Adresse.
        self.assertEqual(log.count("ip -4 -o addr show dev eno1"), 61)
        self.assertEqual(log.count("sleep 1"), 60)
        self.assertFalse(any(x.startswith("arping") for x in log))

    def test_fremde_oder_aehnliche_adresse_zaehlt_nicht(self):
        for adresse in ("192.0.2.100", "192.0.2.1", "192.0.2.101", "203.0.113.10"):
            with self.subTest(adresse=adresse):
                (self.base / "log").unlink(missing_ok=True)
                (self.base / "ip.n").unlink(missing_ok=True)
                run = self.lauf("eno1", "192.0.2.10", adresse=adresse)
                self.assertEqual(run.returncode, 1)
                self.assertFalse(any(x.startswith("arping") for x in self.log()))

    def test_ip_fehler_heisst_noch_nicht(self):
        # Nach dem Resume kann das Interface kurz fehlen; das ist kein Abbruch.
        run = self.lauf("eno1", "192.0.2.10", FAKE_IP_FEHLER_BIS="2")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log().count("sleep 1"), 2)
        self.assertEqual(self.log()[-2:], self.GARP)

    def test_arping_fehler_heisst_noch_nicht(self):
        # NM baut die WOL-Karte erst nach dem Resume ab: arping endet dann mit 2 (ENETDOWN,
        # EADDRNOTAVAIL). Das ist kein Abbruch, gb-garp wartet und sendet erneut.
        run = self.lauf("eno1", "192.0.2.10", FAKE_EXIT_ARPING="2", FAKE_ARPING_OK_AB="3")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log(), ["ip -4 -o addr show dev eno1", self.GARP[0], "sleep 1"] * 2
                         + ["ip -4 -o addr show dev eno1"] + self.GARP + self.NACHRUNDE)

    def test_arping_scheitert_dauerhaft(self):
        run = self.lauf("eno1", "192.0.2.10", FAKE_EXIT_ARPING="2")
        self.assertEqual(run.returncode, 1)
        self.assertIn("eno1", run.stderr)
        log = self.log()
        self.assertEqual(log.count("sleep 1"), 60)
        self.assertEqual(log.count(self.GARP[0]), 61)
        self.assertNotIn(self.GARP[1], log)

    def test_adresse_verschwindet_und_kommt_wieder(self):
        # NM entfernt die Adresse nach dem ersten GARP und setzt sie nach dem DHCP neu: die zweite
        # Runde wartet darauf und meldet die Adresse erneut.
        run = self.lauf("eno1", "192.0.2.10", FAKE_LUECKE_VON="2", FAKE_LUECKE_BIS="4")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log(), ["ip -4 -o addr show dev eno1"] + self.GARP + ["sleep 10"]
                         + ["ip -4 -o addr show dev eno1", "sleep 1"] * 3
                         + ["ip -4 -o addr show dev eno1"] + self.GARP)

    def test_argumente_streng(self):
        for args in ((), ("eno1",), ("eno1", "192.0.2.10", "x"), ("", "192.0.2.10"), ("-I", "192.0.2.10"),
                     ("eno1;id", "192.0.2.10"), ("eno 1", "192.0.2.10"), ("a" * 16, "192.0.2.10"),
                     ("../x", "192.0.2.10"), ("eno1", "192.0.2.256"), ("eno1", "192.0.2.010"),
                     ("eno1", "192.0.2"), ("eno1", "192.0.2.10/24"), ("eno1", " 192.0.2.10"),
                     ("eno1", "a.b.c.d"), ("eno1", "192.0.2.10\n"), ("eno1", "-q"), ("eno1", "")):
            with self.subTest(args=args):
                run = self.lauf(*args)
                self.assertEqual(run.returncode, 2, run.stderr)
                self.assertIn("gb-garp", run.stderr)
                self.assertEqual(self.log(), [])
        self.assertEqual(self.lauf("enp3s0.100", "0.0.0.0", adresse="0.0.0.0").returncode, 0)
        self.assertEqual(self.lauf("eno1", "255.255.255.255", adresse="255.255.255.255").returncode, 0)

    def test_unit_argumente_bestehen_die_pruefung(self):
        argv = shlex.split(direktiven(read("deploy/vhost01/gb-garp.service"))["ExecStart"][0])
        self.assertEqual(argv, ["/usr/local/sbin/gb-garp", "eno1", "192.168.1.110"])
        run = self.lauf(*argv[1:], adresse="192.168.1.110")
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertEqual(self.log()[-1], "arping -q -A -c 2 -w 3 -I eno1 192.168.1.110")


class GarpUnitTests(unittest.TestCase):
    def test_nach_jedem_resume_nur_net_raw(self):
        text = read("deploy/vhost01/gb-garp.service")
        d = direktiven(text)
        erwartet = {"Type": ["oneshot"], "After": ["suspend.target"], "WantedBy": ["suspend.target"],
                    "ExecStart": ["/usr/local/sbin/gb-garp eno1 192.168.1.110"], "User": ["root"],
                    "CapabilityBoundingSet": ["CAP_NET_RAW"], "ProtectSystem": ["strict"],
                    "NoNewPrivileges": ["yes"], "PrivateTmp": ["yes"], "ProtectHome": ["yes"],
                    "TimeoutStartSec": ["90"]}
        for key, value in erwartet.items():
            self.assertEqual(d.get(key), value, key)
        self.assertEqual(sorted(d["RestrictAddressFamilies"][0].split()),
                         ["AF_INET", "AF_NETLINK", "AF_PACKET", "AF_UNIX"])
        # Ohne RemainAfterExit bleibt die Unit inaktiv und läuft beim nächsten Resume erneut.
        for key in ("RemainAfterExit", "Restart", "AmbientCapabilities", "ReadWritePaths"):
            self.assertNotIn(key, d)
        self.assertEqual(d["Environment"], ["PATH=/usr/sbin:/usr/bin"])


class SchlafUnitTests(unittest.TestCase):
    def test_ssh_braucht_keine_neuen_rechte(self):
        d = direktiven(read("deploy/vhost01/gb-schlaf.service"))
        self.assertIn("AF_INET", d["RestrictAddressFamilies"][0].split())
        self.assertEqual(d["ProtectHome"], ["read-only"])
        self.assertNotIn("/etc/greenbuddy", d["ReadWritePaths"][0].split())
        self.assertIn("UserKnownHostsFile", read("deploy/vhost01/gb-schlaf.service"))


class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def test_werkzeuge_und_starter(self):
        install = read("deploy/vhost01/installieren.sh")
        tools = re.search(r"for tool in ([^;]+); do", install).group(1).split()
        for tool in ("arping", "ip", "ssh"):
            self.assertIn(tool, tools)
        starter = re.search(r"for name in ([^;]+); do starter", install).group(1).split()
        self.assertIn("gb-garp", starter)
        # rollback() kennt nur Dauerdienste als Unit; gb-garp steht als Datei im Manifest.
        self.assertNotIn("unit vhost01 gb-garp.service", install)
        self.assertEqual(subprocess.run(["bash", "-n", str(ROOT / "deploy/vhost01/installieren.sh")]).returncode, 0)

    def installer(self, enabled=False):
        """installieren.sh mit protokollierenden Attrappen statt install-lib.sh und systemctl."""
        log = self.base / "log"
        stubs = '''
protokoll() { printf '%s\\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
die() { protokoll "die $*"; exit 1; }
root_only() { :; }
command() { [[ $1 = -v ]] && return 0; builtin command "$@"; }
begin_install() { protokoll "begin_install $*"; }
new_user() { protokoll "new_user $*"; }
install_package() { protokoll install_package; }
starter() { protokoll "starter $*"; }
make_dir() { protokoll "make_dir $*"; }
put_file() { protokoll "put_file ${1#"$PACKAGE"/} $2 $3"; }
unit() { protokoll "unit $*"; }
record() { protokoll "record $*"; }
finish_install() { protokoll finish_install; }
systemd-tmpfiles() { protokoll "systemd-tmpfiles $*"; }
systemctl() {
    protokoll "systemctl $*"
    if [[ $1 = is-enabled ]]; then ''' + ("echo enabled" if enabled else "return 1") + '''; fi
}
'''
        code = read("deploy/vhost01/installieren.sh")
        zeile = 'source "$PACKAGE/deploy/install-lib.sh"'
        self.assertEqual(code.count(zeile), 1)
        ziel = self.base / "paket/deploy/vhost01/installieren.sh"
        ziel.parent.mkdir(parents=True)
        ziel.write_text(code.replace(zeile, stubs))
        run = subprocess.run(["bash", str(ziel)], capture_output=True, text=True, timeout=10)
        return run, log.read_text().splitlines()

    def test_installer_ablauf(self):
        run, log = self.installer()
        self.assertEqual(run.returncode, 0, run.stderr + "\n".join(log))
        schritte = ["systemctl is-enabled gb-garp.service", "begin_install vhost01", "starter gb-garp",
                    "put_file deploy/vhost01/gb-garp.service /etc/systemd/system/gb-garp.service 0644",
                    "systemctl daemon-reload",
                    "record file /etc/systemd/system/suspend.target.wants/gb-garp.service",
                    "systemctl enable gb-garp.service", "finish_install"]
        indizes = [log.index(s) for s in schritte]
        self.assertEqual(indizes, sorted(indizes), log)
        # Kein Dienststart beim Installieren; gb-garp läuft erst nach dem nächsten Resume.
        self.assertFalse(any(x.startswith(("systemctl start", "systemctl restart")) or "--now" in x for x in log))

    def test_installer_bricht_bei_aktivierter_unit_ab(self):
        run, log = self.installer(enabled=True)
        self.assertNotEqual(run.returncode, 0)
        self.assertIn("die GB2-Dienst bereits aktiviert: gb-garp.service", log)
        # Abbruch vor begin_install: nichts angefasst, kein Rückbau nötig.
        self.assertNotIn("begin_install vhost01", log)

    def library(self):
        code = read("deploy/install-lib.sh")
        # Ausschließlich im Testprozess auf lokale Pfade umleiten.
        for path in ("/root/greenbuddy2", "/etc/greenbuddy", "/var/lib/greenbuddy-ssh",
                     "/var/lib/greenbuddy", "/var/log/greenbuddy", "/run/greenbuddy"):
            code = code.replace(path, str(self.base) + path)
        return code + "\nroot_only() { :; }\nlabel() { :; }\n"

    def test_rueckbau_entfernt_skript_unit_und_link(self):
        skript = self.base / "usr/local/sbin/gb-garp"
        unit = self.base / "etc/systemd/system/gb-garp.service"
        link = self.base / "etc/systemd/system/suspend.target.wants/gb-garp.service"
        for path in (skript, unit, link):
            path.parent.mkdir(parents=True, exist_ok=True)
        skript.write_text("#!/bin/bash\n")
        unit.write_text("[Unit]\n")
        link.symlink_to("../gb-garp.service")
        root = self.base / "root/greenbuddy2"
        root.mkdir(parents=True)
        manifest = root / "manifest.tsv"
        manifest.write_text("host\tvhost01\nfile\t%s\nfile\t%s\nfile\t%s\n" % (skript, unit, link))
        manifest.chmod(0o600)
        code = self.library() + '''
stat() { if [[ $1 = -c && $2 = %u ]]; then printf '0\\n'; else command stat "$@"; fi; }
systemctl() { [[ $1 != is-active ]]; }
rollback
'''
        run = subprocess.run(["bash"], input=code, text=True, capture_output=True, timeout=10)
        self.assertEqual(run.returncode, 0, run.stderr)
        for path in (skript, unit, link):
            self.assertFalse(os.path.lexists(str(path)), path)


if __name__ == "__main__":
    unittest.main()
