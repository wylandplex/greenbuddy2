"""Deployment-Verträge und Bash-Funktionen mit lokalen Pfaden/Fake-Werkzeugen."""

import json
import re
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text()


class DeploymentReviewTests(unittest.TestCase):
    def test_w1_private_logverzeichnisse(self):
        install = read("deploy/vhost01/installieren.sh")
        self.assertIn("make_dir /var/log/greenbuddy 0755", install)
        self.assertIn("make_dir /var/log/greenbuddy/mitschnitt 0700 gb-mitschnitt gb-mitschnitt", install)
        unit = read("deploy/vhost01/gb-mitschnitt.service")
        # b6: dazu nur das eigene Unterverzeichnis für die Legitim-Datei, nie /run/greenbuddy als Ganzes.
        self.assertEqual(re.search(r"^ReadWritePaths=(.*)$", unit, re.M).group(1).split(),
                         ["/var/log/greenbuddy/mitschnitt", "/run/greenbuddy/legitim"])
        self.assertEqual(json.loads(read("deploy/vhost01/mitschnitt.example.json"))["log"],
                         "/var/log/greenbuddy/mitschnitt/mitschnitt.jsonl")
        proxy = read("deploy/proxy01/installieren.sh")
        self.assertIn("make_dir /var/log/greenbuddy 0755", proxy)
        self.assertIn("make_dir /run/greenbuddy/log 0700 gb-stellvertreter gb-stellvertreter", proxy)

    def test_w3_exec_stop_post_raeumt_auf(self):
        self.assertIn("ExecStopPost=/usr/local/sbin/gb-stellvertreter --aufraeumen",
                      read("deploy/proxy01/gb-stellvertreter.service"))

    def test_w5_nft_optional_arping_entfaellt_und_nftables_boot(self):
        install = read("deploy/proxy01/installieren.sh")
        required = re.search(r"for tool in ([^;]+); do", install).group(1).split()
        self.assertNotIn("nft", required)
        # ARP-Frames baut gb-stellvertreter selbst; arping fehlt auf proxy01 (Plan Abschnitt 2).
        self.assertNotIn("arping", install)
        for name in ("uebernahme.py", "stellvertreter.py"):
            self.assertNotIn('"arping"', read("greenbuddy2/" + name))
        self.assertIn("Warnung: nft fehlt", install)
        self.assertIn("systemctl disable --now nftables", read("README.md"))

    def test_w6_tcpdump_ohne_promisc_und_nur_net_raw(self):
        self.assertIn('"-p"', read("greenbuddy2/mitschnitt.py"))
        unit = read("deploy/vhost01/gb-mitschnitt.service")
        self.assertNotIn("CAP_NET_ADMIN", unit)
        self.assertIn("CapabilityBoundingSet=CAP_NET_RAW\n", unit)

    def test_k4_kein_ptrace(self):
        self.assertNotIn("CAP_SYS_PTRACE", read("deploy/vhost01/gb-schlaf.service"))

    def test_b2_schlaf_unit_knapp(self):
        unit = read("deploy/vhost01/gb-schlaf.service")
        caps = re.search(r"^CapabilityBoundingSet=(.*)$", unit, re.M).group(1).split()
        # logind erlaubt "systemctl suspend" einem Aufrufer mit CAP_SYS_BOOT ohne polkit-Agent.
        self.assertEqual(sorted(caps), ["CAP_DAC_READ_SEARCH", "CAP_SETGID", "CAP_SETUID", "CAP_SYS_BOOT"])
        # Der eigentliche reboot/kexec-Systemaufruf bleibt gesperrt.
        self.assertRegex(unit, r"(?m)^SystemCallFilter=~reboot kexec_load kexec_file_load$")
        self.assertRegex(unit, r"(?m)^SystemCallErrorNumber=EPERM$")
        # rtcwake nutzt das RTC_WKALM_SET-ioctl auf /dev/rtc0, kein Schreiben in /sys.
        self.assertNotIn("/sys", re.search(r"^ReadWritePaths=(.*)$", unit, re.M).group(1))
        directives = "\n".join(line for line in unit.splitlines() if not line.startswith("#"))
        for text in ("CAP_SYS_ADMIN", "CAP_WAKE_ALARM", "ProtectClock", "PrivateDevices", "DevicePolicy"):
            self.assertNotIn(text, directives)
        self.assertIn("ProtectKernelTunables=yes", unit)
        self.assertIn("NoNewPrivileges=yes", unit)
        self.assertIn("/var/lib/greenbuddy", unit)
        self.assertFalse((ROOT / "deploy/vhost01/gb-schlaf-schatten.service").exists())

    def test_b2_installer_vhost01(self):
        install = read("deploy/vhost01/installieren.sh")
        tools = re.search(r"for tool in ([^;]+); do", install).group(1).split()
        for tool in ("rtcwake", "busctl", "systemctl"):
            self.assertIn(tool, tools)
        # ethtool bräuchte für Wake-on CAP_NET_ADMIN; geprüft wird power/wakeup in sysfs.
        self.assertNotIn("ethtool", tools)
        self.assertIn("unit vhost01 gb-schlaf.service", install)
        self.assertNotIn("gb-schlaf-schatten", install)
        lib = read("deploy/install-lib.sh")
        case = re.search(r"case \$value in ([^)]+)\)", lib).group(1)
        self.assertIn("gb-schlaf.service", case.split("|"))
        self.assertIn("gb-schlaf-schatten.service", case.split("|"))

    def test_b2_gb_wecken_auf_proxy01(self):
        install = read("deploy/proxy01/installieren.sh")
        self.assertIn("starter gb-wecken", install)
        self.assertIn('put_file "$PACKAGE/deploy/proxy01/wecken.example.json" /etc/greenbuddy/wecken.json 0644', install)
        starter = read("bin/gb-wecken")
        self.assertIn("from greenbuddy2.wecken import main", starter)
        self.assertTrue(starter.startswith("#!/usr/bin/python3 -I"))

    def test_b2_doku(self):
        doc = read("README.md")
        for text in ("2.0.0-beta.2", "/etc/greenbuddy/aus", "gb-wecken", "Notfall", '"mode": "aktiv"',
                     "dependencies_verified", "raid_degradiert_erlaubt", "bandbreite_schwelle_bytes"):
            self.assertIn(text, doc)
        self.assertIn("## v2.0.0-beta.2", read("CHANGELOG.md"))

    def test_b4_doku(self):
        changelog = read("CHANGELOG.md")
        self.assertLess(changelog.index("## v2.0.0-beta.4"), changelog.index("## v2.0.0-beta.3"))
        for text in ("verbindung_ruhe_ports", "verbindung_ruhe_sekunden", "verbindung_ruhe_bytes", "lastrcv",
                     "bytes_acked"):
            self.assertIn(text, read("README.md"))

    def test_b5_doku(self):
        doc = read("README.md")
        changelog = read("CHANGELOG.md")
        self.assertLess(changelog.index("## v2.0.0-beta.5"), changelog.index("## v2.0.0-beta.4"))
        eintrag = changelog.split("## v2.0.0-beta.5", 1)[1].split("\n## ", 1)[0]
        for text in ("schlafe-jetzt", "anmelden-abbruch", "stellvertreter_pflicht", "gb-garp", "--probe",
                     "arp_ignore", "32414", "weckung.weg", "GB_NETNS=1"):
            self.assertIn(text, eintrag)
        # Der Phantom-Test ist ersetzt; das Register meldet nicht mehr immer bereit=false.
        self.assertNotIn("## Phantom-IP-Test", doc)
        self.assertNotIn("phantom_test=true", doc)
        self.assertNotIn("keinen automatischen Weckaufrufer", doc)
        self.assertIn("## Weckweg über proxy01", doc)
        self.assertIn("## Probe ohne Produktions-IP (proxy01)", doc)
        weg = doc.split("## Weckweg über proxy01", 1)[1].split("\n## ", 1)[0]
        for text in ("warte_stille", "uebernommen", "wecken", "lebendprobe_s", "GARP", "wan_quelle_h",
                     "liste_h", "lease_unklar", "freigabe_unvollstaendig", "plex_hash", "minecraft_whitelist",
                     "wan_name", "quellen_ports"):
            self.assertIn(text, weg)
        install = doc.split("## Installation", 1)[1].split("\n## ", 1)[0]
        # Ausroll-Reihenfolge: proxy01 vor vhost01, sonst schläft vhost01 nicht.
        reihenfolge = install.split("### Ausrollen von beta.5: erst proxy01, dann vhost01", 1)[1]
        self.assertLess(reihenfolge.index("1. proxy01"), reihenfolge.index("2. vhost01"))
        for text in ("ufw allow from 192.168.1.0/24 to any port 32414 proto udp", "60-greenbuddy-arp.conf",
                     "stellvertreter_pflicht", "Register().status()"):
            self.assertIn(text, install)
        self.assertIn("sudo gb-stellvertreter --probe 300", doc)
        self.assertIn("sudo gb-stellvertreter --aufraeumen", doc)
        abweichung = doc.split("## Abweichungen von der Spec", 1)[1].split("\n## ", 1)[0]
        for text in ("ListenAddress", "IPv6", "Limits liegen nur im Speicher"):
            self.assertIn(text, abweichung)
        tests = doc.split("## Tests und noch zu bestätigende Tatsachen", 1)[1]
        for text in ("GB_NETNS=1", "nft 1.0.2", "Freigabelatenz auf dem Pi", "iputils 20210202"):
            self.assertIn(text, tests)

    def test_b6_doku(self):
        doc = read("README.md")
        self.assertTrue(doc.startswith("# GreenBuddy 2 · v2.0.0-beta.6\n"))
        changelog = read("CHANGELOG.md")
        self.assertLess(changelog.index("## v2.0.0-beta.6"), changelog.index("## v2.0.0-beta.5"))
        eintrag = changelog.split("## v2.0.0-beta.6", 1)[1].split("\n## ", 1)[0]
        for text in ("/run/greenbuddy/legitim/vhost01.json", "wan_filter", "legitim_quellen", "legitim_ttl_s",
                     "legitim_max_alter_s", "verbindungen_wan_ignoriert", "verbindungen_haarnadel", "8880",
                     "eigene_wan_ip", "sni_label", "wan.py"):
            self.assertIn(text, eintrag)
        self.assertIn("## Wachseite filtert Spam (vhost01)", doc)
        wache = doc.split("## Wachseite filtert Spam (vhost01)", 1)[1].split("\n## ", 1)[0]
        for text in ("/run/greenbuddy/legitim/vhost01.json", '"version"', '"zeit"', '"ttl_s"', '"quellen"',
                     '"eigene_wan_ip"', "legitim_ttl_s", "legitim_max", "wan_name", "legitim_max_alter_s",
                     "wan_filter", "legitim_quellen", '"fehlt"', '"veraltet"', '"zukunft"', '"ungueltig"', '"aus"',
                     "verbindungen_wan_ignoriert", "verbindungen_haarnadel", "legitim_schreibfehler",
                     "CAP_DAC_READ_SEARCH", "0700", "Haarnadel", "8880", "::ffff:", "IPv6"):
            self.assertIn(text, wache)
        install = doc.split("## Installation", 1)[1].split("\n## ", 1)[0]
        ausrollen = install.split("### Ausrollen von beta.6: nur vhost01", 1)[1]
        for text in ("rueckbau.sh", "installieren.sh", "/run/greenbuddy/legitim", "mitschnitt.json.bak-gb2",
                     "wan_name", '"legitim": "ok"', "verbindungen_wan_ignoriert"):
            self.assertIn(text, ausrollen)
        # Aufbau: der Mitschnitt schreibt jetzt eine Datei, die gb-schlaf liest.
        self.assertIn("legitim", doc.split("## Aufbau und Verhalten", 1)[1].split("\n## ", 1)[0])

    def test_b5_doku_ohne_hostdaten(self):
        # Repo ist öffentlich lesbar gedacht: WAN-Adressen nur aus Doku-Netzen, kein Plex-Hash, kein DDNS-Name.
        import ipaddress
        erlaubt = [ipaddress.ip_network(n) for n in ("192.168.1.0/24", "10.0.0.0/24", "192.0.2.0/24",
                                                     "198.51.100.0/24", "203.0.113.0/24", "0.0.0.0/32",
                                                     "255.255.255.255/32", "239.0.0.250/32", "127.0.0.1/32")]
        for name in ("README.md", "CHANGELOG.md"):
            text = read(name)
            for adresse in re.findall(r"(?<![\d.])\d{1,3}(?:\.\d{1,3}){3}(?![\d.])", text):
                self.assertTrue(any(ipaddress.ip_address(adresse) in netz for netz in erlaubt), (name, adresse))
            self.assertNotRegex(text.lower(), r"\.ddns\.|dyndns|duckdns")
            for treffer in re.findall(r"([0-9A-Za-z<>_-]+)\.plex\.direct", text):
                self.assertIn(treffer, ("<hash>",), (name, treffer))

    def test_b3_doku(self):
        changelog = read("CHANGELOG.md")
        self.assertIn("## v2.0.0-beta.3", changelog)
        self.assertLess(changelog.index("## v2.0.0-beta.3"), changelog.index("## v2.0.0-beta.2"))
        # Kurze Jobs: die Regel steht dort, wo die Ruhezeit beschrieben ist.
        self.assertIn("zwei aufeinanderfolgenden Runden", read("README.md"))

    def test_review_0710_aktivierungsschritte(self):
        doc = read("README.md")
        section = doc.split("## Aktiver Schlaf (vhost01)", 1)[1].split("\n## ", 1)[0]
        # Vor "mode": "aktiv": Gen-0-Schläfer stilllegen und RTC-Weckung begleitet belegen.
        schritte = section.split("Aktivieren (nach der Schattenwoche)", 1)[1]
        for text in ("systemctl mask auto-sleep.timer auto-sleep.service delay-after-suspend.service",
                     "/sys/class/rtc/rtc0/device/power/wakeup", "wakeup_count",
                     "rtcwake -m no -t $(( $(date +%s)+600 )) && systemctl suspend",
                     '"geweckt_durch": "rtc"'):
            self.assertIn(text, schritte)
        self.assertLess(schritte.index("systemctl mask"), schritte.index('"mode": "aktiv"'))
        self.assertLess(schritte.index("rtcwake -m no -t $(("), schritte.index('"mode": "aktiv"'))
        for text in ("schlaf-takt.json", "rtc_weckquelle_aus", "fremder_schlafdienst", "445", "8081",
                     "verbindung_ausnahmen", "sitzung_closing", "run-*.scope", "suspend_unklar"):
            self.assertIn(text, section)
        for text in ("transient_benutzer", "smb.service", "sitzung_closing", "verbindung_ausnahmen"):
            self.assertIn(text, doc.split("## Aufbau und Verhalten", 1)[1].split("\n## ", 1)[0])
        self.assertIn("Review 07.10.26", read("CHANGELOG.md"))

    def test_k5_werkzeugliste_ohne_runuser(self):
        self.assertNotIn("runuser", read("deploy/vhost01/installieren.sh"))

    def test_k6_tmpfs_rotation_und_zustand(self):
        cfg = json.loads(read("deploy/proxy01/stellvertreter.example.json"))
        self.assertEqual(cfg["log"], "/run/greenbuddy/log/stellvertreter.jsonl")
        self.assertTrue(cfg["stellvertretung"]["zustand"].startswith("/run/greenbuddy/stellvertreter/"))
        self.assertTrue(cfg["stellvertretung"]["status"].startswith("/run/greenbuddy/status/"))
        unit = read("deploy/proxy01/gb-stellvertreter.service")
        self.assertNotIn("/var/log/greenbuddy", unit)
        self.assertNotIn("/var/lib/greenbuddy/stellvertreter", unit)
        self.assertIn("/run/greenbuddy/log", unit)
        self.assertIn("/run/greenbuddy/stellvertreter", unit)
        tmpfiles = read("deploy/proxy01/tmpfiles.conf")
        self.assertIn("d /run/greenbuddy/log 0700 gb-stellvertreter gb-stellvertreter", tmpfiles)
        code = read("greenbuddy2/stellvertreter.py")
        self.assertRegex(code, r"limit=2\s*\*\s*1024\s*\*\s*1024")
        self.assertIn("rotations=3", code)
        self.assertIn("heartbeat_seconds=3600", code)

    def test_b5_stellvertreter_unit(self):
        unit = read("deploy/proxy01/gb-stellvertreter.service")
        self.assertEqual(re.search(r"^ReadWritePaths=(.*)$", unit, re.M).group(1).split(),
                         ["/run/greenbuddy/log", "/run/greenbuddy/stellvertreter", "/run/greenbuddy/status"])
        families = re.search(r"^RestrictAddressFamilies=(.*)$", unit, re.M).group(1).split()
        self.assertEqual(sorted(families), ["AF_INET", "AF_NETLINK", "AF_PACKET", "AF_UNIX"])
        caps = re.search(r"^AmbientCapabilities=(.*)$", unit, re.M).group(1).split()
        self.assertEqual(sorted(caps), ["CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"])
        for text in ("User=gb-stellvertreter", "NoNewPrivileges=yes", "ProtectSystem=strict", "MemoryMax=300M",
                     "ExecStopPost=/usr/local/sbin/gb-stellvertreter --aufraeumen --config "
                     "/etc/greenbuddy/stellvertreter.json"):
            self.assertIn(text, unit)

    def test_b5_sysctl_tmpfiles_installer(self):
        sysctl = read("deploy/proxy01/60-greenbuddy-arp.conf")
        rows = dict(line.replace(" ", "").split("=") for line in sysctl.splitlines()
                    if line.strip() and not line.startswith("#"))
        self.assertEqual(rows, {"net.ipv4.conf.all.arp_ignore": "1", "net.ipv4.conf.all.arp_announce": "2",
                                "net.ipv4.conf.eth0.arp_ignore": "1", "net.ipv4.conf.eth0.arp_announce": "2"})
        tmpfiles = read("deploy/proxy01/tmpfiles.conf")
        self.assertIn("d /run/greenbuddy/status 2750 gb-stellvertreter gb-register -", tmpfiles)
        install = read("deploy/proxy01/installieren.sh")
        for text in ('put_file "$PACKAGE/deploy/proxy01/60-greenbuddy-arp.conf" /etc/sysctl.d/60-greenbuddy-arp.conf 0644',
                     "sysctl --load=/etc/sysctl.d/60-greenbuddy-arp.conf",
                     "migrate_dir /var/lib/greenbuddy gb-register:gb-register:755 2750 gb-register gb-stellvertreter",
                     "make_dir /var/lib/greenbuddy 2750 gb-register gb-stellvertreter",
                     "make_dir /run/greenbuddy/status 2750 gb-stellvertreter gb-register",
                     "port 32414 proto udp"):
            self.assertIn(text, install)
        # Konten vor der Migration, Migration vor make_dir; sysctl erst nach dem Ablegen der Datei.
        self.assertLess(install.index("new_user gb-stellvertreter"), install.index("migrate_dir /var/lib/greenbuddy"))
        self.assertLess(install.index("migrate_dir /var/lib/greenbuddy"),
                        install.index("make_dir /var/lib/greenbuddy 2750"))
        self.assertLess(install.index("/etc/sysctl.d/60-greenbuddy-arp.conf 0644"), install.index("sysctl --load"))
        lib = read("deploy/install-lib.sh")
        case = re.search(r"gb2_dir\(\) \{\n    case \$1 in\n        ([^)]+)\)", lib).group(1).split("|")
        self.assertIn("/run/greenbuddy/status", case)

    def test_b5_beispielkonfig_gueltig_ohne_hostdaten(self):
        from greenbuddy2.konfig import stellvertretung
        text = read("deploy/proxy01/stellvertreter.example.json")
        sv = stellvertretung(json.loads(text))
        self.assertEqual(list(sv["hosts"]), ["vhost01"])
        self.assertEqual(sv["wan_name"], "")
        self.assertEqual(sv["hosts"]["vhost01"]["quellen_ports"], {8443: ["203.0.113.10"]})
        # Repo ist öffentlich: nur LAN, VPN und Doku-Netze als Adressen, kein Plex-Hash, kein WAN-Name.
        import ipaddress
        erlaubt = [ipaddress.ip_network(n) for n in ("192.168.1.0/24", "10.0.0.0/24", "192.0.2.0/24",
                                                     "198.51.100.0/24", "203.0.113.0/24")]
        adressen = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", text)
        self.assertTrue(adressen)
        for adresse in adressen:
            self.assertTrue(any(ipaddress.ip_address(adresse) in netz for netz in erlaubt), adresse)
        self.assertNotIn("plex.direct", text)

    def test_b6_legitim_verzeichnis(self):
        # gb-mitschnitt schreibt nur /run/greenbuddy/legitim; gb-schlaf (root) liest mit CAP_DAC_READ_SEARCH.
        tmpfiles = read("deploy/vhost01/tmpfiles.conf")
        self.assertIn("d /run/greenbuddy 0755 root root -", tmpfiles)
        self.assertIn("d /run/greenbuddy/legitim 0700 gb-mitschnitt gb-mitschnitt -", tmpfiles)
        install = read("deploy/vhost01/installieren.sh")
        self.assertIn("make_dir /run/greenbuddy/legitim 0700 gb-mitschnitt gb-mitschnitt", install)
        self.assertLess(install.index("new_user gb-mitschnitt"), install.index("make_dir /run/greenbuddy/legitim"))
        self.assertLess(install.index("make_dir /run/greenbuddy 0755"), install.index("make_dir /run/greenbuddy/legitim"))
        lib = read("deploy/install-lib.sh")
        case = re.search(r"gb2_dir\(\) \{\n    case \$1 in\n        ([^)]+)\)", lib).group(1).split("|")
        self.assertIn("/run/greenbuddy/legitim", case)
        schlaf = read("deploy/vhost01/gb-schlaf.service")
        self.assertIn("/run/greenbuddy", re.search(r"^ReadWritePaths=(.*)$", schlaf, re.M).group(1).split())
        self.assertIn("CAP_DAC_READ_SEARCH", re.search(r"^CapabilityBoundingSet=(.*)$", schlaf, re.M).group(1).split())
        schlaf_cfg = json.loads(read("deploy/vhost01/schlaf.example.json"))
        self.assertTrue(schlaf_cfg["legitim"].startswith("/run/greenbuddy/legitim/"))

    def test_k7c_spec_abweichung_begruendet(self):
        doc = read("README.md")
        self.assertIn("## Abweichungen von der Spec", doc)
        section = doc.split("## Abweichungen von der Spec", 1)[1].split("\n## ", 1)[0]
        for text in ("25565", "lazymc", "06.10.", "7 Verbindungen", "3 WAN-Adressen"):
            self.assertIn(text, section)


class BashReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def library(self):
        code = read("deploy/install-lib.sh")
        # Ausschließlich im Testprozess auf lokale Pfade umleiten.
        for path in ("/root/greenbuddy2", "/etc/greenbuddy", "/var/lib/greenbuddy-ssh",
                     "/var/lib/greenbuddy", "/var/log/greenbuddy", "/run/greenbuddy"):
            code = code.replace(path, str(self.base) + path)
        return code + "\nroot_only() { :; }\nlabel() { :; }\n"

    def shell(self, code):
        return subprocess.run(["bash"], input=code, text=True, capture_output=True, timeout=5)

    def test_w4_rueckbau_sichert_json_und_daten(self):
        config = self.base / "etc/greenbuddy/schlaf.json"
        data = self.base / "var/lib/greenbuddy"
        root = self.base / "root/greenbuddy2"
        config.parent.mkdir(parents=True)
        data.mkdir(parents=True)
        root.mkdir(parents=True)
        config.write_text('{"angepasst":true}')
        (data / "register.json").write_text('{"behalten":true}')
        manifest = root / "manifest.tsv"
        manifest.write_text("file\t%s\ndir\t%s\n" % (config, data))
        manifest.chmod(0o600)
        code = self.library() + '''
stat() { if [[ $1 = -c && $2 = %u ]]; then printf '0\n'; else command stat "$@"; fi; }
systemctl() { [[ $1 != is-active ]]; }
rollback
'''
        run = self.shell(code)
        self.assertEqual(run.returncode, 0, run.stderr)
        backups = list(config.parent.glob("schlaf.json.bak-gb2-*"))
        self.assertEqual(len(backups), 1, run.stdout)
        self.assertEqual(backups[0].read_text(), '{"angepasst":true}')
        backups = list(data.parent.glob("greenbuddy.bak-gb2-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual((backups[0] / "register.json").read_text(), '{"behalten":true}')

    def test_w4_verwaiste_besitzer_nur_feste_gb2_pfade(self):
        directory = self.base / "var/lib/greenbuddy/stellvertreter"
        directory.mkdir(parents=True)
        log = self.base / "chown.log"
        code = self.library() + '''
record() { :; }
getent() { return 2; }
stat() { case "$2" in %u) printf '42424\n';; %g) printf '43434\n';; *) command stat "$@";; esac; }
chown() { printf '%s\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
make_dir ''' + shlex.quote(str(directory)) + ''' 0700 gb-stellvertreter gb-stellvertreter
'''
        run = self.shell(code)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("gb-stellvertreter:gb-stellvertreter", log.read_text())
        foreign = self.base / "fremd"
        foreign.mkdir()
        run = self.shell(code.rsplit("make_dir ", 1)[0] + "make_dir %s 0700 gb-stellvertreter gb-stellvertreter\n" % shlex.quote(str(foreign)))
        self.assertNotEqual(run.returncode, 0)

    def test_b6_legitim_verzeichnis_mit_verwaistem_besitzer(self):
        directory = self.base / "run/greenbuddy/legitim"
        directory.mkdir(parents=True)
        log = self.base / "chown.log"
        code = self.library() + '''
record() { :; }
getent() { return 2; }
stat() { case "$2" in %u) printf '42424\n';; %g) printf '43434\n';; *) command stat "$@";; esac; }
chown() { printf '%s\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
make_dir ''' + shlex.quote(str(directory)) + ''' 0700 gb-mitschnitt gb-mitschnitt
'''
        run = self.shell(code)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("gb-mitschnitt:gb-mitschnitt", log.read_text())

    def test_b5_migration_der_b2_verzeichnisse(self):
        directory = self.base / "var/lib/greenbuddy"
        directory.mkdir(parents=True)
        log = self.base / "migration.log"
        def run(rechte):
            code = self.library() + '''
stat() { if [[ $1 = -c && $2 = %U:%G:%a ]]; then printf '%s\\n' ''' + shlex.quote(rechte) + '''; else command stat "$@"; fi; }
chgrp() { printf 'chgrp %s\\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
chmod() { printf 'chmod %s\\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
migrate_dir ''' + shlex.quote(str(directory)) + ''' gb-register:gb-register:755 2750 gb-register gb-stellvertreter
'''
            return self.shell(code)
        result = run("gb-register:gb-register:755")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(log.read_text().splitlines(),
                         ["chgrp -- gb-stellvertreter " + str(directory), "chmod 2750 " + str(directory)])
        log.unlink()
        for rechte in ("gb-register:gb-stellvertreter:2750", "root:root:755"):
            with self.subTest(rechte=rechte):
                result = run(rechte)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(log.exists())

    def test_w4_backupfehler_stoppt_rueckbau(self):
        path = self.base / "daten"
        path.write_text("behalten")
        code = self.library() + '''
mv() { return 7; }
if sichern ''' + shlex.quote(str(path)) + ''' probe; then exit 1; fi
'''
        run = self.shell(code)
        self.assertEqual(run.returncode, 0, run.stdout)
        self.assertEqual(path.read_text(), "behalten")

    def test_k7b_trust_update_nur_am_ende(self):
        log = self.base / "trust.log"
        code = self.library() + '''
record() { :; }
systemctl() { return 0; }
trust_exists() { return 1; }
fapolicyd-cli() { printf '%s\n' "$*" >> ''' + shlex.quote(str(log)) + '''; }
trust_file /synthetisch/eins
trust_file /synthetisch/zwei
finish_install
'''
        run = self.shell(code)
        self.assertEqual(run.returncode, 0, run.stderr)
        lines = log.read_text().splitlines()
        self.assertEqual(lines.count("--update"), 1)
        self.assertEqual(lines[-1], "--update")

    def cleanup_run(self, dependency=False, config_reader=False, unit_files_timeout=False):
        config = self.base / "opt/greenbuddy/config.yaml"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.write_text("synthetisch: true\n")
        config.chmod(0o644)
        command_log = self.base / "commands"
        code = read("deploy/proxy01/bereinigen-gb1.sh")
        code = code.replace("[[ $EUID = 0 ]]", "[[ 1 = 1 ]]")
        code = code.replace("/opt/greenbuddy", str(self.base) + "/opt/greenbuddy")
        code = code.replace("/etc/systemd/system", str(self.base) + "/etc/systemd/system")
        # Auch die übrigen Unit-Verzeichnisse lokal halten (sonst liest der Test die Units des Testrechners).
        for path in (" /run/systemd/system", " /usr/lib/systemd/system", " /lib/systemd/system"):
            code = code.replace(path, " " + str(self.base) + path.strip())
        # Nur systemctl-Antworten sind simuliert; chmod/mv würden ausschließlich Tempdaten treffen.
        fake = '''
systemctl() {
  printf '%s\n' "$*" >> ''' + shlex.quote(str(command_log)) + '''
  case "$1" in
    list-unit-files) ''' + ("printf 'Failed to list unit files: Connection timed out\\n' >&2; return 1;;" if unit_files_timeout else "printf 'greenbuddy.service enabled\\nwol_housekeeping_plex.timer enabled\\n';;") + '''
    list-units) printf 'wol_housekeeping_plex.timer loaded active waiting\n-.mount loaded active mounted\n';;
    show)
      case "$*" in
        *greenbuddy-manager.service*) printf 'not-found\n';;
        *LoadState*) printf 'loaded\n';;
        *) ''' + ("printf 'Requires=greenbuddy.service\\nWants=\\nAfter=greenbuddy.service\\n';" if dependency else "printf 'Requires=\\nWants=\\nAfter=\\n';") + '''
           ''' + ("printf 'ExecStart=/usr/bin/python3 %s\\n';;" % str(config) if config_reader else "printf 'ExecStart=/synthetisch/kein-skript\\n';;") + '''
      esac;;
  esac
}
'''
        # Nach dem PATH-Export einfügen, damit nur die Funktion und lokale Dateien wirken.
        code = code.replace("shopt -s nullglob", fake + "\nshopt -s nullglob")
        run = self.shell(code)
        return run, config, command_log.read_text()

    def test_k3_abhaengigkeiten_sperren_maskierung_und_chmod(self):
        for dependency, reader in ((True, False), (False, True)):
            with self.subTest(dependency=dependency, reader=reader):
                run, config, commands = self.cleanup_run(dependency, reader)
                self.assertEqual(run.returncode, 0, run.stderr)
                self.assertNotIn("mask greenbuddy.service", commands)
                self.assertNotIn("disable --now greenbuddy.service", commands)
                self.assertEqual(config.stat().st_mode & 0o777, 0o644)
                self.assertIn("wol_housekeeping_plex.timer", run.stdout)
                self.assertIn("not-found", run.stdout)
                # Unitnamen mit fuehrendem Bindestrich (-.mount) duerfen nicht als Option gelten (proxy01 06.10.26)
                self.assertIn("-- -.mount", commands)

    def test_k3_unitliste_timeout_faellt_auf_verzeichnisse_zurueck(self):
        # proxy01 06.10.26: "Failed to list unit files: Connection timed out" bei jedem Lauf
        units = self.base / "etc/systemd/system"
        units.mkdir(parents=True, exist_ok=True)
        (units / "wol_housekeeping_plex.service").write_text("[Service]\n")
        run, config, commands = self.cleanup_run(dependency=True, unit_files_timeout=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("wol_housekeeping_plex.service", run.stdout)
        self.assertNotIn("mask greenbuddy.service", commands)
        run, config, commands = self.cleanup_run(unit_files_timeout=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("mask greenbuddy.service", commands)

    def test_k3_templates_nur_textuell(self):
        # proxy01 06.10.26: "apport-forward@.service is neither a valid invocation ID nor unit name"
        units = self.base / "etc/systemd/system"
        units.mkdir(parents=True, exist_ok=True)
        (units / "frei@.service").write_text("[Service]\nExecStart=/bin/true\n")
        run, config, commands = self.cleanup_run(unit_files_timeout=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertNotIn("frei@.service", commands)
        self.assertIn("mask greenbuddy.service", commands)
        (units / "haengt@.service").write_text("[Unit]\nAfter=greenbuddy.service\n")
        vorher = len(commands)
        run, config, commands = self.cleanup_run(unit_files_timeout=True)
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("haengt@.service", run.stdout)
        self.assertNotIn("mask greenbuddy.service", commands[vorher:])  # Protokoll waechst ueber beide Laeufe

    def test_k3_rueckweg_dokumentiert(self):
        doc = read("README.md")
        self.assertIn("systemctl unmask", doc)
        self.assertRegex(doc, r"mv[^\n]+\.bak-gb2")

    def test_k3_ohne_abhaengigkeiten_nur_vorhandene_unit_maskieren(self):
        run, config, commands = self.cleanup_run()
        self.assertEqual(run.returncode, 0, run.stderr)
        self.assertIn("mask greenbuddy.service", commands)
        self.assertNotIn("mask greenbuddy-manager.service", commands)
        self.assertEqual(config.stat().st_mode & 0o777, 0o600)
