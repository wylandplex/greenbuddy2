# GreenBuddy 2 · v2.0.0-beta.6

## English summary

GreenBuddy 2 lets a homelab server sleep (suspend to RAM, S3) during the day
without its services becoming unreachable. While the server sleeps, a Raspberry Pi
takes over its IP address and wakes it via Wake-on-LAN only on real demand: SSH,
Plex or Jellyfin from the LAN or VPN, Plex from the internet only with a valid
plex.direct TLS SNI (`<label>.<hash>.plex.direct`), Minecraft only on a login from
a whitelisted player, plus an allowlisted webhook source. While the server is awake,
connections from internet scanners no longer keep it awake.

Status: beta. It runs in exactly one homelab and is tailored to that network; adjust
host names, addresses and MACs in the example configs under `deploy/` before use.
Python 3.9 or newer, standard library only (no third-party packages); it relies on
Linux tools such as systemd, iproute2, nftables, tcpdump and OpenSSH. License: GNU
GPL v3 (see `LICENSE`). The rest of the documentation, the code comments and the
log messages are in German.

## Überblick

GreenBuddy 2 beobachtet die Voraussetzungen für Bedarfsschlaf auf vhost01 und
nas01. Seit 2.0.0-beta.2 legt es vhost01 im Tagschlaffenster aktiv schlafen, wenn
alle Schutzprüfungen bestehen (Standard bleibt der Schattenbetrieb), und bringt den
Notfall-Weckbefehl `gb-wecken` für proxy01; beta.3 wertet kurze Job-Läufe nicht
mehr als Neustart der Ruhezeit, beta.4 lässt ruhende Plex-Verbindungen nicht mehr
wach halten. Seit beta.5 hält proxy01 die Adresse des schlafenden vhost01, erkennt
echte Zugriffe und weckt ihn per WOL (siehe „Weckweg über proxy01“). beta.6
lässt Scanner aus dem WAN vhost01 nicht mehr wach halten: eine WAN-Verbindung zählt
nur noch, wenn sie ihn über proxy01 auch wecken dürfte (siehe „Wachseite filtert Spam“).
Python 3.9 auf vhost01 und Python 3.10 auf proxy01 reichen;
Python-Abhängigkeiten außerhalb der Standardbibliothek gibt es nicht.
proxy01 ist ein Raspberry Pi 3 B+ mit Ubuntu 22.04 und WireGuard.

Die verbindlichen Grundlagen sind die Design-Spec vom 06.10.2026, ihre
Review-Korrekturen, der konkrete beta.1-Auftrag und für beta.5 der Bauplan
„Weckweg über proxy01“ vom 12.10.2026 (Rulings R1–R11), für beta.6 der Live-Befund
und die Rulings vom 13.10.2026. Der Auftrag präzisiert
Minecraft: Scanner-Verbindungen zu lazymc halten den Host nicht wach. Für den
verschlüsselten Threema-Inhalt erzeugt jede frische, geprüfte Nachricht des
freigegebenen Absenders (`wake_sender`) ein Ereignis `absender_freigegeben`; ein
Textvergleich mit „wach“ erfolgt hier nicht.

## Release-Schnitt

Installierbar sind der Schlafwächter `gb-schlaf.service`, der Mitschnitt und
`gb-garp.service` auf vhost01, das SSH-Register, der Stellvertreter
`gb-stellvertreter` (GDM-Zähler und Übernahme) und `gb-wecken` auf proxy01.
Ausschließlich `gb-schlaf` im Modus `aktiv` ruft `rtcwake` und `systemctl suspend`
auf (siehe „Aktiver Schlaf“). Keine Router-Regel und kein bestehender Timer
werden geändert; der proxy01-Installer setzt einzig die ARP-sysctls (siehe
„Installation“). WOL senden `gb-stellvertreter`, ausschließlich für einen
registriert schlafenden vhost01 (in der Probe an deren Dummy-MAC), und der manuelle
Befehl `gb-wecken`. Übernommen
wird nur 192.168.1.110 und nur nach `schlafe-jetzt`; 192.168.1.1, .100, .115
(nas01) und `listen_ip` sind fest gesperrt.

Statt des Phantom-Tests gibt es den Probe-Modus `gb-stellvertreter --probe`, der
nur die konfigurierte freie Testadresse übernimmt (Beispiel .199). Der Webhook
ist gebaut, wird vom Installer aber weder installiert noch aktiviert.
Caddy, Router-Cutover, Übernahme für nas01, GDM-Wecken (Weg 3), VPN-Weckdienst
(Weg 6), Totmann-Wecker und Timer-Umstellung gehören in spätere Releases. Eigene
system-sleep-Hooks braucht beta.2 nicht: Der begleitete S3-Test vom 06.10.26
(vhost01 und nas01, WOL-Weckung nach 6–8 s, RAID/NFS/GPU unverändert) bestand
mit den vorhandenen nvidia-suspend/-resume-Diensten. Die vorhandenen NAS-Wächter und NAS-Fenster bleiben erhalten.

## Aufbau und Verhalten

```text
vhost01: gb-schlaf ── Tatsachen + Entscheidung ── JSONL; aktiv: RTC + abmelden + Suspend,
                      nach dem Resume anmelden (SSH zum Register auf proxy01)
         gb-garp ── nach jedem Resume GARP für 192.168.1.110
         gb-mitschnitt ── tcpdump-Strom ── Klassifikation ── Metadaten
                          └─ legitime WAN-Quellen /run/greenbuddy/legitim/vhost01.json ── gb-schlaf
         gb-fenster ── media-staging.conf + list-timers ── Trockenbericht

proxy01: gb-proxy-ssh ── Host aus authorized_keys ── persistentes Register + Bereitschaft
         gb-stellvertreter ── GDM-Zähler; Übernahme von .110 ── Auslöser ── WOL-Serie
                              └─ Statusbericht /run/greenbuddy/status/stellvertreter.json
         gb-wecken ── feste MAC-Tabelle ── Magic Packet (manuell)

gebaut:  gb-webhook ── MAC + Frische ── dauerhafte Queue ── quittierter Upstream
```

`gb-schlaf` sammelt jede Minute. API-Fehler, fehlender Jellyfin-Key, unlesbare
Logs, kaputte Ansprüche oder Fenster bleiben `unklar`. Plex liest den Token
aus Preferences.xml und nutzt ausschließlich Loopback-APIs ohne HTTP-Proxy
oder Redirect. `MediaContainer.size` zählt bei der Bandbreite alle Listen.
Laufende Sitzungen (`/status/sessions`, auch pausiert) sind immer Nutzung.
`/statistics/bandwidth?timespan=6` liefert ein rollendes Fenster von etwa
130–160 s. Ein Triple (Konto, Gerät, LAN) zählt als Nutzung, wenn seine Bytes
in Buckets der letzten 180 s mindestens `bandbreite_schwelle_bytes` (Standard
262144) erreichen und es nicht in `self_triples` steht. Gemessen am 06.10.26:
eigene Abfragen (1/672 nas01-Wächter, 1/673 gb-schlaf, LAN) und ruhende Clients
(etwa ein Streaming-Stick) liegen bei 10–25 KB je 150 s, reine Keepalives bei
unter 1 KB; Stöbern und Streaming bei Hunderten KB bis MB. Ein Zählerneustart
(unklar) gilt nur, wenn ein Bucket kleiner wurde oder ein Bucket fehlt, dessen Zeit nicht älter
als der älteste Bucket der aktuellen Antwort ist; das normale Herausfallen
alter Buckets und eine leere Antwort sind kein Neustart. Kennungen werden nicht
ins Log übernommen.

Minecraft-Nutzung bedeutet Java mit dem konfigurierten Argumentmuster.
SSH zählt aktive/online Remote-Sitzungen. Eine `closing`-Sitzung hält logind
nur, solange in ihrem Scope noch Prozesse laufen (tmux, `nohup`, Hintergrundjobs
nach dem Logout); sie ist darum das Veto `sitzung_closing`. Jobs werden
über `systemctl show` samt PIDs geprüft, User-Units ohne PAM per `setpriv` direkt
am User-Bus (`systemctl --user show`). Fehlende Jobs
bleiben unklar, außer ihre Unitnamen stehen ausdrücklich in `optional_jobs`.
`smb.service` (Samba bei Bedarf) steht in den Standard-Jobs: läuft Samba, ist
das ein Veto. Zusätzlich sind laufende `systemd-run`-Units (`run-*.service`,
`run-*.scope`) im System-Manager und in den User-Managern aus
`transient_benutzer` (Standard claude, jellyfin, mediauser) Vetos (`transient:…`);
eine fehlgeschlagene Abfrage bleibt `transient_unklar:<benutzer>`.
Degradierte
Daten-Arrays und RAID-Aktionen sind Vetos; ein inaktiver IMSM-Container allein
ist normal. Mit `"raid_degradiert_erlaubt": true` (Freigabe des Betreibers vom 06.10.26
nach bestandenem S3-Test) ist die fehlende Redundanz kein Veto mehr; sie bleibt
als `raid_degradiert` in den Fakten. resync/recovery/check/reshape bleiben Veto. mdmon und GPU-Prozesse werden mit erfasst.
Bestehende Verbindungen (`ss -Htn state established`) auf 32400, 22, 8443, 8096,
445 (Samba) und 8081 (HTTP-Fileserver) sind ein Veto (Ausnahme: ruhende Plex-Verbindungen, s. u.). Jeder andere lokal
lauschende TCP-Port (`ss -Htln`) ist ein Veto, sobald die Gegenstelle nicht der
Host selbst ist (Loopback oder dieselbe Adresse wie lokal): unbekannte
Verbraucher halten wach. Ports in `verbindung_ausnahmen` (Standard 25565, lazymc)
bleiben reine Diagnose. Auf den Ports in `verbindung_ruhe_ports` (Standard
32400) ist eine Verbindung „ruhend“ und nur Diagnose (`verbindungen_ruhend`), wenn
die Gegenstelle seit `verbindung_ruhe_sekunden` (900 = 15 min) keine Daten gesendet
hat (`lastrcv` aus `ss -Htni`) **und** der Server seit der Vorrunde höchstens
`verbindung_ruhe_bytes` (65536) bestätigt bekam (`bytes_acked`): Eine Plex-App, die
nur ihre Websocket-Verbindung offen hält, hält den Host nicht mehr wach; Blättern
und Abspielen senden Anfragen, ein Download über eine einzige Anfrage überträgt
Megabytes. Fehlen `lastrcv` (ss lässt 0 weg), `bytes_acked`, die Infozeile oder die
Vorrunde, zählt die Verbindung. Jellyfin (8096) ist nicht Standard: Seine Apps
senden über den Websocket alle ~30 s `KeepAlive`, `lastrcv` bleibt dort klein.
Seit beta.6 zählt eine Gegenstelle aus dem WAN nur, wenn
der Mitschnitt sie für legitim hält (Datei `legitim`, Schalter `wan_filter`, siehe
„Wachseite filtert Spam“). Eine dauerhafte interne Verbindung über eine andere
Host-Adresse erscheint im Schattenlog als `verbindung:<port>` und lässt sich dort
vor der Aktivierung erkennen. Bot-Nutzung (Signal `coach`, ein Threema-Gateway-Bot
hinter Caddy) ist das Alter des letzten `ThreemaGateway`-Eintrags im Journal der
Unit aus `coach_journal_unit` (Beispiel `bot-caddy.service`).
ANSI-Byte-Listen werden als UTF-8 gelesen. Ein leeres Unit-Journal oder
`MESSAGE=null` bleibt unklar; lesbare Einträge etwa von `/health` ohne Callback
belegen dagegen Ruhe über das abgefragte Fenster. Journal und GPU-Abfrage
haben zehn Sekunden Timeout. Alternativ bleibt der Caddy-JSONL-Pfad nutzbar.

Ein Anspruch unter `/run/greenbuddy/ansprueche/*.json` enthält `host`, `dienst`,
`besitzer`, `zyklus` und `ablauf` als Epoch-Zeit. Ein gültiger Anspruch für
vhost01 ist ein Veto. Ansprüche sind lokale Beobachtungsdaten; beta.1 verteilt
sie noch nicht zwischen Hosts.

Ein Ruhekandidat braucht 45 Minuten ohne Nutzung, Veto oder Unklar-Befund
und liegt im Tagschlaffenster. Nutzung, Unklares und Vetos der Tatsachen
starten die Ruhezeit neu; Fenster und Mindestwachzeit sperren nur, ohne sie
neu zu starten. Ein Job (`job:<unit>`) sperrt jede Runde, in der er läuft, startet
die Ruhezeit aber erst neu, wenn dieselbe Unit in zwei aufeinanderfolgenden Runden
läuft: No-op-Timer (etwa ein Staging-Job alle 15 min, je ~10 ms) feuern genau dann,
wenn die Runde PID1 bzw. den User-Manager abfragt (fällige Timer mit
`AccuracySec=1min` laufen beim nächsten Aufwachen des Managers an), und erscheinen
so in genau einer Runde. Nach dem Dienststart und nach einer Runde mit
Unklar-Befund gilt jeder laufende Job als schon gelaufen (Neustart).
Im Schattenmodus bleibt `dependencies_verified` `false`, der
ungeprüfte Abhängigkeitsbefund wird aufgeführt und die Entscheidung lautet
`beobachten`, `unklar` oder `abgeschaltet`. `CLOCK_BOOTTIME` gegen
`CLOCK_REALTIME` erkennt Uhrsprünge; der Vergleich mit MONOTONIC erkennt Resume.
Dienststart und Resume erzwingen zehn Minuten Mindestwachzeit, echte
Uhrsprünge 45 Minuten Vorsicht. Ein Resume startet zusätzlich die Ruhezeit neu.

Mitschnitt und Stellvertreter verwenden dasselbe Modul `klassifikation`; der
Stellvertreter prüft bei WAN-32400 zusätzlich das SNI-Label (siehe „Weckweg über
proxy01“).
LAN ist standardmäßig 192.168.1.0/24, VPN 10.0.0.0/24, sonst WAN. Ein gültiges
Plex-SNI mit `*.<hash>.plex.direct`, ein Minecraft-Login aus der Whitelist
oder eine bekannte Plex-HTTP-Client-ID im LAN/VPN ergibt `wuerde_wecken`.
Status-Pings und unbekannte Kennungen ergeben `spam`, unvollständige Anfänge
`unklar`. SNI und Spielernamen sind Spam-Filter, keine Anmeldung.
Port 8443 bleibt ohne MAC-Prüfung unklar (Weg 5).
Port 8096 wird mindestens als SYN erfasst: LAN/VPN ergibt `wuerde_wecken`
(Weg 4), WAN ergibt `spam`.

tcpdump erhält einen IPv4-BPF für SYNs auf 32400/25565/8443/8096, alle
Payload-Segmente auf 32400/8443 und kleine Minecraft-Pakete,
`-p -U -w - -s 65535`. Es schreibt keine pcap-Datei und arbeitet ohne
Promiscuous-Modus; die Unit braucht ausschließlich `CAP_NET_RAW`.
Der Parser unterstützt geteilte TLS-Records, TCP-Segmente, Retransmits sowie
Ethernet/VLAN/Linux-Cooked-Header. IPv6 ist in diesem Release nicht abgedeckt.
Maximal 2048 Flows und 16 KiB Anfang je Flow bleiben kurz im RAM. Puffer
wachsen erst bei Payload; entschiedene Flows verwerfen weitere Pakete ohne
erneute Klassifikation. Die Ablaufprüfung läuft höchstens einmal pro Sekunde.

Auf vhost01 ist `/var/log/greenbuddy` root:root 0755; ausschließlich
`/var/log/greenbuddy/mitschnitt` und seit beta.6 `/run/greenbuddy/legitim` gehören
gb-mitschnitt (0700) und sind in dessen Unit schreibbar. JSONL-Dateien haben
höchstens 20 MiB und fünf Rotationen, Heartbeats kommen spätestens minütlich. Alle Logöffnungen nutzen `O_NOFOLLOW`;
beschädigte Zeilen unterbrechen die Retention nicht.
Auf proxy01 gehört der Log-Elternpfad ebenfalls root:root 0755. Stellvertreter-
Logs liegen privat im tmpfs unter `/run/greenbuddy/log` (gb-stellvertreter,
0700), mit 2 MiB je Datei und drei Rotationen. Heartbeats kommen bei
Zustandsänderung oder stündlich. Auch der Übernahmezustand
(`/run/greenbuddy/stellvertreter/uebernahme.json`) und der Statusbericht liegen
unter `/run`; im installierten Betrieb bleibt nur das selten geschriebene Register
persistent. Quelladressen verschwinden automatisch nach höchstens 14 Tagen, auch aus
Rotationen; danach bleiben Tageszähler. GDM speichert nur Quellenzähler je
Stunde, sendet niemals Antworten und weckt nicht. Weckentscheidungen und Limits des
Stellvertreters stehen als Einzelzeilen im Log, Spam und Unklares nur stündlich
verdichtet.

## Fenster und Wege 1/2

Die einzige Zeitquelle ist `/etc/media-staging.conf`. Der Installer schreibt
diese Datei nicht. Vor dem Start die folgenden neuen Schlüssel dort ergänzen;
die Uhrzeiten sind ein Beispiel und müssen lokal bestätigt werden:

```sh
WACH_MORGEN_START="07:00"
WACH_MORGEN_END="09:00"
WACH_ABEND_START="17:00"
WACH_ABEND_END="22:00"
TAGSCHLAF_START="09:00"
TAGSCHLAF_END="17:00"
VORLAUF_MIN=5
```

Bestehende `NAS_*_START/END`-Paare werden nur gelesen. Beginn ist inklusiv,
Ende exklusiv; Fenster über Mitternacht sind erlaubt. Fehlende, doppelte oder
ungültige Schlüssel ergeben unklar. Die Uhrzeiten gelten in der lokalen Zeitzone
des Hosts (samt Sommerzeit).
`gb-fenster` berechnet den nächsten Wachfensterbeginn minus Vorlauf und
meldet die nächsten Timer-Ausführungen in einer möglichen Schlafphase.
Es nutzt `systemctl list-timers --all --output=json`, ersatzweise dessen
Textausgabe. Für eine vollständige Prüfung wiederkehrender Timer braucht
eine spätere Stufe zusätzlich deren Kalenderregeln; beta.1 zeigt die jeweils
nächste Ausführung und ändert keine Unit.

## Installation

Das Paketverzeichnis auf den jeweiligen Host übertragen. Als root aus dem
Paketverzeichnis ausführen:

```sh
bash deploy/vhost01/installieren.sh
# Auf proxy01:
bash deploy/proxy01/installieren.sh
```

Die Installer schreiben das Paket nach
`/usr/local/lib/greenbuddy2/greenbuddy2/` und die jeweiligen Starter nach
`/usr/local/sbin/`. Die Starter verwenden Python im isolierten Modus und
setzen `sys.path` auf `/usr/local/lib/greenbuddy2`. Webhook-Modul, Webhook-Starter
und Webhook-Konfiguration bleiben ausschließlich im Baupaket.

vhost01 braucht `tcpdump`, `nvidia-smi`, `loginctl`, `ss`, `rtcwake`, `busctl`,
`ssh`, `ip`, `arping` (iputils) und systemd ≥ 248.
proxy01 braucht Python, `ip`, `sysctl`, `systemd-tmpfiles` und systemd; `arping`
nicht, die ARP-Frames baut `gb-stellvertreter` selbst. Fehlendes `nft` erzeugt nur
eine Warnung; dann meldet der Dienst `nft_fehlt`, übernimmt nie, und vhost01 schläft
mangels Bereitschaft nicht. Falls nftables nachinstalliert wird, anschließend ausführen:

```sh
systemctl disable --now nftables
```

Der nftables-Dienst kann beim Boot sein Ruleset leeren und dadurch WireGuard-
oder NAT-Regeln entfernen. GB2 verwaltet ausschließlich seine eigenen Tabellen
(`gb2_sv_*`) und legt sie mit `create` an: eine fremde gleichnamige Tabelle wird nie
ergänzt oder gelöscht.

Der proxy01-Installer legt `/etc/sysctl.d/60-greenbuddy-arp.conf` an und lädt sie
sofort: `arp_ignore=1` und `arp_announce=2` für `all` und `eth0` (vorher 0). proxy01
beantwortet ARP danach nur noch für Adressen der Empfangs-NIC und fragt mit der zur
Ziel-IP passenden eigenen Adresse; das verhindert, dass er für den Alias über eine
andere Adresse antwortet. Der Installer liest die wirksamen Werte zurück und warnt,
falls sie fehlen; der Dienst übernimmt ohne sie nie (`arp_sysctl_ungueltig`).

Die Installer starten keine Dienste; aktiviert wird nur `gb-garp.service` auf
vhost01 (läuft erst nach dem nächsten Resume). Sie
legen ein Manifest unter `/root/greenbuddy2/manifest.tsv` an, sichern
ersetzte Dateien als `*.bak-gb2` und versuchen bei Fehlern den Rückbau.
Ein vorhandenes Manifest verhindert eine zweite Installation. Bereits
vorhandene Dienstkonten oder Verzeichnisse mit fremden Rechten verhindern
die Installation. Feste UIDs/GIDs werden nicht erzwungen. Verwaiste numerische
Besitzer werden ausschließlich in der festen GB2-Verzeichnisliste per chown
übernommen. fapolicyd-Trust wird nur bei aktivem fapolicyd angepasst und genau
einmal am Ende aktualisiert. SELinux-Labels werden nur bei aktivem SELinux
über `restorecon` hergestellt.

Auf vhost01 zuerst `/etc/greenbuddy/schlaf.json` und `mitschnitt.json` prüfen:
Plex-Preferences-Pfad, private Jellyfin-Key-Datei (0600), Bot-Journal-Unit,
Minecraft-Argument, Jobs, NIC, Plex-Hash und gelernte Client-IDs/Whitelist.
Die Key-Datei enthält ausschließlich den API-Key; keine Shell-Zuweisung.
Die Beispielkonfiguration enthält keine Geheimnisse. Anschließend:

```sh
/usr/local/sbin/gb-fenster
/usr/local/sbin/gb-schlaf --einmal
systemctl enable --now gb-schlaf.service gb-mitschnitt.service
```

Auf proxy01 `stellvertreter.json` prüfen (Platzhalter siehe „Weckweg über
proxy01“), zuerst die Probe laufen lassen (siehe „Probe ohne Produktions-IP“) und
erst dann den Dienst starten:

```sh
systemctl enable --now gb-stellvertreter.service
```

Die Units beschränken Schreibpfade, setzen `ProtectSystem=strict`,
`NoNewPrivileges=yes` und begrenzen Speicher und Capabilities. Mitschnitt
und Stellvertreter haben eigene Benutzer. Der Root-Schlafwächter benötigt
Leserechte auf Prozesse/Preferences; `CAP_SYS_PTRACE` wird nicht benötigt.
Für den Suspend erhält er zusätzlich nur `CAP_SYS_BOOT`: logind lässt
`systemctl suspend` einem Aufrufer mit dieser Capability ohne polkit-Agent zu.
Die Systemaufrufe `reboot`, `kexec_load` und `kexec_file_load` sind per
`SystemCallFilter` gesperrt. `rtcwake` stellt den Wecker über das
`RTC_WKALM_SET`-ioctl auf `/dev/rtc0` (keine Capability, `/dev/rtc0` ist
root:root 0600); `/sys/class/rtc/rtc0/wakealarm` wird nur zurückgelesen, darum
bleibt `ProtectKernelTunables=yes` ohne Schreibausnahme. `ProtectClock` und
`PrivateDevices` sind absichtlich nicht gesetzt, weil beide `/dev/rtc0` sperren.
Kein `CAP_SYS_ADMIN`, kein `CAP_WAKE_ALARM`, keine Netzwerk-Raw-Capability.

Der Stellvertreter läuft als gb-stellvertreter mit `CAP_NET_ADMIN` (Alias, nft),
`CAP_NET_RAW` (Raw-Sockets an eth0 und wg0) und `CAP_NET_BIND_SERVICE`, den
Adressfamilien AF_INET, AF_UNIX, AF_PACKET und AF_NETLINK (kein AF_INET6) und
Schreibpfaden nur unter `/run/greenbuddy`; `ExecStopPost` ruft
`gb-stellvertreter --aufraeumen` auf. `gb-garp` läuft als root nur mit `CAP_NET_RAW`.

### Ausrollen von beta.5: erst proxy01, dann vhost01

Die Reihenfolge ist Pflicht. Ein beta.5-vhost01 verlangt vor jedem Suspend
`bereit: true`; das beta.2-Register antwortet immer `bereit: false`
(`beta1_nur_register`), vhost01 schläft dann nicht mehr (Abbruch
`stellvertreter_nicht_bereit:beta1_nur_register`). Ein beta.5-proxy01 neben einem
älteren vhost01 ist dagegen harmlos: ohne `schlafe-jetzt` übernimmt er nie. Wer
vhost01 doch zuerst ausrollt, setzt dort bis dahin `"stellvertreter_pflicht": false`.
Ein vorhandenes Manifest verhindert eine zweite Installation; ein Update ist darum
Rückbau plus Neuinstallation.

1. proxy01 (vhost01 sollte dabei wach sein, siehe „Abschalter und Rückbau“):

   ```sh
   bash /root/greenbuddy2/rueckbau.sh       # Konfig, Register und authorized_keys -> *.bak-gb2-<datum>
   bash deploy/proxy01/installieren.sh
   # authorized_keys aus /var/lib/greenbuddy-ssh.bak-gb2-<datum>/.ssh/ zurücklegen (root:root 0644)
   ```

   `stellvertreter.json` kommt aus der neuen Vorlage; die beta.2-Datei (mit
   `phantom_test`) nicht zurücklegen, sondern die Platzhalter der Vorlage ersetzen.
   Das Register muss nicht zurück. Wer ein beta.2-Register vor dem Installer
   zurücklegt (`/var/lib/greenbuddy` gb-register:gb-register 0755), bekommt es auf
   2750 mit Gruppe gb-stellvertreter und `register.json` auf 0640 angehoben.
   Danach sysctls prüfen und ufw ergänzen (INPUT-Policy DROP):

   ```sh
   sysctl net.ipv4.conf.all.arp_ignore net.ipv4.conf.all.arp_announce \
          net.ipv4.conf.eth0.arp_ignore net.ipv4.conf.eth0.arp_announce   # 1, 2, 1, 2
   ufw allow from 192.168.1.0/24 to any port 32414 proto udp   # GDM-Zähler (Plan R10)
   ufw status numbered        # 32400 und 25565 müssen auch für Ziel 192.168.1.110 gelten
   ```

   Ohne die GDM-Regel verwarf ufw jedes GDM-Paket; der Zähler sah seit 07.10.26
   kein einziges. ufw betrifft beim Weckweg nur die Inhaltsports: die Handshakes auf
   .110:32400 (WAN-SNI) und .110:25565 (Minecraft) muss ufw durchlassen. Eine Regel
   `allow 32400` bzw. `allow 25565` ohne Zieladresse genügt, sonst
   `ufw allow proto tcp to 192.168.1.110 port 32400` (ebenso 25565). Die SYN-Auslöser
   (22, 8096, LAN-32400, 8443) sieht der Raw-Socket vor jeder Firewall; sie brauchen
   keine Regel. Dann die Probe und erst danach:

   ```sh
   systemctl enable --now gb-stellvertreter.service
   cat /run/greenbuddy/status/stellvertreter.json   # root: "stellvertretung": "ok", "bereit_fuer": ["vhost01"]
   ```

2. vhost01:

   ```sh
   bash /root/greenbuddy2/rueckbau.sh
   bash deploy/vhost01/installieren.sh
   ```

   Der Installer legt `schlaf.json` aus der Vorlage an (Modus `schatten`); die
   Live-Werte aus `schlaf.json.bak-gb2-<datum>` zurückholen (`mode`,
   `dependencies_verified`, `raid_degradiert_erlaubt`, `wol_interface` …). Die
   `stellvertreter_*`-Schlüssel dürfen fehlen, dann gelten die Standardwerte. Der
   Schlafzustand beginnt neu (`schlaf-zustand.json` liegt im gesicherten
   `/var/lib/greenbuddy`): eine laufende 24-Stunden-Sperre vorher prüfen. Schlüssel
   und known_hosts für das Register bleiben unter `/etc/greenbuddy/ssh/` (root,
   `id_ed25519` 0600, known_hosts mit dem Hostschlüssel von 192.168.1.100 per IP);
   der Rückbau fasst sie nicht an, fehlen sie, warnt der Installer. `gb-garp.service`
   ist bereits aktiviert. Den SSH-Weg einmal aus einer Umgebung wie der gehärteten
   Unit prüfen (muss `"bereit": true` liefern), GARP einmal von Hand senden (nur für
   die eigene Adresse), dann starten:

   ```sh
   systemd-run --wait --pipe -p ProtectHome=read-only -p ProtectSystem=strict \
       -p 'RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK' -p NoNewPrivileges=yes \
       -p 'CapabilityBoundingSet=CAP_DAC_READ_SEARCH CAP_SETUID CAP_SETGID CAP_SYS_BOOT' \
       /usr/bin/python3 -I -c 'import sys, json; sys.path.insert(0, "/usr/local/lib/greenbuddy2"); from greenbuddy2.register_client import Register; print(json.dumps(Register().status()))'
   systemctl start gb-garp.service && systemctl status gb-garp.service --no-pager
   systemctl enable --now gb-schlaf.service gb-mitschnitt.service
   ```

3. Den ersten Tagschlaf begleiten, und zwar von proxy01 aus: eine offene
   SSH-Sitzung auf vhost01 hält ihn wach.

   ```sh
   timeout 4h tail -f /run/greenbuddy/log/stellvertreter.jsonl   # root auf proxy01
   ```

   Erwartet: `phase` `frei → warte_stille → uebernommen`. Weckprobe per VPN: vom
   VPN-Client `ssh 192.168.1.110` → `ausloeser` mit `weg` 4, `quellklasse` `VPN`,
   `entscheidung` `wecken`; nach dem Aufwachen `wecken_erfolg` und `phase … frei`
   mit `grund` `echte_mac`; auf vhost01 danach `aufgewacht` mit
   `geweckt_durch_proxy01`. Anschließend dasselbe mit der Plex-App im LAN und im
   Mobilnetz.

### Ausrollen von beta.6: nur vhost01

proxy01 bleibt auf beta.5: beta.6 ändert dort kein Verhalten (die WAN-Auflösung liegt
nur in einem eigenen Modul `wan.py`). Ein vhost01 mit beta.6 neben einem proxy01 mit
beta.5 ist der vorgesehene Zustand. Auf vhost01 wie bei beta.5 Rückbau plus
Neuinstallation (der Schlafzustand beginnt neu, eine laufende 24-Stunden-Sperre
vorher prüfen):

```sh
bash /root/greenbuddy2/rueckbau.sh
bash deploy/vhost01/installieren.sh   # legt /run/greenbuddy/legitim an (gb-mitschnitt 0700, auch per tmpfiles)
```

`schlaf.json` und `mitschnitt.json` kommen aus der Vorlage. Die Live-Werte aus
`schlaf.json.bak-gb2-<datum>` und `mitschnitt.json.bak-gb2-<datum>` zurückholen
(Modus, Freigaben, Plex-Hash, Whitelist, Client-IDs …), die neuen Schlüssel dabei
behalten; fehlen sie, gelten die Standardwerte. Ohne gültigen `plex_hash` (etwa der
Platzhalter der Vorlage) schreibt der Mitschnitt keine Legitim-Datei und meldet einmal
`"ereignis": "legitim_aus", "grund": "plex_hash"`; gb-schlaf bleibt dann bei beta.5
(`"legitim": "fehlt"`). In `mitschnitt.json` den DDNS-Namen
als `wan_name` eintragen (derselbe wie `wan_name` in `stellvertreter.json` auf
proxy01), sonst gibt es keine Haarnadel-Ausnahme. Für das Threema-Gateway optional in
`schlaf.json` `"legitim_quellen": {"8443": [...]}` mit denselben Adressen wie
`quellen_ports` auf proxy01. Dann zuerst den Mitschnitt starten, die Datei prüfen und
einen Takt von Hand laufen lassen (vor dem Dienst, er hält die Sperre):

```sh
systemctl enable --now gb-mitschnitt.service
stat -c '%U %a %n' /run/greenbuddy/legitim /run/greenbuddy/legitim/vhost01.json   # gb-mitschnitt 700, 600
cat /run/greenbuddy/legitim/vhost01.json   # "version":1, frische "zeit" und "letztes_paket", mit wan_name auch "eigene_wan_ip"
/usr/local/sbin/gb-schlaf --einmal | python3 -m json.tool | grep -A3 -E '"legitim"|verbindungen_wan_ignoriert|verbindungen_haarnadel'
systemctl enable --now gb-schlaf.service
```

Erwartet: `"legitim": "ok"` und kein `legitim_aus` im Mitschnitt-Log
(`/var/log/greenbuddy/mitschnitt/mitschnitt.jsonl`); Scanner stehen unter
`verbindungen_wan_ignoriert` statt als Veto `verbindung:32400` oder
`verbindung:8880`, die Haarnadel um :01 unter `verbindungen_haarnadel`. Zurück zum
beta.5-Verhalten ohne Neuinstallation: `"wan_filter": false` in `schlaf.json` und
`systemctl restart gb-schlaf.service`.

## Aktiver Schlaf (vhost01)

Der Schlafwächter legt vhost01 nur schlafen, wenn **alle** Bedingungen gelten:

- `"mode": "aktiv"` und `"dependencies_verified": true` in `schlaf.json`
  (eines allein bleibt Schattenbetrieb), kein Abschalter `/etc/greenbuddy/aus`,
  keine Konfigurations- oder Zustandsfehler;
- innerhalb `TAGSCHLAF_START..TAGSCHLAF_END` aus `/etc/media-staging.conf`, in
  keinem Wachfenster (samt Vorlauf) und mindestens 20 Minuten vor dem Ende der
  Schlafphase (TAGSCHLAF-Ende oder früherer Beginn eines anderen Fensters);
- 45 Minuten Ruhe ohne Nutzungssignal, Veto oder Unklar-Befund
  (`idle_seconds` kleiner als 2700 wird auf 2700 angehoben); der Zeitpunkt der
  letzten Unruhe steht mit Boot-ID in `/var/lib/greenbuddy/schlaf-zustand.json`
  und gilt nach einem Dienstneustart nur weiter, wenn der Vorgänger lückenlos
  beobachtet hat: Jeder aktive Takt schreibt einen Stempel (BOOTTIME, Boot-ID,
  bezeugte Ruhe) nach `/run/greenbuddy/schlaf-takt.json` (`takt_stempel`, tmpfs).
  Übernommen wird nur bei passendem Stempel, der höchstens zwei Takte alt ist, und
  ohne offenen Schlafeintrag. Nach Schattenbetrieb, gestopptem Dienst, Hostneustart
  oder einem Resume, den der neue Prozess nicht selbst gesehen hat, beginnt die
  Ruhe neu; ebenso nach jedem `aufgewacht`/`suspend_ohne_wirkung`;
- keine Vetos (SSH, `closing`-Sitzungen, Jobs samt `smb.service`, `systemd-run`-Units
  (`run-*.service`/`run-*.scope`), GPU, Ansprüche, RAID-Aktion, Verbindungen auf 32400 (außer ruhenden)/22/8443/8096/445/8081 oder
  von außen auf jeden anderen lauschenden Port außer `verbindung_ausnahmen`,
  degradiertes RAID ohne Freigabe) und keine Nutzung (Plex,
  Jellyfin, Minecraft-Java, Claude-Läufe, Bot-Signal `coach`, SSH);
- zehn Minuten seit Dienststart bzw. Resume, kein Uhrsprung, kein verspäteter
  Takt;
- höchstens sechs Schlafzyklen in 24 Stunden. Erreicht die Zahl sechs, setzt
  der Wächter eine 24-Stunden-Sperre (`schlafsperre_24h` im Log, persistent);
- proxy01 meldet Bereitschaft (`abmelden` und `schlafe-jetzt` mit `bereit: true`),
  solange `"stellvertreter_pflicht": true` gilt (Standard), und seit dem letzten
  Register-Fehler sind fünf Minuten vergangen (sonst Hindernis `stellvertreter_pause`).

Ablauf bei `schlafen`: RTC-Wecker mit `rtcwake -m no -t <epoch>` auf das Ende
der Schlafphase minus `VORLAUF_MIN` (mindestens 10 Minuten, höchstens 12 Stunden
voraus); der Kernel muss den Termin in `/sys/class/rtc/rtc0/wakealarm`
zurückmelden, sonst kein Schlaf. Danach frische Schlussprüfung aller Tatsachen;
ergibt sie nicht wieder `schlafen` mit derselben Weckzeit, wird abgebrochen und
der Wecker gelöscht. Zusätzlich müssen logind `CanSuspend=yes` melden, kein
`block`-Inhibitor für `sleep` bestehen (root würde ihn sonst übergehen) und
`/sys/class/net/<wol_interface>/device/power/wakeup` `enabled` melden. Dieses
PCI-Weckflag setzt der Treiber beim Scharfschalten von WOL; `ethtool` scheidet
aus, weil seine Wake-on-Abfrage `CAP_NET_ADMIN` braucht. Ebenso muss
`/sys/class/rtc/rtc0/device/power/wakeup` `enabled` melden (sonst
`rtc_weckquelle_aus`/`rtc_weckquelle_unklar`): `rtcwake -m no` prüft dieses Flag
nicht, und ohne es maskiert rtc_cmos den Alarm beim Suspend, obwohl `wakealarm`
den Termin zurückmeldet. Kein Gen-0-Schläfer darf übrig sein
(`fremder_schlafdienst:<unit>`): `auto-sleep.timer` und `auto-sleep.service`
dürfen nicht laufen, `delay-after-suspend.service` muss maskiert oder entfernt
sein, weil es nach jedem Resume `auto-sleep.timer` startet (auch deaktiviert).
Danach meldet sich vhost01 mit `abmelden <zyklus>` bei proxy01 ab (siehe unten);
erst nach dem Logeintrag `einschlafen`, dem atomaren Sichern des Zyklus,
`schlafe-jetzt <zyklus> <sekunden>` und einer letzten Prüfung folgt
`systemctl suspend`. Die beiden SSH-Aufrufe dauern je bis zu 20 s; die letzte Prüfung
unmittelbar vor dem Suspend (Spec 3.2: Phase A vor der letzten lokalen Prüfung)
sieht deshalb noch einmal Abschalter, frische Fakten (Nutzung, Verbindungen,
Sitzungen, Jobs, Unklares, mit derselben Entscheidungslogik wie jeder Takt) und die
Vorbedingungen samt `block`-Inhibitoren. Jede Abweichung bricht ab (`grund`
`letzte_pruefung`, `abbruch` mit den Gründen): Schlafeintrag zurückgenommen,
`anmelden-abbruch`, Wecker gelöscht. proxy01 übernimmt dann nicht, weil der wache
Host die ARP-Proben beantwortet.
Scheitert `systemctl suspend` (Exit ≠ 0), wird der Wecker gelöscht; bei
Zeitüberschreitung oder Startfehler (`suspend_unklar`) bleiben Wecker und
Schlafeintrag stehen, weil logind den Auftrag schon angenommen haben kann. In
beiden Fällen beginnt die Ruhezeit neu, statt im Minutentakt erneut zu versuchen.
Nach dem Aufwachen protokolliert der Wächter `aufgewacht` mit `schlafdauer_s`
(aus BOOTTIME minus MONOTONIC) und `geweckt_durch` (`rtc` oder `anderes`).
Bleibt der Suspend fünf Minuten ohne Wirkung, steht `suspend_ohne_wirkung` im Log.

Register bei proxy01 (seit beta.5, Plan Abschnitt 5): Der Zyklus ist eine je
Einschlafversuch neue Kennung aus 16 Hexzeichen. vhost01 ruft als root
`ssh -i /etc/greenbuddy/ssh/id_ed25519 -o BatchMode=yes -o IdentitiesOnly=yes
-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/etc/greenbuddy/ssh/known_hosts
… -T gb-register@192.168.1.100 '<befehl>'` mit 20 s Frist auf und prüft Tatsachen
statt nur den Exit-Code: genau eine JSON-Zeile, `host` = vhost01, die zum Befehl
passende Phase (`abgemeldet`, `schlaf_absicht`, `angemeldet`), der eigene Zyklus,
bei `anmelden` das Feld `weckung`. `abmelden` und `schlafe-jetzt` verlangen
`bereit: true`; `schlafe-jetzt` trägt die Sekunden bis zum RTC-Wecker, auf
600–43.200 begrenzt. Absage (`bereit: false` mit `grund` oder eine Fehlerzeile mit
`fehler`) oder unklare Antwort (Frist, ssh-Exit 255, falsches Schema): kein Suspend,
Wecker gelöscht, best effort `anmelden-abbruch` (auch nach gescheitertem `abmelden`,
weil proxy01 den Zyklus schon eröffnet haben kann), Abbruchzeile mit `grund`
`stellvertreter`, `abbruch` `["stellvertreter_nicht_bereit:<grund>"]` oder
`["stellvertreter_unklar"]`, `stellvertreter_detail` (etwa `frist`, `exit_255`,
`antwort_json`, `antwort_phase`) und `anmelden_abbruch` (`ok` oder Grund); danach
fünf Minuten `stellvertreter_pause` statt SSH im Minutentakt. Scheitert
`systemctl suspend` mit Exit ≠ 0, folgt sofort `anmelden-abbruch`; bei
`suspend_unklar` erst mit `suspend_ohne_wirkung`, damit ein doch schlafender Host
seinen Weckweg behält (ein wacher beantwortet die ARP-Proben von proxy01, der dann
nicht übernimmt). Nach dem Resume meldet sich vhost01 mit `anmelden <zyklus>` zurück:
`aufgewacht` trägt `zyklus`, `anmelden` (`ok`/`offen`), `anmelden_grund` und
`geweckt_durch_proxy01` (die letzte Weckung laut proxy01: Zeit, Weg 4/5/7, Port,
Quellklasse, Entscheidung, keine IP; `null`, wenn RTC oder Taster weckten). Ein
offenes `anmelden` wiederholt der Wächter in jeder Runde (`angemeldet` mit
`versuche`) und gibt es nach zehn Minuten auf (`anmelden_aufgegeben`; proxy01 hat
dann längst beim ersten Frame freigegeben, der Lease läuft ab). Die Versuche lassen
die Ruhezeit unberührt; Pause und offenes `anmelden` liegen nur im Speicher.
Schlüssel in `schlaf.json` (Standardwerte, dürfen fehlen): `stellvertreter_ziel`
(`gb-register@192.168.1.100`), `stellvertreter_schluessel`
(`/etc/greenbuddy/ssh/id_ed25519`), `stellvertreter_known_hosts`
(`/etc/greenbuddy/ssh/known_hosts`) und `stellvertreter_pflicht` (`true`). Ein
Formfehler ergibt `konfig_fehler` (unklar, kein Schlaf).

Aktivieren (nach der Schattenwoche), in dieser Reihenfolge:

1. Schattenlog auf dauerhafte Vetos prüfen (`verbindung:<port>`, `transient:…`,
   `sitzung_closing`, `transient_unklar:…`) und Ursachen klären.
2. Gen-0-Schläfer stilllegen (nur mit Freigabe des Betreibers; die Units liegen in
   `/etc/systemd/system`, dort verweigert `systemctl mask` das Überschreiben):

   ```sh
   systemctl show -p Id -p LoadState -p ActiveState -p UnitFileState -- \
       auto-sleep.timer auto-sleep.service delay-after-suspend.service
   systemctl disable --now auto-sleep.timer auto-sleep.service delay-after-suspend.service
   install -d -m 0700 /root/gen0-units
   mv /etc/systemd/system/{auto-sleep.timer,auto-sleep.service,delay-after-suspend.service} /root/gen0-units/
   systemctl daemon-reload
   systemctl mask auto-sleep.timer auto-sleep.service delay-after-suspend.service
   ```

   Danach `LoadState=masked` für alle drei.
3. Pflichttest RTC-Weckung, begleitet (vor Ort oder mit `gb-wecken` als Rückweg):

   ```sh
   cat /sys/class/rtc/rtc0/device/power/wakeup        # muss enabled melden
   cat /sys/class/rtc/rtc0/device/power/wakeup_count  # Wert notieren
   rtcwake -m no -t $(( $(date +%s)+600 )) && systemctl suspend
   # vhost01 muss nach etwa 10 min ohne WOL und ohne Taster selbst aufwachen:
   journalctl -b -u systemd-suspend.service --no-pager | tail -n 5
   cat /sys/class/rtc/rtc0/device/power/wakeup_count  # sollte gestiegen sein
   ```

   Wacht vhost01 nicht selbst auf, bleibt der Aktivmodus aus (BIOS-/Weckquellen
   klären).
4. Umschalten und den ersten Zyklus begleiten:

   ```sh
   # /etc/greenbuddy/schlaf.json: "mode": "aktiv", "dependencies_verified": true,
   # "raid_degradiert_erlaubt": true (Freigabe 06.10.26), "wol_interface": "eno1"
   systemctl restart gb-schlaf.service
   tail -f /var/log/greenbuddy/schlaf.jsonl
   ```

   Zum Fensterende muss `"ereignis": "aufgewacht"` mit `"geweckt_durch": "rtc"`
   im Log stehen.

Abschalten: `touch /etc/greenbuddy/aus` wirkt im nächsten Takt und auch während
der Schlussprüfung. Dauerhaft zurück in den Schatten: `"mode": "schatten"` und
`systemctl restart gb-schlaf.service`. Notschalter nur für den Weckweg:
`"stellvertreter_pflicht": false` und `systemctl restart gb-schlaf.service` – vhost01
schläft dann wie in beta.4 ohne Register, proxy01 übernimmt nie, geweckt wird nur
per RTC-Wecker und `gb-wecken`.

`gb-schlaf --einmal` bleibt eine Diagnose: Der frische Prozess steht in der
Mindestwachzeit und suspendiert deshalb nie.

## Wachseite filtert Spam (vhost01)

Live-Befund 13.10.26 (beta.5 seit 12.10. 20:53 auf vhost01 und proxy01): vhost01
schlief im Tagschlaffenster nie ein, weil die 45-min-Ruhezeit laufend neu startete.
Jede aufgebaute Verbindung auf einem lauschenden Port mit fremder Gegenstelle war ein
Veto `verbindung:<port>`. Aus dem Internet erreichbar sind 32400 (Plex), 25565
(ohnehin Ausnahme) und weitere weitergeleitete Ports, etwa 8443 und 8880. Der
Mitschnitt sah in 55 min 2.221 WAN-Flüsse auf 32400, davon
genau einen mit gültigem SNI; Scanner hielten bis zu 46 Runden `verbindung:32400` ohne
Plex-Sitzung (ein Qualys-Scan mit ~30 vollständigen TLS-Verbindungen), 18 Runden
`verbindung:8880`, dazu stündlich um :01 eine Verbindung von der eigenen WAN-Adresse
(Haarnadel). Der Weckweg auf proxy01 filtert genau diese Scanner schon. Seit beta.6
gilt darum auf der Wachseite: Eine Verbindung aus dem WAN hält vhost01 nur noch wach,
wenn sie ihn über proxy01 auch wecken dürfte.

```text
gb-mitschnitt ── Klassifikation ── wuerde_wecken aus dem WAN ──▶ /run/greenbuddy/legitim/vhost01.json
              └─ wan_name ── Hintergrundfaden ── eigene_wan_ip ──▶        (tmp + rename, ≤ 30 s)
gb-schlaf ── ss -Htn ── Gegenstelle öffentliche IPv4? ── legitim oder Allowlist? ── zählt
                                                    └─ sonst Diagnose, kein Veto
```

**Legitim** ist eine WAN-Quell-IP, für die der Mitschnitt `wuerde_wecken` entschieden
hat (gültiges Plex-SNI auf 32400, Minecraft-Login aus der Whitelist auf 25565), oder
eine IP aus `legitim_quellen` für genau diesen Port, etwa
`{"8443": ["203.0.113.10"]}` wie `quellen_ports` auf proxy01 (gedacht für das
Threema-Gateway: 8443 bleibt im Mitschnitt sonst immer `unklar`). Eine legitime IP
zählt auf allen Ports (eine Plex-App-IP ist ein echter Mensch), eine Allowlist-IP nur
auf ihrem Port. Wie proxy01 (Weg 7) prüft der Mitschnitt dabei das SNI-Label: die
gestrichelte LAN-IP des Ziels oder die aktuelle WAN-IP, bei unbekannter WAN-IP jede
öffentliche IPv4. Forschungsscanner mit gültigem Hash-Suffix, aber fremdem Label,
bleiben `spam`; die Logzeilen des Mitschnitts tragen seither `sni_label`. Spam,
Unklares, LAN/VPN und die eigene WAN-Adresse werden nie eingetragen. Weitere
Anfragen in einem legitimen Fluss (Keep-alive ohne neuen Handshake) setzen „zuletzt
gesehen“ höchstens alle 10 s neu, aber nur, solange der Mitschnitt den Fluss kennt
(60 s nach dem letzten Paket mit Nutzdaten vergisst er ihn). Ein Download über eine
einzige Anfrage schickt nach dem ClientHello nur noch ACKs, die der BPF nicht erfasst:
Sein Eintrag verfällt nach `legitim_ttl_s`. Dass die Verbindung trotzdem zählt, regelt
gb-schlaf (siehe unten).

**Die Datei** `/run/greenbuddy/legitim/vhost01.json` (Schlüssel `legitim` in beiden
Konfigurationen) schreibt ausschließlich gb-mitschnitt, atomar (temporäre Datei im
selben Verzeichnis, fsync, rename): bei einer neuen Quelle, einer verfallenen oder
einer geänderten eigenen Adresse sofort (höchstens einmal je Sekunde), sonst als
Herzschlag alle 30 s, auch ohne Änderung.

```json
{"version": 1, "zeit": 1760350000.5, "ttl_s": 3600, "letztes_paket": 1760349999.8,
 "quellen": {"203.0.113.5": 1760349990.1}, "eigene_wan_ip": ["198.51.100.1"]}
```

`"zeit"` ist die Schreibzeit, `"quellen"` hält je IP den Zeitpunkt, zu dem sie zuletzt
gesehen wurde (nie später als `"zeit"`), `"ttl_s"` die Gültigkeit der Einträge;
`"letztes_paket"` ist der Zeitpunkt, zu dem der Mitschnitt zuletzt irgendein Paket für
das Ziel erfasst hat (bis zum ersten der Start, nie später als `"zeit"`);
`"eigene_wan_ip"` (Liste der A-Records) fehlt, solange die eigene Adresse unbekannt
ist. Einträge verfallen nach `legitim_ttl_s` (Standard 3600); höchstens `legitim_max`
(4096) Einträge, die am längsten nicht gesehenen fliegen zuerst. Schreibfehler stehen
einmal je Fehlerserie als `legitim_schreibfehler` im Mitschnitt-Log. Das Verzeichnis
gehört gb-mitschnitt (0700, per tmpfiles und Installer) und ist der einzige Pfad unter
`/run/greenbuddy`, den dessen Unit schreiben darf; Ansprüche, Takt-Stempel und Lock
bleiben root. Die Datei ist 0600, gb-schlaf liest sie als root über
`CAP_DAC_READ_SEARCH`, das seine Unit schon hat.

**Haarnadel.** Die eigene öffentliche Adresse löst gb-mitschnitt aus `wan_name` auf
(leer = aus). Es ist derselbe Hintergrundfaden wie auf proxy01 (Modul `wan.py`):
höchstens alle 10 min, nach 2 s ohne Antwort unbekannt, die Mitschnittschleife
blockiert nie. Verbindungen von dieser Adresse zählen in gb-schlaf nicht (wie
Verbindungen zu sich selbst), und sie wird nie legitim. Unbekannt oder ohne
`wan_name` gibt es keine Haarnadel-Ausnahme.

**gb-schlaf** liest die Datei in jeder Runde. Als WAN gilt eine öffentliche IPv4
außerhalb von `lan` und `vpn` (Standard wie im Mitschnitt 192.168.1.0/24 und
10.0.0.0/24), auch als `::ffff:`-gemappte Adresse (Caddy lauscht dual-stack). LAN,
VPN, Loopback, die eigenen Adressen, nicht öffentliche IPv4 (Container-Netze, CGNAT,
Link-local) und IPv6 zählen wie bisher: Der Mitschnitt sieht nur IPv4, eine
IPv6-Gegenstelle könnte nie legitim werden. Eine WAN-Gegenstelle zählt nur mit einem
Eintrag, der auch nach gb-schlafs eigener Uhr jünger als `ttl_s` ist, oder mit einem
Allowlist-Treffer. 8880 braucht darum keinen Sonderfall: WAN
zählt dort nie, LAN und VPN zählen weiter. Legitimität hängt danach an der
Verbindung, nicht an der Quell-IP: Eine einmal als legitim gezählte WAN-Verbindung
(Schlüssel aus beiden Adressen und Ports) merkt sich gb-schlaf und zählt sie weiter,
solange sie aufgebaut ist, auch wenn der Eintrag ihrer Quelle verfallen ist oder der
Mitschnitt neu gestartet wurde (Review 13.10.26: Download über eine einzige Anfrage).
Eine neue Verbindung derselben IP braucht wieder einen frischen Eintrag. Die
Merkliste lebt im Speicher von gb-schlaf: Eine unklare Runde und die Rückfallebene
leeren sie nicht (ohne Filter wird aber nichts neu gemerkt), ein Neustart von gb-schlaf
schon. Die Ruhe-Regel (`verbindung_ruhe_ports`) gilt unverändert für die gezählten
Verbindungen, `verbindung_ausnahmen` ebenso; eine gemerkte Verbindung im Leerlauf hält
also nicht wach.

Diagnose-Fakten im Schlaflog (nur Zähler, nie Adressen): `legitim` mit `"ok"`,
`"fehlt"`, `"veraltet"`, `"zukunft"`, `"still"`, `"ungueltig"` oder `"aus"`;
`verbindungen_wan_ignoriert` und `verbindungen_haarnadel` je als `{port: anzahl}`;
`verbindungen` zählt nur noch, was zählt.

**Rückfallebene.** Fehlt die Datei, ist sie unlesbar, kein reguläres File, ein
Symlink, nicht im Besitz von root oder gb-mitschnitt, gruppen- oder weltschreibbar,
größer als 1 MiB oder schemawidrig, ist `"zeit"` älter als `legitim_max_alter_s`
(Standard 180) oder mehr als 60 s in der Zukunft oder `"letztes_paket"` älter als
`legitim_stille_s` (Standard 900), filtert gb-schlaf nicht: Jede Verbindung zählt wie
in beta.5, und `legitim` nennt den Grund. Das ist nie `unklar`,
das würde den Schlaf ganz sperren. Ein gestoppter Mitschnitt und der Abschalter
`/etc/greenbuddy/aus` (der Mitschnitt schreibt dann nicht) führen so nach spätestens
180 s zurück zu beta.5. Ebenso ein `plex_hash` ohne die Form aus der Klassifikation
(6–64 Hexziffern, etwa der Platzhalter der Vorlage): Damit würde keine Plex-Quelle je
legitim, eine frische Datei mit leerer Liste hieße aber `"ok"` und ließe jede
WAN-Verbindung fallen. Der Mitschnitt schreibt dann keine Datei und meldet beim Start
einmal `legitim_aus` (Review 13.10.26). Die Stille-Grenze prüft dieselbe Tatsache
für die Erfassung: Eine frische Datei beweist nur, dass die Schleife läuft. Live
kommen etwa 40 Scanner-Flüsse je Minute auf 32400; erfasst der Mitschnitt 15 min lang
kein einziges Paket (etwa ein falsches `target`), kann er nichts als legitim erkennen.
Ohne Code zurück: `"wan_filter": false` in `schlaf.json`.

Neue Schlüssel (die Konfig-Prüfung behandelt Formfehler wie im Bestand):

| Datei | Schlüssel | Standard | Bedeutung |
|---|---|---|---|
| `schlaf.json` | `wan_filter` | `true` | `false` = beta.5-Verhalten |
| `schlaf.json` | `legitim` | `/run/greenbuddy/legitim/vhost01.json` | Datei lesen |
| `schlaf.json` | `legitim_max_alter_s` | `180` | älter = Rückfallebene |
| `schlaf.json` | `legitim_stille_s` | `900` | so lange kein erfasstes Paket = Rückfallebene |
| `schlaf.json` | `legitim_quellen` | `{}` | Allowlist je Port |
| `schlaf.json` | `lan`, `vpn` | `["192.168.1.0/24"]`, `["10.0.0.0/24"]` | wie im Mitschnitt |
| `mitschnitt.json` | `legitim` | `/run/greenbuddy/legitim/vhost01.json` | Datei schreiben |
| `mitschnitt.json` | `legitim_ttl_s` | `3600` | Gültigkeit eines Eintrags |
| `mitschnitt.json` | `legitim_max` | `4096` | Obergrenze der Einträge |
| `mitschnitt.json` | `wan_name` | `""` (aus) | DNS-Name der eigenen WAN-Adresse |

## Weckweg über proxy01 (Wege 4, 5 und 7)

Schläft vhost01 registriert, hält proxy01 dessen Adresse 192.168.1.110, erkennt
echte Zugriffe und weckt per WOL. nas01 wird nie übernommen (Plan R11). Den Ablauf
trägt `gb-stellvertreter` in einer select-Schleife; Register und Statusbericht sind
Dateien.

```text
vhost01 (gb-schlaf)                    proxy01 (gb-proxy-ssh, gb-stellvertreter)
abmelden Z            ───────────────▶ bereit? Statusbericht ≤ 15 s, vhost01 in bereit_fuer
schlafe-jetzt Z S     ───────────────▶ schlaf_absicht, Lease S + 15 min (BOOTTIME, boot_id)
systemctl suspend                      warte_stille: 3 s ohne ARP der echten MAC
                                       uebernommen: nft-Tabellen, Alias .110, Listener, GARP
                      ◀── WOL-Serie ── SYN / SNI / Login ─ Limits ─ wecken
Resume, gb-garp       ───────────────▶ erster Frame der echten MAC ─ frei
anmelden Z            ───────────────▶ angemeldet; Antwort mit weckung
```

**Phasen** `frei → warte_stille → uebernommen (→ wecken) → frei`. In `frei` liest
der Dienst das Register jede Sekunde (neu nur bei geänderter Datei). Ein Host in
`schlaf_absicht` mit gültigem Lease wechselt nach `warte_stille`: ein Raw-Socket an
eth0 nimmt per Kernel-cBPF nur ARP der echten MAC und ARP anderer Geräte mit Absender
.110 an, je Sekunde geht eine ARP-Probe who-has .110 tell .100 hinaus. Erst `stille_s`
(3 s) ohne ARP der echten MAC führen zur Übernahme; bleibt die Stille `stille_max_s`
(10 min) aus, kehrt der Dienst ohne Übernahme nach `frei` zurück
(`stille_ausgeblieben`: der Host ist wach). Meldet sich ein anderes Gerät mit .110
(vhost01 mit gewechselter MAC nach NIC-, Bridge- oder Bond-Umbau, ein Adresskonflikt),
übernimmt der Dienst nicht (`fremde_mac` mit der MAC im Protokoll, Zyklus erledigt,
WOL-Serie an die konfigurierte MAC; Spec 3.7 „bei Zweifel WOL statt Alias“).
Übernahme: Vorprüfung (sysctls, eigene MAC ≠ Host-MAC, Adresse nicht lokal,
`listen_ip` an eth0, keine eigene Tabelle vorhanden, Raw-Socket möglich) → Filter
auf „echte MAC, fremdes ARP mit Absender .110 oder SYN an .110“ umstellen, Raw-Socket
an wg0 (`vpn_interface`) öffnen → nft-Tabellen `ip gb2_sv_vhost01` und
`arp gb2_sv_vhost01_arp` → Alias `192.168.1.110/32` an eth0 → Listener auf
.110:32400 und .110:25565 → GARP bei 0, 1 und 3 s, danach alle `garp_s` (60 s). Jeder
Schritt wird an Tatsachen geprüft (`ip -j`, `nft -j`), nie am Exit-Code allein;
scheitert einer, wird das Angelegte entfernt und vhost01 sofort per WOL-Serie geweckt
(`uebernahme_fehlgeschlagen`). Das gilt auch, wenn `ip` oder `nft` die 2-s-Frist erst
nach der Änderung reißen (rtnl_lock bzw. commit_mutex auf dem Pi): ein so gesetzter
Alias wird wieder entfernt, Tabellen erkennt der Dienst an der Marke dieses
Ladeversuchs im Regelkommentar (`gb2-<pid>-<zufall>`) und löscht nur diese, nie eine
fremde gleichnamige. Solange eine WOL-Serie läuft, heißt `uebernommen` im Bericht
`wecken`.

**Isolation.** Die ip-Tabelle (input und output, Priorität -300) verwirft alles an
.110 außer den Inhaltsports (32400 nur aus dem WAN, 25565 von allen), alles von
ausgenommenen Quellen und jeden lokalen Ausgang an .110. Dienste von proxy01, die auf
0.0.0.0 lauschen, antworten unter .110 weder mit SYN-ACK noch mit RST. Lokale
Verbindungen von proxy01 an .110 (auch `gb-wecken`) enden im
Timeout. Die arp-Tabelle verwirft ARP mit der Absender-MAC von vhost01: proxy01s
Kernel beantwortet dessen Proben beim Aufwachen nie, eine Doppelbelegung entsteht
nicht.

**Auslöser** (Plan R3, Konfig je Host):

| Port | Quelle | Behandlung | weckt, wenn | Weg | Limit |
|---|---|---|---|---|---|
| 22, 8096, 32400 | LAN, VPN | DROP, SYN am Raw-Socket (eth0, wg0) | immer | 4 | LAN 3/h je Quelle, VPN 6/h je Peer |
| 32400 | WAN, auch Haarnadel | Handshake am Listener, dann RST | TLS-SNI `<label>.<hash>.plex.direct`, Label = gestrichelte LAN-IP von vhost01 (`192-168-1-110`) oder aktuelle WAN-IP | 7 | WAN 3/h je Quelle, 4/h und 12/Tag je Host |
| 25565 | alle | Handshake am Listener, dann RST | Minecraft-Login (kein Status-Ping) mit Namen aus `minecraft_whitelist` | 4 (LAN/VPN), 7 (WAN) | je Quellklasse wie oben |
| 8443 | nur Quellen aus `quellen_ports` | DROP, SYN am Raw-Socket | immer | 5 | 6/h (`liste_h`), nicht in den WAN-Limits |
| alle übrigen | alle | DROP | nie | – | – |

Ausgenommen sind 192.168.1.100, .115 und .1 (`ausgenommen`, nft-Drop, der Listener
prüft es ein zweites Mal). Ein SYN auf 8443 von einer anderen Quelle ist
`verworfen`, ein WAN-SYN auf 22 oder 8096 `ignoriert`. Die WAN-IP für das SNI-Label
löst ein Hintergrundfaden aus `wan_name` auf, nur solange ein Host nicht `frei` ist
(10 min gültig, 2 s Frist; die Schleife blockiert nie). Unbekannt oder ohne
`wan_name` ist jede öffentliche IPv4 als Label zulässig, die Weckzeile trägt dann
`wan_ip_unklar`; die Limits begrenzen den Schaden. Forschungsscanner, die das gültige
Hash-Suffix kennen, senden fremde Labels und wecken so nicht. SNI und Spielernamen
sind Spam-Filter, kein Identitätsnachweis. Am Listener gelten höchstens 64
gleichzeitige Verbindungen, 16 KiB und 5 s je Verbindung.

**Wecken** (Plan R4): Eine Weckentscheidung startet eine WOL-Serie an die MAC von
vhost01, sofort und dann alle `wol_wiederholen_s` (15 s) bis `wol_max_s` (180 s)
oder bis zum ersten Frame der echten MAC; tote RAID-Platten verzögern das Einschlafen
bis ~60 s, ein einzelnes Paket verpufft dort. Der Alias bleibt währenddessen stehen
(Plan R2): Clients bekommen weder RST noch „No route to host“, sondern wiederholen
ihre SYNs und erreichen den erwachten Host. Nachfrage während einer Serie wird nicht
gezählt (`wecken_laeuft`). Endet die Serie ohne Lebenszeichen, protokolliert der
Dienst `wecken_gescheitert`; der Alias bleibt, die Lebendprobe schützt, neue
Nachfrage darf innerhalb der Limits erneut wecken.

**Limits** (Spec 3.7, Schlüssel `limits`): `wan_quelle_h` 3, `wan_host_h` 4,
`wan_host_tag` 12, `lan_quelle_h` 3, `vpn_quelle_h` 6, `liste_h` 6 in rollenden
Fenstern; `0` schaltet den Weg ab. Gezählt wird nur eine tatsächlich begonnene
Weckung. Ein volles Limit steht je Stunde, Limit und Quelle einmal als Zeile
`entscheidung: limit` im Log, weitere Treffer nur verdichtet. Die Fenster liegen nur
im Speicher, ein Dienstneustart setzt sie zurück; den Wecksturm begrenzt weiterhin
vhost01 (höchstens sechs Schlafzyklen in 24 Stunden).

**Freigabe** in der Reihenfolge Alias → Listener → Tabellen → Zustand, ausgelöst
durch:

- jeden Frame der echten MAC (Kernel-cBPF auf `ether src` am Raw-Socket): im
  Netztest war der Alias 2,2–5 ms nach dem Rahmen weg, die Tabellen nach 27–44 ms
  (Ziel < 100 ms); bei laufender Serie mit `wecken_erfolg` und deren Dauer;
- jedes ARP eines anderen Geräts mit Absender .110 (`fremde_mac`): die Adresse gehört
  gerade jemand anderem, etwa vhost01 mit gewechselter MAC; Zyklus erledigt,
  WOL-Serie an die konfigurierte MAC (läuft schon eine, bleibt sie);
- das Register: `angemeldet`, ein neuer Zyklus, `lease_abgelaufen` oder eine
  fehlende Zeile;
- den Lease-Ablauf (Sekunden bis zum RTC-Wecker + 15 min, auf BOOTTIME von
  proxy01): Freigabe und WOL-Serie (`lease_abgelaufen`) – der Rückfall, wenn vhost01
  zum RTC-Termin nicht erscheint;
- den Abschalter `/etc/greenbuddy/aus`: Freigabe und WOL-Serie (Spec 3.7);
- das Dienstende (Stopp, SIGTERM): Freigabe ohne WOL. Abschalter und Dienstende
  erledigen den Zyklus nicht; nach einem Neustart übernimmt der Dienst nach erneuter
  Stille wieder.

Steht im Register eine fremde oder keine boot_id (proxy01 neu gestartet, altes
Register), übernimmt proxy01 nicht, sondern weckt (`lease_unklar`, Spec 3.7 „bei
Zweifel WOL“). Weicht der Alias nicht, bleiben die Tabellen stehen (Isolation vor
Vollständigkeit); der Dienst versucht es alle 10 s und beim Dienstende erneut und
meldet bis dahin `freigabe_unvollstaendig`. `ExecStopPost` entfernt Alias und beide
Tabellen auch nach SIGKILL (`gb-stellvertreter --aufraeumen`, Exit 0 = sauber,
1 = Artefakte blieben).

**Lebendprobe und GARP.** Während der Übernahme fragt proxy01 alle `lebendprobe_s`
(5 s) who-has .110 tell .100; ist vhost01 unbemerkt aufgewacht, antwortet er mit
seiner echten MAC und löst damit die Freigabe aus. Nach jedem Resume wartet
`gb-garp.service` auf vhost01 höchstens 60 s, bis 192.168.1.110 wieder an eno1 liegt,
und meldet die Adresse per `arping -U -c 3` und `arping -A -c 2`: Box und LAN-Clients
stellen ihren ARP-Eintrag sofort auf die echte MAC um. NetworkManager baut die
WOL-Karte erst nach dem Resume ab und setzt die Adresse per DHCP neu; scheitert
`arping` dabei (Exit 2: ENETDOWN, EADDRNOTAVAIL), wartet `gb-garp` erneut und sendet
wieder, und nach 10 s meldet es die Adresse ein zweites Mal. Freigegeben hat proxy01
zu diesem Zeitpunkt schon; scheitert die Unit (Exit 1, wenn die Adresse 60 s fehlt
oder `arping` so lange scheitert, 2 bei falschen Argumenten), gibt proxy01 trotzdem
beim ersten Frame frei.

**Bereitschaft und Statusbericht.** Der Dienst schreibt spätestens alle 5 s und bei
jedem Phasenwechsel `/run/greenbuddy/status/stellvertreter.json` (gb-stellvertreter:
gb-register, 0640) mit `stellvertretung` (`ok` oder Formfehler), `bereit_fuer`,
`gruende`, `phasen`, `zyklen`, `weckung` je Host (keine IP), `register` und
`wan_ip_bekannt`. Bereit ist vhost01, wenn die Vorprüfung in `frei` besteht (alle
30 s und nach jeder Änderung neu bewertet); während einer Übernahme bleibt der
Befund von davor stehen. Sonst steht in `gruende` einer von `arp_sysctl_ungueltig`,
`arp_sysctl_unklar`, `interface_unklar`, `mac_eigene`, `adressen_unklar`,
`adresse_lokal`, `listen_ip_fehlt`, `tabelle_belegt`, `nft_fehlt`, `nft_unklar`,
`raw_socket_fehlt`, `freigabe_unvollstaendig`, `abgeschaltet`, `dienst_beendet` oder
`unbekannt` (nach einem Dienststart in eine laufende Übernahme). `gb-proxy-ssh`
leitet daraus `bereit` ab (siehe „SSH-Register“).

**Protokoll** `/run/greenbuddy/log/stellvertreter.jsonl` (nur root und das
Dienstkonto): Phasenwechsel mit `von`, `nach`, `grund` und Zyklus, `ausloeser` mit
Quelle, Port, Quellklasse, Weg und `entscheidung` (`wecken` oder `limit`),
`wecken_erfolg`, `wecken_gescheitert`, `wol_serie_ende`, `lease_abgelaufen`,
`lease_unklar`, `fremde_mac` (mit `mac` und `phase`), `uebernahme_fehlgeschlagen`,
`freigabe_unvollstaendig`,
`wan_ip_unklar`, `vpn_socket_fehlt`. Spam, Unklares, ignorierte, verworfene und
ausgenommene Zugriffe zählt der Dienst nur stündlich je Host × Port × Quellklasse ×
Entscheidung (`verdichtet: true`, Plan R9; einzeln wären es ~13 MB am Tag im tmpfs).

**Konfiguration** in `/etc/greenbuddy/stellvertreter.json` unter
`stellvertretung` (Vorlage `deploy/proxy01/stellvertreter.example.json`):
`hosts.vhost01` mit `ip`, `mac`, `syn_ports`, `inhalt_ports`, `quellen_ports` und
`ausgenommen`; optional `probe`; `wan_name`, `vpn_interface` (`wg0`, leer = aus), die
Pfade `register`, `status` und `zustand`, `limits` sowie die Zeiten
`wol_wiederholen_s` 15, `wol_max_s` 180, `stille_s` 3, `stille_max_s` 600, `garp_s`
60 und `lebendprobe_s` 5. Unbekannte Schlüssel, ein anderer Host als vhost01, eine
gesperrte Adresse oder Überschneidungen von `quellen_ports` mit den übrigen Ports
sind ein Formfehler (`stellvertretung_<feld>`): dann gibt es keine Übernahme, der
GDM-Zähler läuft weiter, und vhost01 schläft mangels Bereitschaft nicht. Vor dem
Start die Platzhalter ersetzen: `plex_hash` (der `<hash>` aus
`*.<hash>.plex.direct`; mit dem Platzhalter weckt WAN-Plex nie, die Verbindungen
enden als unklar), `minecraft_whitelist`, `wan_name` (der DDNS-Name, etwa
`home.example.net`; leer = WAN-IP unbekannt) und die Absenderadresse der
Threema-Callbacks in `quellen_ports` (Vorlage: 203.0.113.10). Echte Werte gehören nur
in die Live-Konfiguration, nie ins Repository.

## Notfall-Wecken (proxy01)

`gb-wecken` sendet das Magic Packet an `192.168.1.255:9` und
`255.255.255.255:9`, ausschließlich an MACs aus `/etc/greenbuddy/wecken.json`
(Vorlage: vhost01 `00:00:5e:00:53:10`, nas01 `00:00:5e:00:53:15`, Doku-MACs nach
RFC 7042). Kein Root nötig;
der Abschalter sperrt Schlaf, nie das manuelle Wecken. Per VPN-SSH auf proxy01:

```sh
gb-wecken vhost01               # wiederholt alle 15 s, bis TCP 22 antwortet (höchstens 180 s)
gb-wecken nas01 --nur-senden    # genau ein Versuch, ohne Erreichbarkeitsnachweis
```

Standardmäßig wird wiederholt, weil ein Paket in der Einschlafphase verpufft:
Die toten RAID-Platten verzögern das Einschlafen von vhost01 bis ~60 s, die
NIC vermerkt das Magic Packet, weckt aber nicht (Messung 07.10.26).
Exit 0 = erreichbar (bzw. bei `--nur-senden` gesendet), 1 = nach 180 s nicht
erreichbar, 2 = unbekannter Host oder Konfigurationsfehler (dann wird nichts
gesendet), 3 = kein einziges Paket ging hinaus (Netzfehler auf proxy01).
Ohne proxy01: Ein RTC-Wecker steht vor jedem Schlaf, spätestens zum Ende der
Schlafphase minus Vorlauf wacht vhost01 selbst auf; notfalls Netztaster.
Hält `gb-stellvertreter` gerade die Adresse von vhost01, sieht `gb-wecken` auf
192.168.1.110:22 nur Timeouts (die nft-Tabelle verwirft auch proxy01s eigene
Verbindungen dorthin) und wiederholt WOL, bis vhost01 aufwacht und proxy01 beim
ersten Frame freigibt; Exit 1 nach 180 s heißt dann nicht zwingend „schläft noch“.

## SSH-Register und GB1-Bereinigung

Je Host einen eigenen öffentlichen Schlüssel in die root-eigene Datei
`/var/lib/greenbuddy-ssh/.ssh/authorized_keys` aufnehmen (root:root 0644,
Eltern root:root 0755). Vorlagen stehen in
`deploy/proxy01/authorized_keys.example`; Platzhalter zuerst ersetzen:

```text
command="/usr/local/sbin/gb-proxy-ssh --host vhost01",restrict,from="192.168.1.110" ssh-ed25519 …
```

Das Konto ist `gb-register`; bestehende AllowUsers-/AllowGroups-Regeln müssen
es zulassen. Die SSH-Konfiguration wird nicht automatisch verändert. Eigene
Hostschlüssel vorab vertrauenswürdig bestätigen; auf vhost01 liegen Schlüssel und
known_hosts unter `/etc/greenbuddy/ssh/` (root, Schlüssel 0600), known_hosts mit dem
Hostschlüssel von 192.168.1.100 unter der IP. Das Hostargument kommt
ausschließlich aus der Zwangsbefehlszeile. `abmelden nas01 <zyklus>` mit dem
vhost01-Schlüssel scheitert. Das Register liegt atomar (fsync) unter
`/var/lib/greenbuddy/register.json`; Verzeichnis gb-register:gb-stellvertreter
2750, Datei 0640, damit der Stellvertreter es über die Gruppe liest. Jede Antwort
ist eine JSON-Zeile; kein Befehl nimmt eine IP, MAC oder einen Host entgegen. Die
zulässigen Originalbefehle:

| Befehl | Wirkung im Register | Antwort |
|---|---|---|
| `status` | keine | `host`, `bereit`, `grund`, `zustand`, `stellvertreter` |
| `abmelden <zyklus>` | neue Zeile, Phase `abgemeldet`, Lease 15 min; ein anderer Zyklus ersetzt jeden alten | wie `status` |
| `schlafe-jetzt <zyklus> <sekunden>` | nur bei `bereit: true`: Phase `schlaf_absicht`, Lease `sekunden` + 15 min (Wanduhr sowie BOOTTIME mit boot_id) | wie `status` |
| `anmelden <zyklus>` | Phase `angemeldet` | zusätzlich `weckung` oder `null` |
| `anmelden-abbruch <zyklus>` | Phase `angemeldet` | zusätzlich `weckung` oder `null` |

`<sekunden>` ist eine ganze Zahl von 600 bis 43.200: die Zeit bis zum RTC-Wecker von
vhost01. `bereit` ist nur `true`, wenn der Statusbericht des Stellvertreters
höchstens 15 s alt (und höchstens 5 s in der Zukunft) ist und vhost01 in
`bereit_fuer` steht (Plan R1). Sonst nennt `grund` `stellvertreter_status_fehlt`,
`stellvertreter_status_alt`, `stellvertreter_nicht_bereit` oder `abgeschaltet`;
`stellvertreter` zeigt dazu Phase, Alter und Grund aus dem Bericht. Ohne
Bereitschaft bleibt `schlafe-jetzt` wirkungslos (Phase bleibt `abgemeldet`,
Exit 0), damit proxy01 nicht übernimmt, während vhost01 abbricht. Wiederholungen mit
derselben Zyklus-ID verlängern keinen Lease; ein schon beendeter Zyklus lässt sich
nicht erneut abmelden (`zyklus_beendet`). Ein neuer Zyklus ersetzt jeden alten,
auch einen laufenden; der Stellvertreter gibt dann frei, ein abgestürzter vhost01
ist so nie bis zum Lease-Ende gesperrt. Ein abgelaufener Lease wird beim nächsten
Befehl als `lease_abgelaufen` eingetragen. `weckung` (Zeit, Weg 4/5/7, Port,
Quellklasse, Entscheidung; ohne Nachfrage geweckt: Weg, Port und Quellklasse
`null`) kommt nur, wenn die letzte Weckung nach dem `abmelden` dieses Zyklus lag.
Fehler enden mit Exit 1 und `{"bereit": false, "fehler": "<code>"}`:
`befehl_unbekannt`, `befehl_argumente`, `sekunden_ungueltig`, `zyklus_ungueltig`,
`zyklus_passt_nicht`, `zyklus_beendet`, `lease_abgelaufen`,
`ssh_argumente_ungueltig`, `register_schema`, `register_symlink`, sonst
`befehl_oder_register_ungueltig`. Unter dem Abschalter schreiben `abmelden` und
`schlafe-jetzt` nichts (Antwort `bereit: false`, `grund` und `entscheidung`
`abgeschaltet`, Exit 0); `anmelden` und `anmelden-abbruch` schreiben weiter, weil sie
nur beenden.

Die separate Altbereinigung auf proxy01 ausführen:

```sh
/usr/local/sbin/gb-bereinigen-gb1
```

Sie meldet zuerst die Existenz der GB1-Units und prüft bei anderen Units
`Requires`, `Wants`, `After` sowie Verweise auf `config.yaml`, einschließlich
genannter Skripte. Bei Abhängigkeiten oder Konfig-Verbrauchern meldet sie
die betroffenen Units und verändert weder Units noch Dateirechte.
Ohne solche Abhängigkeiten setzt sie vorhandene `/opt/greenbuddy/config.yaml`
und `access_token*.txt` auf 0600 und stoppt/deaktiviert/maskiert GB1-Dienste. Lokale
Unitdateien werden gegebenenfalls gesichert. Sie löscht keine Datei und
fasst insbesondere `wol_housekeeping_plex.timer` nicht an.

Rückweg der separaten GB1-Bereinigung, nur für zuvor vorhandene Units:

```sh
systemctl unmask greenbuddy-manager.service greenbuddy.service
# Vorhandene lokale Unit-Backups wieder an ihren ursprünglichen Ort legen:
mv /etc/systemd/system/greenbuddy.service.bak-gb2 /etc/systemd/system/greenbuddy.service
# Entsprechend greenbuddy-manager.service.bak-gb2 zurücklegen, falls vorhanden.
systemctl daemon-reload
# Nur die zuvor tatsächlich genutzten GB1-Dienste wieder aktivieren/starten.
```

## Probe ohne Produktions-IP (proxy01)

Der Probe-Modus ersetzt den Phantom-Test (`arp.py`, `phantom_test`). Er übt die
ganze Übernahme mit der Adresse aus `stellvertretung.probe` (Vorlage 192.168.1.199
mit Dummy-MAC `02:00:00:00:00:99`, `syn_ports` [22], `inhalt_ports` [32400, 25565])
und lädt dabei den nft-Regelsatz echt: Scheitert die Syntax unter nft 1.0.2 auf
proxy01, meldet er `uebernahme_fehlgeschlagen` mit `nft_laden`. Antwortet ein
Gerät auf die ARP-Proben für die Probe-Adresse, übernimmt die Probe nicht und endet
ohne GARP (`fremde_mac` mit dessen MAC auf stdout). Die Probe-Adresse trotzdem vorher
als frei bestätigen (außerhalb des DHCP-Bereichs, von vhost01
`arping -c 2 -I eno1 192.168.1.199` ohne Antwort): Ein Gerät, das die drei Proben im
Stillefenster verschläft (WLAN-Energiesparen), bemerkt die Probe erst bei dessen
nächstem ARP; bis dahin zeigen die ARP-Caches im LAN auf proxy01.
Gesperrt bleiben .1, .100, .115, `listen_ip` und die Adresse von vhost01.

```sh
sudo gb-stellvertreter --probe 300
```

Die Probe läuft ohne Register und GDM, übernimmt nach 3 s Stille und hat eigene
Tabellen (`ip gb2_sv_probe`, `arp gb2_sv_probe_arp`), einen eigenen Zustand
(`uebernahme-probe.json`) und ein eigenes Protokoll (`stellvertreter-probe.jsonl`,
jede Zeile zusätzlich auf stdout); sie verträgt sich mit dem laufenden Dienst.
Prüfungen von vhost01 aus, während sie läuft:

```sh
ssh -o ConnectTimeout=5 192.168.1.199 true     # Timeout ohne Banner von proxy01; stdout: ausloeser, weg 4, port 22
openssl s_client -connect 192.168.1.199:32400 -servername 192-168-1-199.<hash>.plex.direct </dev/null   # weckt, RST
openssl s_client -connect 192.168.1.199:32400 -servername 192-168-1-110.<hash>.plex.direct </dev/null   # Spam, RST
```

Jede Weckung startet eine harmlose WOL-Serie an die Dummy-MAC (180 s); Nachfrage
währenddessen erscheint nur verdichtet als `wecken_laeuft`. Darum je Lauf einen
Auslöser prüfen oder drei Minuten Abstand halten; Spam und Verdichtetes stehen am
Ende der Probe auf stdout. Die Freigabe durch die echte MAC lässt sich mit der
Dummy-MAC nicht prüfen; sie zeigt sich beim ersten echten Aufwachen.

Nach Ablauf gibt die Probe ohne WOL frei (`probe_ende`). Exit 0 = sauber, 1 = Alias
oder Tabelle blieben, 2 = Konfig- oder Sekundenfehler (1–900). Danach – und nach
Strg-C oder Absturz – als root aufräumen: Die Zustandsdatei einer als root
gestarteten Probe gehört root, `--aufraeumen` des Dienstkontos (`ExecStopPost`) lässt
sie stehen (`probe_unklar`), eine noch laufende Probe ebenso (`probe_laeuft`).

```sh
sudo gb-stellvertreter --aufraeumen   # {"entfernt", "fehler", "uebersprungen"}; Exit 0 = sauber
ip -4 addr show dev eth0              # 192.168.1.199 ist weg
sudo nft list tables                  # keine gb2_sv_probe-Tabelle
```

## Webhook-Baustein (aus)

`deploy/proxy01/webhook.example.json` ist nur eine Vorlage. Der Baustein bindet
an 127.0.0.1 und ist für einen späteren Caddy gedacht. Methode, Pfad,
Content-Length, Body-Limit 64 KiB und Formulartyp werden vor der
Annahme geprüft. MAC ist HMAC-SHA256 über die unveränderten Formularwerte
`from+to+messageId+date+nonce+box` mit dem Secret aus einer 0600-Datei;
Vergleich über `hmac.compare_digest`. Optionale Zusatzfelder wie `nickname`
werden ignoriert, höchstens zwölf Formularfelder sind erlaubt.
Nach gültigem MAC und passender Gateway-ID werden auch alte oder zeitlich
unklare Nachrichten angenommen. Nur plausible Nachrichten bis zehn Minuten
Alter (höchstens 30 Sekunden in der Zukunft) erhalten `darf_wecken=true`.
Die gültige Quellrate zählt erst nach MAC-Prüfung und begrenzt ausschließlich
das Schattenereignis; ungültige MACs werden separat gedrosselt. X-Forwarded-For
wird nur beim Peer 127.0.0.1 ausgewertet. Jeder Handler hat fünf Sekunden
Timeout; ein ThreadingHTTPServer verhindert Blockade durch stille Verbindungen.
`messageId` wird mindestens sieben
Tage persistent dedupliziert. Ein Replay erzeugt kein zweites Weck-Ereignis.

Die SQLite-Warteschlange nutzt `synchronous=FULL`, 24 Stunden TTL und Limits
von 500 Einträgen/5 MiB. Erst nach Commit und erneuter Lesbarkeit gibt es 200;
bei Überlauf/Schreibfehler 503. `secure_delete` entfernt abgearbeitete Inhalte
aus freien Datenbankseiten. Die Nutzdaten sind die weiterhin verschlüsselten
Callback-Formulare; sie stehen niemals im Log. Abgelaufene Einträge alarmieren
im Log, ebenso offene Einträge über fünf Minuten. Es wird kein Alarm versandt.

Bei einem angemeldeten vhost01 liefert der Dienst sofort im nächsten Durchlauf
weiter; nach Resume werden ältere Einträge strikt vor neueren ausgeliefert.
Der Upstream bekommt `X-GreenBuddy-Eingangs-ID` und muss bei 2xx dieselbe ID
im Antwortheader `X-GreenBuddy-Quittung` zurückgeben. Zusätzlich überträgt
`X-GreenBuddy-Darf-Wecken` die Frischefreigabe (0/1); sie verfällt auch während
der Wartezeit in der Queue. Ohne diese Quittung bleibt
der Eintrag erhalten. Bei einem Absturz nach Upstream-Annahme kann eine
Nachlieferung erfolgen: auch der Upstream muss die Eingangs-ID deduplizieren.
Der Upstream muss als LAN-Ziel erreichbar sein. Caddy/Router,
Gateway-Test und Quittung sind Voraussetzungen einer späteren Aktivierung.

## Abschalter und Rückbau

```sh
touch /etc/greenbuddy/aus
```

Die Datei sperrt jede Automatik: kein Suspend, kein RTC-Wecker; Dienste protokollieren nur `abgeschaltet`,
Mitschnitt und GDM-Sockets werden geschlossen. Auf proxy01 gibt `gb-stellvertreter`
eine Übernahme sofort frei, weckt einen registriert schlafenden vhost01 per WOL-Serie
(Spec 3.7) und übernimmt nicht neu; der Statusbericht meldet `abgeschaltet`. Das
Register antwortet `bereit: false` mit `grund` `abgeschaltet` und trägt keine
Schlafabsicht ein; `anmelden` und `anmelden-abbruch` schreiben weiter. Auf vhost01
gilt die eigene Datei (kein Suspend). Nur den Weckweg abschalten:
`"stellvertreter_pflicht": false` auf vhost01 (siehe „Aktiver Schlaf“).
Die Legitim-Datei schreibt der Mitschnitt dann nicht mehr; nach 180 s zählt gb-schlaf
wieder jede Verbindung wie in beta.5 (siehe „Wachseite filtert Spam“).
Ein absichtlich gestarteter Webhook nimmt in diesem Zustand nichts an und
liefert nichts aus. Entfernen der Datei erlaubt erneute Beobachtung.
Für einen vollständigen sofortigen Stopp die eigenen GB2-Dienste stoppen.
`systemctl stop gb-stellvertreter.service` gibt die Adresse ohne WOL frei: ein
schlafender vhost01 wacht dann erst zum RTC-Termin auf (oder per `gb-wecken`);
darum proxy01 möglichst stoppen oder zurückbauen, während vhost01 wach ist.

Rückbau je Host:

```sh
bash /root/greenbuddy2/rueckbau.sh
```

Er stoppt/deaktiviert ausschließlich die eigenen Units, entfernt installierte
Dateien und eigene Trust-Einträge und stellt Backups samt Trust wieder her.
Die aktuelle `/etc/greenbuddy/*.json`-Konfiguration sowie Datenverzeichnisse
mit Logs, Register, Ansprüchen und ergänzten Schlüsseln werden vor dem
Entfernen der Konten nach `*.bak-gb2-<datum>` verschoben. Vorhandene frühere
Konfigurationen werden aus `*.bak-gb2` wiederhergestellt. Für eine spätere
Neuinstallation gewünschte Daten/JSON-Dateien aus den datierten Backups
bewusst zurücklegen; verwaiste GB2-Besitzer werden dann übernommen.
GB1-Masken aus der
separaten Bereinigung werden nicht automatisch aufgehoben. Der Stopp von
`gb-stellvertreter` gibt Alias und Tabellen frei; nach SIGKILL oder einer Probe
`gb-stellvertreter --aufraeumen` als root verwenden (entfernt auch die Altlast
`ip gb2_phantom` aus beta.1/2) und mit `ip -4 addr show dev eth0` und
`nft list tables` prüfen, dass weder 192.168.1.110 noch eine `gb2_sv_*`-Tabelle
übrig ist. Ein Neustart des Hosts entfernt die flüchtigen Aliasse, Tabellen und
tmpfs-Beobachtungsdaten ohnehin. Die ARP-sysctls bleiben nach dem Rückbau bis zum
nächsten Neustart wirksam, obwohl die Datei `/etc/sysctl.d/60-greenbuddy-arp.conf`
entfernt ist; sofort zurück auf die Werte von vorher (auf proxy01 0) mit
`sysctl -w net.ipv4.conf.all.arp_ignore=0 net.ipv4.conf.all.arp_announce=0
net.ipv4.conf.eth0.arp_ignore=0 net.ipv4.conf.eth0.arp_announce=0`. Von Hand
ergänzte ufw-Regeln bleiben. Auf vhost01 entfernt der Rückbau Skript, Unit und
wants-Link von `gb-garp`; Schlüssel und known_hosts unter `/etc/greenbuddy/ssh/`
bleiben stehen.

## Abweichungen von der Spec

Offene Verbindungen auf 25565 sind kein Veto: lazymc hält Scanner-Verbindungen
auch ohne Minecraft-Spieler. Am 06.10. wurden 7 Verbindungen von 3 WAN-Adressen
beobachtet. Ein Java-Prozess mit dem konfigurierten Minecraft-Argument bleibt
ein Nutzungssignal; 25565-Verbindungen bleiben als Diagnose im Log.

Weckweg (beta.5, Bauplan vom 12.10.2026):

- Bereitschaft über den Statusbericht des Dienstes (höchstens 15 s alt), nicht per
  Test-Nonce über proxy01s eigene Adresse (Spec 3.2 Phase A; Plan R1). Kosten bei
  Irrtum: vhost01 schläft nicht.
- Der Alias bleibt während des Weckens stehen statt „Freigabe vor jedem WOL“
  (Spec 3.5), und WOL läuft alle 15 s bis 180 s statt dreimal in 90 s (Plan R2/R4):
  LAN-Clients wiederholen sonst nicht, und ein Paket in der bis zu 60 s langen
  Einschlafphase verpufft. Doppelbelegung verhindern die arp-Tabelle, die Freigabe
  beim ersten Frame und die Lebendprobe.
- Ein SYN aus LAN oder VPN auf 22, 8096 oder 32400 weckt ohne gelernte Client-ID
  (Spec 3.5 verlangt sie für Plex und Jellyfin; Inhalte sind in TLS nicht lesbar).
  WAN-Plex weckt mit der Label-Regel, Weg 5 ist ein SYN einer Allowlist-Quelle auf
  8443, nicht der geprüfte Webhook. GDM (Weg 3) bleibt eine Zählung, die
  VPN-Weckadresse (Weg 6) ist nicht gebaut; VPN-SYNs auf 22/8096/32400 wecken.
- Die proxy01-Dienste sind nicht auf `ListenAddress 192.168.1.100` gebunden (Spec 3.5
  Isolation); unter .110 isoliert sie allein der nft-Drop (im Netztest belegt).
- IPv6 ist nicht abgedeckt, die Übernahme gilt nur für IPv4 (Spec 3.5); vhost01 hat
  IPv6 aus. Die Unit erlaubt kein AF_INET6: erzwingt die Namensauflösung einen
  IPv6-Socket, bleibt die WAN-IP unbekannt (jedes öffentliche Label zählt, die Limits
  greifen).
- Limits liegen nur im Speicher; ein Dienstneustart setzt sie zurück (R-A15). Den
  Wecksturm begrenzt vhost01 mit sechs Zyklen in 24 Stunden, nicht proxy01 mit
  Ereignissen je rollender Stunde (Spec 3.7).
- nas01 wird nicht übernommen (Plan R11).
- Nachfrage zwischen `abmelden` und Suspend (Zähler `nachfrage`, neue lokale
  Signale; Spec 3.2 Schritt 3) wertet vhost01 nicht aus; bis zu 20 s nach
  `abmelden` prüft er nicht erneut. Ein noch wacher Host beantwortet aber die
  ARP-Proben, proxy01 übernimmt dann nicht.
- Kein Resume-Hook hält DHCP bis zur bestätigten Freigabe zurück (Spec 3.2
  Schritt 6): proxy01 gibt beim ersten Frame frei, `gb-garp` meldet die Adresse
  danach.

Wachseite (beta.6, Rulings vom 13.10.2026):

- IPv6-Gegenstellen und nicht öffentliche IPv4 außerhalb von LAN/VPN bleiben
  ungefiltert: Der Mitschnitt sieht nur IPv4 (BPF `ip and …`), solche Quellen könnten
  nie legitim werden; Container-Netze und CGNAT kommen nicht über die
  Portweiterleitung.
- Der Mitschnitt prüft das SNI-Label wie proxy01, damit „würde wecken“ auf beiden
  Seiten dieselbe Entscheidung ist; die Datei trägt zusätzlich `ttl_s`, und gb-schlaf
  prüft die TTL selbst. `eigene_wan_ip` ist eine Liste (alle A-Records von `wan_name`).
- Herzschlag 30 s statt höchstens 60 s, damit ein verspäteter Schreibvorgang die
  180-s-Grenze nicht reißt; die Zukunft ist erst ab 60 s ein Fehler, weil die Runde
  von gb-schlaf vor dem Lesen beginnt.
- Nach dem Review vom 13.10.26 zwei Rückfallgründe mehr als in R4 aufgezählt, beide
  in Richtung beta.5: kein gültiger `plex_hash` (keine Datei) und kein erfasstes Paket
  seit `legitim_stille_s` (`"still"`). Legitimität bindet gb-schlaf zusätzlich an die
  einmal gezählte Verbindung; die Merkliste übersteht keinen Neustart von gb-schlaf.

## Tests und noch zu bestätigende Tatsachen

```sh
python3 -m unittest discover -s tests -q
uv run --no-project --python 3.9 python -m unittest discover -s tests -q    # wie vhost01
uv run --no-project --python 3.10 python -m unittest discover -s tests -q   # wie proxy01
GB_NETNS=1 python3 -m unittest discover -s tests -q   # zusätzlich die Netztests, unter 2 min
```

Alle Fixtures sind synthetisch, Zeit ist injizierbar; die Unittests brauchen kein
Netz, keine Root-Rechte und keine Sleeps. Die Suite läuft unter der lokalen
Python-Version und per `uv` unter 3.9 und 3.10; Installationen gehören zur
Hostabnahme. Unter anderem sind kaputte APIs/Schema, Schatten- und
Aktiventscheidung (jede Schutzprüfung einzeln, RTC-/Suspend-Fehler,
Schlussprüfung, Ratenlimit, Bandbreitenregeln), `gb-wecken`,
Fenster über Mitternacht, Login-Sitzungen, Byteparser, Hostbindung, atomare
Registerwechsel, Leases, MAC/Replay, Queue-Reihenfolge/TTL, ARP-Sperre,
Logrotation und WOL-Paketaufbau abgedeckt, seit beta.5 auch der Übernahme-Automat
(Phasen, Vorprüfung, Freigabegründe, Teilfehler), nft-Regelsatz und cBPF-Programme,
Auslöser und Limits, Konfigprüfung, Register-Protokoll samt Abschalter, der
SSH-Aufruf und die Antwortprüfung auf vhost01, der Schlafablauf mit Register sowie
`gb-garp` und der Installer, seit beta.6 die Legitim-Datei (`tests/test_wachseite.py`:
Schreiben, Herzschlag, Obergrenze, TTL, Atomarität mit gleichzeitigem Leser und
fsync-Fehler, Haarnadel, hängender Resolver mit echtem Faden, Rückfallebene, Filter in
gb-schlaf, Konfigprüfung und ein tcpdump-Strom durch `mitschnitt.main()` bis zur
Datei). Ein Vertragstest schickt echte Antworten von
`proxy_ssh.ausfuehren` durch die Prüfung von `register_client`; er fand beim
Zusammenführen, dass proxy01 `weckung.weg` als Nummer meldet, vhost01 aber Text
verlangte. Kein Test suspendiert, ruft `rtcwake` auf oder sendet ein Paket ins
echte Netz; alle Befehle laufen über injizierte Fake-Runner oder in
Wegwerf-Namensräumen.

Netztests (opt-in `GB_NETNS=1`; ohne die Variable oder ohne die Werkzeuge
übersprungen): `tests/test_netns_stellvertretung.py` startet den echten
`gb-stellvertreter` in Wegwerf-Namensräumen (`unshare --user --map-root-user --net
--mount --pid --fork --kill-child --mount-proc`, Szenario `tests/netns/szenario.py`
als PID 1; endet es oder wird `unshare` getötet, beendet der Kernel alle Prozesse
und Namensräume). Aufbau: Brücke mit proxy01 (eth0 .100, wg0 10.0.0.1), einem Host
mit der MAC von vhost01 (.110), LAN-Client .18 und Router .1 mit den WAN-Doku-Netzen
198.51.100.0/24 und 203.0.113.0/24, VPN-Gegenstelle 10.0.0.2 über echtes WireGuard
(sonst veth). Register und Bereitschaft laufen über den echten Zwangsbefehl unter
den Standardpfaden (`/var/lib` nur im privaten Mount-Namensraum überdeckt), mit
kurzen Testzeiten (`stille_s` 1, `wol_max_s` 2); die produktiven Zeiten decken die
Unittests ab. Rahmen werden an der Brücke mit Kernel-Zeitstempeln mitgeschnitten,
Freigabezeiten per bind-Test auf .110 gemessen. Dazu kommt
`test_stellvertretung.NetzNamensraumTests` (veth in `unshare -Urnm`). Voraussetzungen:
unprivilegierte Benutzer- und PID-Namensräume, `unshare` (util-linux), `ip`, `nft`,
optional `wg`; kein root. Dauer: etwa 80 s und 20 s. Gemessen am 12.10.26 (x86,
nft 1.1.6): Übernahme 1,0 s nach Stille, GARP bei 0/1/3 s, keine Antwort von
proxy01-Diensten unter .110, SYN→WOL 0,4 ms, Freigabe nach dem ersten Frame der
echten MAC: Alias 2,2–5 ms, Tabellen 27–44 ms.

Der Rückfall über proxy01 (Spec 3.8) ist seit beta.5 der Lease: Meldet sich
vhost01 bis 15 Minuten nach dem RTC-Termin nicht zurück, gibt proxy01 frei und weckt
per WOL-Serie. Ob die
User-Manager aus `transient_benutzer` unter der Diensthärtung erreichbar sind,
zeigt das Schattenlog (`transient_unklar:<benutzer>`).

Für beta.6 live zu bestätigen:

- `"legitim": "ok"` im Schlaflog, Scanner unter `verbindungen_wan_ignoriert`, keine
  Veto-Runden `verbindung:32400`/`verbindung:8880` ohne echte Sitzung mehr; der erste
  Tagschlaf mit Ruhekandidat.
- Namensauflösung aus der gb-mitschnitt-Unit (AF_UNIX/AF_INET, kein AF_INET6):
  `"eigene_wan_ip"` in der Datei, Haarnadel um :01 unter `verbindungen_haarnadel`.
- Eine echte Fern-Plex-App (Mobilnetz) erscheint in `"quellen"` und hält vhost01
  wach; das Threema-Gateway nur mit `legitim_quellen` auf 8443.

Für beta.5 live zu bestätigen (Stand 12.10.26 abends):

- nft 1.0.2 auf proxy01: bestätigt in der Live-Probe am 12.10.26 (Ubuntu 22.04, Pi 3B+).
  Der Regelsatz (`create table/chain`, `arp saddr ether`, anonyme Mengen, Priorität
  -300) lädt, und `nft -j list table` gibt die Marke `gb2-<pid>-<hex8>` in beiden
  Tabellen aus; der seltene Weg nach einem abgebrochenen `nft -f` funktioniert dort
  also. Danach waren Alias und Tabellen weg.
- Freigabelatenz auf dem Pi: live 278 ms vom Frame der (Probe-)MAC bis `frei`, mit
  derselben Uhr gemessen (tcpdump auf proxy01). Lokal waren es 2,2–5 ms (Alias) und
  27–44 ms (Tabellen); den Unterschied machen die Forks von `ip` und `nft` auf dem
  Pi. Das Ziel < 100 ms ist damit verfehlt, die Folge aber gering: In diesem Fenster
  beantwortet proxy01 die ARP-Proben von vhost01 dank der arp-Sperre nicht, und die
  GARPs von vhost01 kommen erst Sekunden nach dem Link-Aufbau. Beim ersten echten
  Aufwachen erneut ansehen (`phase` mit `grund` `echte_mac`).
- iputils 20210202 auf vhost01: `arping -U`/`-A` endet dort laut Quelltext ebenfalls
  mit Exit 0, getestet ist nur 20250605. Einmal `systemctl start gb-garp.service`,
  nach dem ersten Resume `systemctl status gb-garp.service`. Die Härtungen der Unit
  (`PrivateDevices`, `ProtectClock` …) sind auf EL9/systemd 252 ungetestet.
- SSH aus der gehärteten `gb-schlaf`-Unit (`ProtectHome=read-only`,
  `ProtectSystem=strict`, SELinux); ältere OpenSSH melden ggf. „Could not create
  directory '/root/.ssh'“ (nicht fatal). Probe mit `systemd-run` (siehe Ausrollen).
- ufw lässt die Handshakes an .110:32400 und .110:25565 durch; GDM-Pakete erscheinen
  nach der ufw-Regel im Zähler.
- Ob Clients (Plex-Apps, Threema-Gateway, Minecraft) ihre Verbindung lange genug
  wiederholen, bis vhost01 wach ist (WOL-Weckung 6–8 s plus Dienststart), und ob
  Plex-Apps einen laut plex.tv offline gemeldeten Server überhaupt ansprechen
  (Spec 3.3 Weg 7).
- Box und LAN-Clients stellen ihren ARP-Eintrag nach Übernahme und Freigabe (GARP)
  um; `gb-wecken` während einer Übernahme braucht bis zur Freigabe länger.

Auf den Hosts offen: Pfade/Rechte der Preferences und Caddy-Logs, Jellyfin-Key,
Jobs/User-Bus unter Diensthärtung, Java-Muster, NICs, Plex-Hash/Client-Lernliste,
Minecraft-Whitelist, neue Fenster und lokale Zeitzone, multicastfähiges
GDM-Interface, freie Probe-IP, echte MAC/sysctls/nft sowie fapolicyd-/SELinux-
Verhalten. Vor späterem S3 sind die Review-Abnahmen einschließlich RAID-
Redundanz/Backup-Freigabe, 20 S3-Zyklen, NFS-/GPU-/Container-Resume, WOL,
Router-ARP-Cache und proxy01-Ausfall vor Ort erforderlich.
