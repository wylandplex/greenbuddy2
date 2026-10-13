#!/bin/bash
# Installiert den Schlafwächter (Standard: Schatten) und den Mitschnitt, ohne Dienststart.
set -euo pipefail
PACKAGE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source "$PACKAGE/deploy/install-lib.sh"
root_only
[[ $# = 0 ]] || die 'Keine Argumente erwartet.'
for tool in python3 tcpdump nvidia-smi loginctl systemctl ss rtcwake busctl ssh ip arping; do
    command -v "$tool" >/dev/null || die "Werkzeug fehlt: $tool"
done
# rollback() kennt nur Dauerdienste als Unit; gb-garp steht darum als Datei samt wants-Link im Manifest.
[[ $(systemctl is-enabled gb-garp.service 2>/dev/null || true) != enabled ]] || die 'GB2-Dienst bereits aktiviert: gb-garp.service'
begin_install vhost01
new_user gb-mitschnitt /nonexistent
install_package
for name in gb-schlaf gb-mitschnitt gb-fenster gb-garp; do starter "$name"; done
make_dir /etc/greenbuddy 0755
make_dir /var/lib/greenbuddy 0700
make_dir /var/log/greenbuddy 0755
make_dir /var/log/greenbuddy/mitschnitt 0700 gb-mitschnitt gb-mitschnitt
make_dir /run/greenbuddy 0755
make_dir /run/greenbuddy/ansprueche 0755
make_dir /run/greenbuddy/legitim 0700 gb-mitschnitt gb-mitschnitt
put_file "$PACKAGE/deploy/vhost01/schlaf.example.json" /etc/greenbuddy/schlaf.json 0600
put_file "$PACKAGE/deploy/vhost01/mitschnitt.example.json" /etc/greenbuddy/mitschnitt.json 0644
unit vhost01 gb-schlaf.service
unit vhost01 gb-mitschnitt.service
put_file "$PACKAGE/deploy/vhost01/gb-garp.service" /etc/systemd/system/gb-garp.service 0644
put_file "$PACKAGE/deploy/vhost01/tmpfiles.conf" /etc/tmpfiles.d/greenbuddy2.conf 0644
systemd-tmpfiles --create /etc/tmpfiles.d/greenbuddy2.conf
systemctl daemon-reload
# Vor dem Aktivieren eintragen: auch ein halb gelaufenes enable wird beim Rückbau entfernt.
record file /etc/systemd/system/suspend.target.wants/gb-garp.service
systemctl enable gb-garp.service
finish_install
if [[ ! -f /etc/greenbuddy/ssh/id_ed25519 || ! -f /etc/greenbuddy/ssh/known_hosts ]]; then
    printf 'Warnung: /etc/greenbuddy/ssh/id_ed25519 oder known_hosts fehlt; mit "stellvertreter_pflicht": true schläft vhost01 dann nicht.\n'
fi
printf 'Installiert, noch nicht gestartet (gb-garp läuft nach jedem Resume). Konfiguration und Fenster zuerst bestätigen;\n'
printf 'aktiver Schlaf erst mit "mode": "aktiv" und "dependencies_verified": true.\n'
