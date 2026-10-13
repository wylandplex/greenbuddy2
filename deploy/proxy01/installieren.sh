#!/bin/bash
# SSH-Register, Stellvertreter (GDM + Übernahme) und Notfall-Wecken; Webhook wird nicht installiert.
set -euo pipefail
PACKAGE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
source "$PACKAGE/deploy/install-lib.sh"
root_only
[[ $# = 0 ]] || die 'Keine Argumente erwartet.'
for tool in python3 ip systemctl sysctl systemd-tmpfiles; do
    command -v "$tool" >/dev/null || die "Werkzeug fehlt: $tool"
done
command -v nft >/dev/null || printf 'Warnung: nft fehlt; gb-stellvertreter meldet nft_fehlt und übernimmt nie.\n' >&2
begin_install proxy01
new_user gb-register /var/lib/greenbuddy-ssh /bin/sh
new_user gb-stellvertreter /nonexistent
install_package
starter gb-proxy-ssh
starter gb-stellvertreter
starter gb-wecken
make_dir /etc/greenbuddy 0755
# b2-Register lag gb-register:gb-register 0755; der Stellvertreter liest es jetzt über die Gruppe.
migrate_dir /var/lib/greenbuddy gb-register:gb-register:755 2750 gb-register gb-stellvertreter
make_dir /var/lib/greenbuddy 2750 gb-register gb-stellvertreter
if [[ -f /var/lib/greenbuddy/register.json && ! -L /var/lib/greenbuddy/register.json ]]; then
    chgrp -- gb-stellvertreter /var/lib/greenbuddy/register.json
    chmod 0640 /var/lib/greenbuddy/register.json
fi
make_dir /var/lib/greenbuddy-ssh 0755
make_dir /var/lib/greenbuddy-ssh/.ssh 0755
make_dir /var/log/greenbuddy 0755
make_dir /run/greenbuddy 0755
make_dir /run/greenbuddy/log 0700 gb-stellvertreter gb-stellvertreter
make_dir /run/greenbuddy/stellvertreter 0700 gb-stellvertreter gb-stellvertreter
make_dir /run/greenbuddy/status 2750 gb-stellvertreter gb-register
put_file "$PACKAGE/deploy/proxy01/stellvertreter.example.json" /etc/greenbuddy/stellvertreter.json 0644
put_file "$PACKAGE/deploy/proxy01/wecken.example.json" /etc/greenbuddy/wecken.json 0644
put_file "$PACKAGE/deploy/proxy01/authorized_keys.example" /etc/greenbuddy/authorized_keys.example 0644
put_file "$PACKAGE/deploy/proxy01/bereinigen-gb1.sh" /usr/local/sbin/gb-bereinigen-gb1 0700
trust_file /usr/local/sbin/gb-bereinigen-gb1
put_file "$PACKAGE/deploy/proxy01/60-greenbuddy-arp.conf" /etc/sysctl.d/60-greenbuddy-arp.conf 0644
sysctl --load=/etc/sysctl.d/60-greenbuddy-arp.conf >/dev/null || true
# Tatsachen statt Exit-Code: der Dienst übernimmt nur mit genau diesen Werten.
for scope in all eth0; do
    if [[ $(cat "/proc/sys/net/ipv4/conf/$scope/arp_ignore" 2>/dev/null) != 1 \
          || $(cat "/proc/sys/net/ipv4/conf/$scope/arp_announce" 2>/dev/null) != 2 ]]; then
        printf 'Warnung: arp_ignore/arp_announce für %s nicht wirksam; Übernahme bleibt gesperrt.\n' "$scope" >&2
    fi
done
unit proxy01 gb-stellvertreter.service
put_file "$PACKAGE/deploy/proxy01/tmpfiles.conf" /etc/tmpfiles.d/greenbuddy2.conf 0644
systemd-tmpfiles --create /etc/tmpfiles.d/greenbuddy2.conf
systemctl daemon-reload
finish_install
printf 'Installiert, noch nicht gestartet. Öffentliche Schlüssel getrennt hostgebunden eintragen.\n'
printf 'Vor dem Start in /etc/greenbuddy/stellvertreter.json die Platzhalter ersetzen: plex_hash,\n'
printf 'minecraft_whitelist, wan_name, quellen_ports 8443 (203.0.113.10 = Platzhalter der Threema-Adresse).\n'
printf 'GDM-Zähler (Plan R10): ufw allow from 192.168.1.0/24 to any port 32414 proto udp\n'
printf 'Live-Probe ohne Produktions-IP: /usr/local/sbin/gb-stellvertreter --probe 300\n'
printf 'Altbereinigung bei Bedarf: /usr/local/sbin/gb-bereinigen-gb1\n'
printf 'Notfall-Wecken: /usr/local/sbin/gb-wecken vhost01|nas01 [--nur-senden]\n'
