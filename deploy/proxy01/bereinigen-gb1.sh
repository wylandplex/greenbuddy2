#!/bin/bash
# Idempotente Altbereinigung; keine Datei löschen, keine Timer ändern.
set -euo pipefail
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID = 0 ]] || { printf 'Als root ausführen.\n' >&2; exit 1; }
shopt -s nullglob
# Vor JEDEM Eingriff alle bekannten Units und gemeinsame Konfig-Verbraucher prüfen.
config=/opt/greenbuddy/config.yaml
unit_files=$(systemctl list-unit-files --no-legend --no-pager) || {
    # Auf proxy01 läuft ListUnitFiles in den D-Bus-Timeout (06.10.26); Unit-Dateien direkt lesen.
    printf 'Unitliste per systemctl unklar; lese die Unit-Verzeichnisse.\n' >&2
    unit_files=$(for dir in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
        [[ -d $dir ]] || continue
        for file in "$dir"/*.service "$dir"/*.timer "$dir"/*.socket "$dir"/*.path; do printf '%s\n' "${file##*/}"; done
    done)
    [[ -n $unit_files ]] || { printf 'Unitliste unklar; keine Änderung.\n' >&2; exit 1; }
}
loaded_units=$(systemctl list-units --all --plain --no-legend --no-pager) || { printf 'Geladene Units unklar; keine Änderung.\n' >&2; exit 1; }
mapfile -t units < <(printf '%s\n%s\n' "$unit_files" "$loaded_units" | awk '{print $1}' | sort -u)
blocked=0
declare -A states=()
for name in greenbuddy-manager.service greenbuddy.service; do
    state=$(systemctl show --property=LoadState --value "$name") || { printf 'Unitstatus unklar: %s\n' "$name" >&2; exit 1; }
    states[$name]=$state
    printf 'Unit geprüft: %s, LoadState=%s\n' "$name" "$state"
    for other in "${units[@]}"; do
        [[ -n $other && $other != greenbuddy.service && $other != greenbuddy-manager.service ]] || continue
        if [[ $other == *@.* ]]; then
            # Templates sind nicht abfragbar (proxy01: apport-forward@.service); Verweise nur textuell prüfen.
            for dir in /etc/systemd/system /run/systemd/system /usr/lib/systemd/system /lib/systemd/system; do
                if [[ -f $dir/$other ]] && grep -qE 'greenbuddy(-manager)?\.service|/opt/greenbuddy/config\.yaml' "$dir/$other"; then
                    printf 'Abhängigkeit: Template %s nennt GreenBuddy; keine Bereinigung.\n' "$other"
                    blocked=1
                fi
            done
            continue
        fi
        details=$(systemctl show --property=Requires --property=Wants --property=After --property=ExecStart --property=ExecStartPre --property=ExecStartPost --property=FragmentPath -- "$other") || { printf 'Abhängigkeiten unklar: %s\n' "$other" >&2; exit 1; }
        while IFS='=' read -r key value; do
            case $key in
                Requires|Wants|After)
                    if [[ " $value " = *" $name "* ]]; then
                        printf 'Abhängigkeit: %s hat %s auf %s; keine Bereinigung.\n' "$other" "$key" "$name"
                        blocked=1
                    fi ;;
            esac
        done <<< "$details"
        reads_config=0
        [[ $details != *"$config"* ]] || reads_config=1
        # Auch in der Unit genannte Skripte prüfen, etwa wol_housekeeping_plex.py.
        while IFS= read -r path; do
            if [[ -f $path && ! -L $path ]] && grep -qF 'config.yaml' "$path"; then
                reads_config=1
            fi
        done < <(printf '%s\n' "$details" | grep -oE '/[^[:space:];{}]+' || true)
        if (( reads_config != 0 )); then
            printf 'Konfig-Verbraucher: %s liest config.yaml; keine Bereinigung.\n' "$other"
            blocked=1
        fi
    done
done
if (( blocked != 0 )); then
    printf 'GB1 bleibt unverändert: weder maskieren/stoppen noch chmod bei Abhängigkeiten.\n'
    exit 0
fi
for file in /opt/greenbuddy/config.yaml /opt/greenbuddy/access_token*.txt; do
    if [[ -f $file && ! -L $file ]]; then
        chmod 0600 -- "$file"
        printf 'Rechte 0600 gesetzt: %s\n' "$file"
    elif [[ -L $file ]]; then
        printf 'Symlink übersprungen: %s\n' "$file"
    fi
done
for name in greenbuddy-manager.service greenbuddy.service; do
    state=${states[$name]}
    if [[ $state = masked ]]; then
        systemctl stop "$name"
        printf 'Bereits maskiert; vorsorglich gestoppt: %s\n' "$name"
    elif [[ $state != not-found ]]; then
        systemctl disable --now "$name"
        # Lokale Units vor dem Maskieren sichern; systemctl mask ersetzt keine Datei.
        path=/etc/systemd/system/$name
        if [[ -f $path && ! -L $path ]]; then
            [[ ! -e $path.bak-gb2 && ! -L $path.bak-gb2 ]] || { printf 'Backup vorhanden: %s\n' "$path" >&2; exit 1; }
            mv -- "$path" "$path.bak-gb2"
        fi
        systemctl mask "$name"
        printf 'Gestoppt, deaktiviert und maskiert: %s\n' "$name"
    else
        printf 'Bereits maskiert oder nicht vorhanden: %s\n' "$name"
    fi
done
systemctl daemon-reload
