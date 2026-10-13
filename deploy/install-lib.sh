#!/bin/bash
# Gemeinsamer Installer: eigene Dateien, Rückbau und unveränderte Altdateien.
set -euo pipefail
umask 077
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
export LC_ALL=C
MANIFEST=/root/greenbuddy2/manifest.tsv
TRUST_DIRTY=0

die() { printf '%s\n' "$*" >&2; exit 1; }
root_only() { [[ $EUID = 0 ]] || die 'Als root ausführen.'; }
record() { printf '%s\t%s\n' "$1" "$2" >> "$MANIFEST"; }
safe_path() {
    local p=$1
    while [[ $p != / ]]; do
        [[ ! -L $p ]] || die "Symlink im Zielpfad: $p"
        p=${p%/*}; [[ -n $p ]] || p=/
    done
}
gb2_dir() {
    case $1 in
        /etc/greenbuddy|/var/lib/greenbuddy|/var/lib/greenbuddy/stellvertreter|/var/lib/greenbuddy-ssh|/var/lib/greenbuddy-ssh/.ssh|/var/log/greenbuddy|/var/log/greenbuddy/mitschnitt|/run/greenbuddy|/run/greenbuddy/ansprueche|/run/greenbuddy/legitim|/run/greenbuddy/log|/run/greenbuddy/stellvertreter|/run/greenbuddy/status|/usr/local/lib/greenbuddy2|/usr/local/lib/greenbuddy2/greenbuddy2) return 0 ;;
        *) return 1 ;;
    esac
}
make_dir() {
    local p=$1 mode=$2 owner=${3:-root} group=${4:-root}
    safe_path "$p"
    if [[ ! -e $p ]]; then
        record dir "$p"
        install -d -o "$owner" -g "$group" -m "$mode" "$p"
        label "$p"
    else
        local uid gid
        [[ -d $p ]] || die "Kein Verzeichnis: $p"
        uid=$(stat -c %u "$p"); gid=$(stat -c %g "$p")
        if gb2_dir "$p" && { ! getent passwd "$uid" >/dev/null || ! getent group "$gid" >/dev/null; }; then
            # Nur eigene, feste GB2-Pfade mit verwaisten Besitzern übernehmen.
            chown -hR --from="$uid:$gid" "$owner:$group" "$p"
            chmod "$mode" "$p"
            label "$p"
            printf 'Verwaiste GB2-Besitzer übernommen: %s\n' "$p"
            return
        fi
        [[ -d $p && $(stat -c %U "$p") = "$owner" && $(stat -c %G "$p") = "$group" && $(stat -c %a "$p") = "${mode#0}" ]] || die "Verzeichnis mit fremden Rechten: $p"
    fi
}
# Genau bekannte Vorgängerrechte (owner:group:mode) eines vorhandenen GB2-Verzeichnisses anheben, ohne Abbruch.
migrate_dir() {
    local p=$1 old=$2 mode=$3 owner=$4 group=$5
    safe_path "$p"
    [[ -d $p && ! -L $p ]] || return 0
    gb2_dir "$p" || die "Kein GB2-Verzeichnis: $p"
    [[ $(stat -c %U:%G:%a "$p") = "$old" ]] || return 0
    chgrp -- "$group" "$p"
    chmod "$mode" "$p"
    label "$p"
    printf 'GB2-Verzeichnis migriert: %s (%s -> %s:%s %s)\n' "$p" "$old" "$owner" "$group" "$mode"
}
label() {
    if command -v selinuxenabled >/dev/null && selinuxenabled; then
        command -v restorecon >/dev/null || die 'SELinux aktiv, restorecon fehlt.'
        restorecon -F "$1"
    fi
}
trust_exists() {
    local f
    for f in /etc/fapolicyd/fapolicyd.trust /etc/fapolicyd/trust.d/*; do
        [[ -f $f ]] || continue
        grep -qF -- "$1 " "$f" && return 0
    done
    return 1
}
trust_file() {
    if systemctl is-active --quiet fapolicyd; then
        command -v fapolicyd-cli >/dev/null || die 'fapolicyd aktiv, Werkzeug fehlt.'
        if trust_exists "$1"; then
            record trust-update "$1"
            fapolicyd-cli --file update "$1"
        else
            record trust-new "$1"
            fapolicyd-cli --file add "$1"
        fi
        TRUST_DIRTY=1
    fi
}
put_file() {
    local source=$1 target=$2 mode=$3
    safe_path "$target"
    if [[ -e $target ]]; then
        [[ -f $target && ! -e $target.bak-gb2 && ! -L $target.bak-gb2 ]] || die "Backup/Ziel nicht frei: $target"
        cp -a -- "$target" "$target.bak-gb2"
        record restore "$target"
    else
        case $target in
            /etc/greenbuddy/*.json) record backup "$target" ;;
            *) record file "$target" ;;
        esac
    fi
    install -o root -g root -m "$mode" "$source" "$target"
    label "$target"
}
finish_install() {
    if (( TRUST_DIRTY != 0 )); then
        fapolicyd-cli --update
        TRUST_DIRTY=0
    fi
    trap - EXIT
}
new_user() {
    local name=$1 home=$2 shell=${3:-/usr/sbin/nologin}
    ! getent passwd "$name" >/dev/null || die "Konto schon vorhanden: $name"
    ! getent group "$name" >/dev/null || die "Gruppe schon vorhanden: $name"
    record group "$name"
    groupadd --system "$name"
    record user "$name"
    useradd --system --gid "$name" --home-dir "$home" --no-create-home --shell "$shell" "$name"
}
begin_install() {
    root_only
    [[ $# = 1 && ( $1 = vhost01 || $1 = proxy01 ) ]] || die 'Unbekannter Host.'
    safe_path /root/greenbuddy2
    [[ ! -e $MANIFEST ]] || die 'Manifest vorhanden; zuerst den bisherigen Rückbau ausführen.'
    install -d -o root -g root -m 0700 /root/greenbuddy2
    : > "$MANIFEST"
    record host "$1"
    record dir /root/greenbuddy2
    trap install_failed EXIT
    put_file "$PACKAGE/deploy/install-lib.sh" /root/greenbuddy2/install-lib.sh 0700
    put_file "$PACKAGE/deploy/$1/rueckbau.sh" /root/greenbuddy2/rueckbau.sh 0700
    trust_file /root/greenbuddy2/install-lib.sh
    trust_file /root/greenbuddy2/rueckbau.sh
}
install_package() {
    make_dir /usr/local/lib/greenbuddy2 0755
    make_dir /usr/local/lib/greenbuddy2/greenbuddy2 0755
    local source target
    for source in "$PACKAGE"/greenbuddy2/*.py; do
        [[ ${source##*/} != webhook.py ]] || continue
        target=/usr/local/lib/greenbuddy2/greenbuddy2/${source##*/}
        put_file "$source" "$target" 0644
        trust_file "$target"
    done
}
starter() {
    put_file "$PACKAGE/bin/$1" "/usr/local/sbin/$1" 0755
    trust_file "/usr/local/sbin/$1"
}
unit() {
    local host=$1 name=$2
    [[ $(systemctl is-active "$name" || true) != active ]] || die "GB2-Dienst bereits aktiv: $name"
    [[ $(systemctl is-enabled "$name" 2>/dev/null || true) != enabled ]] || die "GB2-Dienst bereits aktiviert: $name"
    put_file "$PACKAGE/deploy/$host/$name" "/etc/systemd/system/$name" 0644
    record unit "$name"
}
install_failed() {
    local code=$?
    trap - EXIT
    if (( code != 0 )); then
        printf 'Installation fehlgeschlagen; Rückbau anhand des Manifests.\n' >&2
        rollback || printf 'Rückbau unvollständig: %s bleibt erhalten.\n' "$MANIFEST" >&2
    fi
    exit "$code"
}
rollback() {
    root_only
    [[ -f $MANIFEST && ! -L $MANIFEST && $(stat -c %u "$MANIFEST") = 0 && $(stat -c %a "$MANIFEST") = 600 ]] || die 'Unsicheres oder fehlendes Manifest.'
    local -a entries=()
    local line kind value i trust=0 backup_suffix
    backup_suffix=$(date -u +%Y%m%dT%H%M%S%N)
    mapfile -t entries < "$MANIFEST"
    for line in "${entries[@]}"; do
        kind=${line%%$'\t'*}; value=${line#*$'\t'}
        if [[ $kind = unit ]]; then
            case $value in gb-schlaf.service|gb-schlaf-schatten.service|gb-mitschnitt.service|gb-stellvertreter.service) ;; *) die 'Fremde Unit im Manifest.' ;; esac
            systemctl disable --now "$value" || return 1
        fi
        if [[ $kind = trust-new ]] && trust_exists "$value"; then
            fapolicyd-cli --file delete "$value" || return 1
            trust=1
        fi
    done
    # Laufende Konfiguration und Daten sichern, bevor Dateien/Konten zurückgebaut werden.
    local path
    for path in /etc/greenbuddy/*.json /var/lib/greenbuddy /var/lib/greenbuddy-ssh /var/log/greenbuddy /run/greenbuddy; do
        [[ -e $path || -L $path ]] || continue
        sichern "$path" "$backup_suffix" || return 1
    done
    for ((i=${#entries[@]}-1; i>=0; i--)); do
        kind=${entries[i]%%$'\t'*}; value=${entries[i]#*$'\t'}
        case $kind in
            file) rm -f -- "$value" || return 1 ;;
            backup) if [[ -e $value ]]; then sichern "$value" "$backup_suffix" || return 1; fi ;;
            restore)
                if [[ -f $value.bak-gb2 && ! -L $value.bak-gb2 ]]; then
                    mv -f -- "$value.bak-gb2" "$value" || return 1
                    label "$value"
                fi ;;
            user) if getent passwd "$value" >/dev/null; then userdel "$value" || return 1; fi ;;
            group) if getent group "$value" >/dev/null; then groupdel "$value" || return 1; fi ;;
            dir)
                [[ $value != /root/greenbuddy2 ]] || continue
                if [[ -d $value ]]; then
                    rmdir -- "$value" 2>/dev/null || printf 'Daten/Dateien bleiben erhalten: %s\n' "$value"
                fi ;;
        esac
    done
    for line in "${entries[@]}"; do
        kind=${line%%$'\t'*}; value=${line#*$'\t'}
        if [[ $kind = trust-update && -f $value ]]; then
            fapolicyd-cli --file update "$value" || return 1
            trust=1
        fi
    done
    if (( trust != 0 )) || systemctl is-active --quiet fapolicyd; then
        fapolicyd-cli --update || return 1
    fi
    systemctl daemon-reload || return 1
    rm -- "$MANIFEST"
    rmdir /root/greenbuddy2 2>/dev/null || true
    printf 'GB2 zurückgebaut; Konfiguration und Daten als *.bak-gb2-%s gesichert.\n' "$backup_suffix"
}
sichern() {
    local path=$1 target=$1.bak-gb2-$2
    safe_path "$path"
    [[ ! -e $target && ! -L $target ]] || { printf 'Backup belegt: %s\n' "$target" >&2; return 1; }
    mv -T -- "$path" "$target" || return 1
    printf 'Gesichert: %s\n' "$target"
}
