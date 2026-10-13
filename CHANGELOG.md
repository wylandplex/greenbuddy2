# Änderungen

## v2.0.0-beta.6 – 13.10.2026

- Wachseite filtert Spam. Live-Befund 13.10.26 (beta.5 auf vhost01 und proxy01 seit
  12.10. 20:53): vhost01 schlief im Tagschlaffenster nie ein, weil jede aufgebaute
  Verbindung auf einem lauschenden Port mit fremder Gegenstelle die 45-min-Ruhezeit
  neu startete. Der Mitschnitt sah in 55 min 2.221 WAN-Flüsse auf 32400, davon einen
  mit gültigem SNI; bis zu 46 Veto-Runden `verbindung:32400` ohne Plex-Sitzung
  (Scanner, darunter ein Qualys-Scan mit ~30 vollständigen TLS-Verbindungen),
  18 Runden `verbindung:8880` (Scanner) und stündlich um :01 eine
  Haarnadel-Verbindung von der eigenen WAN-Adresse. Seit beta.6 hält eine
  WAN-Verbindung vhost01 nur noch wach, wenn sie ihn über proxy01 auch wecken dürfte.
- gb-mitschnitt führt `/run/greenbuddy/legitim/vhost01.json` (`version`, `zeit`,
  `ttl_s`, `quellen` als IP → zuletzt gesehen, `letztes_paket`, optional
  `eigene_wan_ip`): WAN-Quellen mit `wuerde_wecken` (gültiges Plex-SNI,
  Whitelist-Login), nie spam, unklar, LAN/VPN oder die eigene WAN-Adresse. Atomar (tmp + fsync + rename), Neues sofort (höchstens
  1/s), sonst Herzschlag alle 30 s; Einträge verfallen nach `legitim_ttl_s` (3600),
  höchstens `legitim_max` (4096), die am längsten nicht gesehenen fliegen zuerst;
  Schreibfehler einmal als `legitim_schreibfehler`. Laufende legitime Flüsse halten
  ihren Eintrag frisch (höchstens alle 10 s). Das SNI-Label prüft der Mitschnitt jetzt
  wie proxy01 (LAN-IP des Ziels oder aktuelle WAN-IP, unbekannt = jede öffentliche
  IPv4); seine Logzeilen tragen `sni_label`.
- Haarnadel: gb-mitschnitt löst `wan_name` (leer = aus) im Hintergrund auf, höchstens
  alle 10 min, 2 s Frist; die Auflösung (`WanAdresse`) liegt dafür unverändert im neuen
  Modul `wan.py`. Verbindungen von der eigenen WAN-Adresse zählen in gb-schlaf nicht.
- gb-schlaf: eine öffentliche IPv4 außerhalb `lan`/`vpn` (auch `::ffff:`-gemappt) zählt
  nur mit frischem Eintrag (TTL auch gegen die eigene Uhr) oder für ihren Port in
  `legitim_quellen` (Allowlist wie `quellen_ports`, gedacht für 8443/Threema); eine
  legitime IP zählt auf allen Ports. LAN, VPN, Loopback, nicht öffentliche IPv4 und
  IPv6 zählen wie bisher. 8880 braucht keinen Sonderfall. Diagnose-Fakten `legitim`,
  `verbindungen_wan_ignoriert`, `verbindungen_haarnadel` (Zähler, keine Adressen); die
  Ruhe-Regel gilt unverändert. Eine einmal als legitim gezählte WAN-Verbindung zählt
  weiter, solange sie aufgebaut ist (Merkliste im Speicher, Review 13.10.26): Ein
  Download über eine einzige Anfrage schickt nur ACKs, sein Eintrag verfiel nach 1 h
  bzw. sofort nach einem Neustart des Mitschnitts, und vhost01 hätte rund 1 h 45 min
  nach Downloadbeginn schlafen können.
- Rückfallebene: Datei fehlt, unlesbar, Symlink, kein reguläres File, fremder Besitzer
  (nicht root/gb-mitschnitt), gruppen-/weltschreibbar, über 1 MiB, schemawidrig,
  `zeit` älter als `legitim_max_alter_s` (180) oder über 60 s in der Zukunft: kein
  Filter, beta.5-Verhalten, nie unklar. Schalter `"wan_filter": false` in `schlaf.json`.
  Ohne gültigen `plex_hash` (etwa der Platzhalter der Vorlage nach einer
  Neuinstallation) schreibt der Mitschnitt keine Datei und meldet einmal
  `legitim_aus` (Review 13.10.26: sonst frische Datei mit leerer Liste, `"ok"`, und
  jede WAN-Verbindung samt echter Plex-Apps still ignoriert). Aus demselben Grund
  trägt die Datei `letztes_paket` (zuletzt ein Paket für das Ziel erfasst); länger als
  `legitim_stille_s` (900) still heißt `"legitim": "still"` und beta.5-Verhalten, etwa
  bei einem falschen `target` (live ~40 Scanner-Flüsse je Minute auf 32400).
- Deploy: `/run/greenbuddy/legitim` gb-mitschnitt:gb-mitschnitt 0700 (tmpfiles,
  Installer, feste GB2-Verzeichnisliste); `gb-mitschnitt.service` darf zusätzlich nur
  dieses Verzeichnis schreiben. gb-schlaf liest die 0600-Datei über
  `CAP_DAC_READ_SEARCH`. Ausrollen nur auf vhost01 (proxy01 bleibt beta.5).
- Konfig: `wan_filter`, `legitim`, `legitim_max_alter_s`, `legitim_stille_s`,
  `legitim_quellen`, `lan`, `vpn` (gb-schlaf), `legitim`, `legitim_ttl_s`, `legitim_max`, `wan_name`
  (Mitschnitt, Standardwerte jetzt in `konfig.MITSCHNITT`); streng geprüft,
  Beispielkonfigs ergänzt.
- Tests: `tests/test_wachseite.py` (Schreiben, Lesen, Rückfallebene, Haarnadel,
  hängender Resolver mit echtem Faden, Atomarität, Strom durch `mitschnitt.main()`).
- Repo-Hygiene: echte MAC-Adressen, Benutzer- und Unitnamen, Home-Pfade und
  Testkennungen durch Beispielwerte ersetzt (Live-Konfigurationen setzen sie explizit).

## v2.0.0-beta.5 – 12.10.2026

- Weckweg über proxy01 (Spec Wege 4, 5 und 7, nur für vhost01; nas01 wird nie
  übernommen): Meldet vhost01 mit `schlafe-jetzt` seine Schlafabsicht, wartet
  `gb-stellvertreter` 3 s ARP-Stille der echten MAC (Probe who-has .110 tell .100
  je Sekunde, nach 10 min ohne Stille `stille_ausgeblieben`), lädt
  dann die nft-Tabellen `ip gb2_sv_vhost01` (input/output Priorität -300: alles an
  .110 verwerfen außer den Inhaltsports, auch proxy01s eigene Verbindungen dorthin)
  und `arp gb2_sv_vhost01_arp` (ARP der echten MAC verwerfen, damit proxy01s Kernel
  deren Proben nie beantwortet), setzt erst danach 192.168.1.110/32 als Alias auf
  eth0, öffnet Listener auf .110:32400 und .110:25565 und sendet GARP bei 0, 1 und
  3 s, danach minütlich. Phasen `frei → warte_stille → uebernommen (→ wecken) → frei`.
  Dienste von proxy01 auf 0.0.0.0 antworten unter .110 nicht
  (im Netztest mit einem sshd-Ersatz belegt).
- Auslöser je Port (Plan R3): ein SYN auf 22, 8096 oder 32400 aus LAN oder VPN
  (Raw-Sockets mit Kernel-cBPF an eth0 und wg0) weckt (Weg 4); ein SYN auf 8443
  nur von den Allowlist-Quellen in `quellen_ports` (Weg 5, eigenes Limit, zählt nicht
  in die WAN-Limits); WAN-32400 nach dem Handshake nur mit TLS-SNI
  `<label>.<hash>.plex.direct`, dessen Label die gestrichelte LAN-IP von vhost01
  oder die aktuelle WAN-IP ist (Weg 7) – Forschungsscanner mit gültigem Hash-Suffix,
  aber fremdem Label wecken so nicht; 25565 nur ein Minecraft-Login (kein Status-Ping)
  aus der Whitelist. Danach RST. Die WAN-IP löst ein Hintergrundfaden aus `wan_name`
  auf (10 min gültig, 2 s Frist, die Schleife blockiert nie); unbekannt heißt: jede
  öffentliche IPv4 als Label zulassen und `wan_ip_unklar` protokollieren. proxy01,
  nas01 und die Box sind ausgenommen (nft-Drop, der Listener prüft es ein zweites
  Mal), alle übrigen Ports werden ohne Antwort verworfen. Mitschnitt 07.–12.10.: 40–68 k
  WAN-SYNs/Tag auf 32400 ohne Nutzlast, 5.961 Minecraft-Spamverbindungen.
- Wecken (Plan R4): WOL sofort, dann alle 15 s bis 180 s oder bis zum ersten Frame
  der echten MAC; tote RAID-Platten verzögern den Suspend bis ~60 s, ein einzelnes
  Paket verpufft dort (Messung 07.10.). Der Alias bleibt während des Weckens stehen
  (DROP ohne RST, Plan R2), damit LAN-Clients ihre SYNs wiederholen statt nach 3 s
  „No route to host“ zu melden. Scheitert die Serie, folgt `wecken_gescheitert`; der
  Alias bleibt, neue Nachfrage darf innerhalb der Limits erneut wecken. Nachfrage
  während einer Serie wird nicht gezählt (`wecken_laeuft`).
- Freigabe: Jeder Frame der echten MAC entfernt sofort Alias, Listener und
  Tabellen, im Netztest war der Alias 2,2 ms nach dem Rahmen weg (Gesamtnetztest
  Alias 3–5 ms, Tabellen 27–44 ms; Ziel < 100 ms). Ebenso geben `anmelden`, ein neuer
  Zyklus, ein abgelaufener Register-Lease und das Dienstende frei; Lease-Ablauf
  (Sekunden bis zum RTC-Wecker + 15 min, auf BOOTTIME von proxy01) und Abschalter
  geben frei und starten eine WOL-Serie. Eine Lebendprobe alle 5 s findet einen still
  erwachten Host. Fremde boot_id im Register (proxy01 neu gestartet, altes Register):
  WOL statt Alias (`lease_unklar`, Spec 3.7 „bei Zweifel WOL“; R-A3). Weicht der Alias
  nicht, bleiben die Tabellen stehen (Isolation vor Vollständigkeit), Nachholen alle
  10 s, Bereitschaft `freigabe_unvollstaendig` (R-A4). Abschalter und Dienstende
  erledigen den Zyklus nicht: nach einem Neustart übernimmt der Dienst nach erneuter
  Stille wieder, statt vhost01 ungeschützt zu lassen (R-A5).
- Limits (Spec 3.7, Konfig `limits`): WAN je Quelle 3/h, WAN je Host 4/h und
  12/Tag, LAN je Quelle 3/h, VPN je Peer 6/h, Allowlist-Port 6/h; 0 schaltet den
  Weg ab. Gezählt wird nur eine tatsächlich begonnene Weckung. Die Fenster liegen nur
  im Speicher, ein Dienstneustart setzt sie zurück (R-A15); der Sturmschutz auf
  vhost01 (6 Zyklen/24 h) bleibt. Spam und Unklares werden stündlich je Host × Port ×
  Quellklasse × Entscheidung verdichtet, Einzelzeilen gibt es nur für
  Weckentscheidungen und Limits (sonst ~13 MB/Tag im tmpfs, Plan R9).
- Register-Protokoll (`gb-proxy-ssh`): `abmelden <zyklus>`, `schlafe-jetzt <zyklus>
  <sekunden>` (600–43.200, sonst `sekunden_ungueltig`), `anmelden <zyklus>`,
  `anmelden-abbruch <zyklus>`. `bereit` ist nur `true`, wenn der Dienst einen frischen
  Statusbericht (höchstens 15 s alt, `/run/greenbuddy/status/stellvertreter.json`)
  mit vhost01 in `bereit_fuer` schreibt (Plan R1 statt Test-Nonce); sonst nennt
  `grund` `stellvertreter_status_fehlt`, `…_alt`, `…_nicht_bereit` oder `abgeschaltet`.
  `beta1_nur_register` entfällt. `schlafe-jetzt` ohne Bereitschaft trägt keine
  Schlafabsicht ein (R-A2). Ein neuer Zyklus ersetzt jeden alten, sonst wäre ein
  abgestürzter vhost01 bis zu 12 h 15 min gesperrt (R-A1). `anmelden` liefert die
  letzte Weckung dieses Zyklus (Zeit, Weg, Port, Quellklasse, Entscheidung, keine IP).
  Unter dem Abschalter schreiben `abmelden` und `schlafe-jetzt` nichts, `anmelden`
  und `anmelden-abbruch` weiter (R-A6). Fehler heißen jetzt nach ihrer Ursache
  (`zyklus_beendet`, `zyklus_passt_nicht`, `lease_abgelaufen` …). Register-Verzeichnis
  gb-register:gb-stellvertreter 2750, Datei 0640; der Dienst liest es über die Gruppe.
- vhost01 meldet sich vor dem Suspend ab und nach dem Resume an: Nach Schlussprüfung
  und Vorbedingungen `abmelden` (Bereitschaft nötig), Ereignis `einschlafen` und
  Zustand mit `zyklus`, `schlafe-jetzt` mit den Sekunden bis zum RTC-Wecker (auf
  600–43.200 begrenzt, R-B3), eine letzte Prüfung (siehe Review) und dann
  `systemctl suspend`. Absage oder unklare Antwort:
  kein Suspend, `anmelden-abbruch` (auch nach gescheitertem `abmelden`, R-B1), Wecker
  gelöscht, Abbruch `stellvertreter` mit `stellvertreter_nicht_bereit:<grund>` oder
  `stellvertreter_unklar` samt `stellvertreter_detail`, danach 5 min Pause
  (`stellvertreter_pause`). Geprüft werden Host, Phase je Befehl und Zyklus der
  Antwort, nicht nur der Exit-Code (R-B5). Nach dem Resume `anmelden`, bei Fehler in
  jeder Runde erneut, höchstens 10 min (`angemeldet` bzw. `anmelden_aufgegeben`);
  `aufgewacht` trägt `geweckt_durch_proxy01`. Scheitert `systemctl suspend` sicher
  (Exit ≠ 0), folgt sofort `anmelden-abbruch`; bei unklarem Ausgang erst mit
  `suspend_ohne_wirkung`, damit ein doch schlafender Host seinen Weckweg behält
  (R-B2). Neue Schlüssel `stellvertreter_ziel`, `stellvertreter_schluessel`,
  `stellvertreter_known_hosts` und `stellvertreter_pflicht` (Standard `true`;
  `false` ist der Notschalter auf den Ablauf von beta.4 ohne Register).
- `gb-garp.service` auf vhost01 (`WantedBy=suspend.target`, root nur mit
  `CAP_NET_RAW`): wartet nach jedem Resume höchstens 60 s auf 192.168.1.110 an eno1
  und meldet die Adresse per `arping -U` (3×) und `arping -A` (2×), damit Box und
  LAN-Clients ihren ARP-Eintrag sofort erneuern. Freigegeben hat proxy01 dann schon
  beim ersten Frame. Installiert als Datei samt wants-Link im Manifest (R-B6).
  NetworkManager baut WOL-Karten erst nach dem Resume ab und setzt die Adresse neu
  (Review 12.10.): Ein scheiterndes `arping` heißt darum „noch nicht“, `gb-garp`
  wartet und sendet erneut und meldet nach 10 s ein zweites Mal; sonst stünde die
  Unit nach jedem verlorenen Rennen auf failed und kein GARP käme nach dem DHCP.
- proxy01-Installation: `/etc/sysctl.d/60-greenbuddy-arp.conf` setzt `arp_ignore=1`
  und `arp_announce=2` für all und eth0 (bisher 0) und wird sofort geladen; der Dienst
  übernimmt ohne diese Werte nie (`arp_sysctl_ungueltig`). Neues Statusverzeichnis
  `/run/greenbuddy/status` (gb-stellvertreter:gb-register 2750), Unit mit
  `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_NET_BIND_SERVICE` und AF_PACKET/AF_NETLINK.
  `ExecStopPost=… --aufraeumen` entfernt Alias und beide Tabellen auch nach SIGKILL;
  nft legt mit `create` statt `add` an, eine fremde gleichnamige Tabelle wird nie
  ergänzt oder gelöscht (R-A7). arping braucht proxy01 nicht (der Dienst baut ARP-
  Frames selbst), ohne nft gibt es keine Übernahme (`nft_fehlt`). Der Installer druckt
  die ufw-Regel `ufw allow from 192.168.1.0/24 to any port 32414 proto udp`: ufw
  (INPUT DROP) verwarf GDM, der GDM-Zähler hatte seit 07.10. kein einziges Paket
  gesehen (Plan R10; Weg 3 bleibt eine Zählung).
- Probe-Modus statt Phantom-Test: `gb-stellvertreter --probe SEKUNDEN` (1–900)
  übernimmt sofort die Probe-Adresse aus der Konfig (Beispiel .199 mit Dummy-MAC) mit
  eigenen Tabellen `gb2_sv_probe`/`gb2_sv_probe_arp`, eigenem Zustand und Protokoll
  (zusätzlich auf stdout), ohne Register und GDM; das Ende gibt ohne WOL frei, Exit 1,
  wenn Alias oder Tabelle blieben (R-A14). `arp.py` und `phantom_test` entfallen,
  `--aufraeumen` entfernt die Altlast `ip gb2_phantom` mit (R-A11). Eine als root
  gestartete Probe räumt nur root auf (R-A12).
- Netztest (opt-in `GB_NETNS=1`): der echte Dienst in Wegwerf-Namensräumen
  (`unshare` mit Benutzer-, Netz-, Mount- und PID-Namensraum, Szenario als PID 1;
  endet es, sterben alle Prozesse und Namensräume mit, R-N1), Brücke mit proxy01, Host
  mit der MAC von vhost01, LAN-Client, Router mit WAN-Doku-Netzen und
  WireGuard-Gegenstelle; Register und Bereitschaft über den echten Zwangsbefehl (R-N2).
  Belegt: Übernahme nach Stille, Isolation, SYN→WOL 0,4 ms, Limit an der Grenze,
  SNI, Minecraft, Allowlist, VPN, Freigabe, Lease-Ablauf, Abschalter, SIGKILL mit
  Aufräumen und Neustart, Lebendprobe. Drei Funde behoben: ARP-Proben in
  `warte_stille` jetzt alle min(1 s, `stille_s`/3) – bei `stille_s` = 1 genügte ein um
  1 ms verspäteter Takt, um einen antwortenden Host zu übernehmen (R-N4); SIGTERM
  setzt nur noch einen Merker, eine Ausnahme aus dem Handler ging in einem Finalizer
  verloren (R-N5); die Bereitschaft wird nur in `frei` neu bewertet – vorher stand
  während jeder Übernahme und bis 30 s nach der Freigabe `freigabe_unvollstaendig`
  im Bericht, vhost01 hätte nach `anmelden` bereit=false gesehen (R-N6).
- Vertragstest proxy01 ↔ vhost01: echte Antworten von `proxy_ssh.ausfuehren` laufen
  durch die Prüfung von `register_client`. Beim Zusammenführen fand er eine
  Abweichung: proxy01 meldet `weckung.weg` als Nummer (4/5/7) und nach Lease-Ablauf
  `weg`, `port` und `quellklasse` als null, vhost01 verlangte Text – jedes `anmelden`
  nach einer Weckung wäre 10 min als unklar wiederholt und dann aufgegeben worden.
  Außerdem erkennt vhost01 die Absage `abgeschaltet` jetzt vor der Zyklusprüfung.
- Review vor dem Ausrollen, drei Funde behoben (je ein Test, der vorher rot war):
  (1) Antwortet ein anderes Gerät für die Host-IP, übernahm proxy01 trotzdem und gab
  nie frei, denn Stilleprüfung, Lebendprobe und Freigabe kannten nur die konfigurierte
  MAC. Betroffen: eine belegte Probe-Adresse oder vhost01 mit gewechselter MAC (neue
  NIC, Bridge, Bond). Folge war ein IP-Konflikt auf .110 bis zum Lease-Ende, bis zu
  12 h 15 min. Jetzt lassen beide cBPF-Filter auch fremdes ARP mit Absender .110 durch
  (nicht von proxy01s eigener MAC). In `warte_stille` übernimmt der Dienst dann nicht,
  in `uebernommen` gibt er sofort frei (`fremde_mac` mit MAC und Phase, Zyklus
  erledigt, WOL-Serie an die konfigurierte MAC, im Probe-Modus ohne WOL und ohne GARP).
  Die README-Warnung, die Stilleprüfung bemerke ein fremdes Gerät nicht, entfällt.
  (2) `uebernehmen()` glaubte bei `ip addr add` und `nft -f` dem Exit-Code. Reißt einer
  von beiden die 2-s-Frist erst nach der Änderung (rtnl_lock bzw. commit_mutex auf dem
  Pi), blieb ein Alias ohne Tabellen stehen: proxy01s sshd antwortete unter .110, dazu
  ein IP-Konflikt mit dem geweckten vhost01. Oder die ARP-Sperre für vhost01 blieb
  stehen, und VPN zu vhost01 sowie Register-SSH waren bis zum Dienstneustart tot. Jetzt
  zählen nur Tatsachen: Ein vorhandener Alias wird entfernt, bei unklarer Lage gilt er
  als vorhanden (die Tabellen bleiben, bis er weg ist). Jeder Ladeversuch trägt eine
  Marke als Regelkommentar (`gb2-<pid>-<zufall>`). Nach einem unklaren Laden löscht
  der Dienst nur Tabellen mit dieser Marke; eine fremde gleichnamige Tabelle bleibt
  wie bisher unberührt (R-A7). (3) vhost01 prüfte zuletzt vor `abmelden` und
  `schlafe-jetzt`; die beiden SSH-Aufrufe zum Pi können je bis zu 20 s dauern. Eine
  Plex-/Jellyfin-Wiedergabe, ein Minecraft-Login, eine SSH-Sitzung, ein Job, ein
  `block`-Inhibitor oder der Abschalter aus diesem Fenster blieben unbemerkt, und
  vhost01 suspendierte mitten hinein. Jetzt folgt nach `schlafe-jetzt` unmittelbar vor
  dem Suspend eine letzte Prüfung (Spec 3.2: Phase A vor der letzten lokalen
  Prüfung): Abschalter, frische Fakten mit der Entscheidungslogik des Takts und die
  Vorbedingungen. Jede Abweichung bricht ab (`letzte_pruefung`, Schlafeintrag
  zurückgenommen, `anmelden-abbruch`, Wecker gelöscht). Die bisherige Schlussprüfung
  vor `abmelden` bleibt: Dauerhafte Hindernisse kosten so weiterhin keinen
  SSH-Aufruf und keinen Registerschreibvorgang auf der SD-Karte. Mit
  `stellvertreter_pflicht: false` bleibt der Ablauf wie in beta.4.
- Live-Probe auf proxy01 (12.10.26, 192.168.1.199 mit Dummy-MAC, nft 1.0.2): Übernahme
  nach 3,2 s Stille. Von vhost01 aus weckten ein SYN auf 22, TLS mit gültigem Hash und
  dem Label der Probe-Adresse und ein Minecraft-Login mit Whitelist-Namen (je Weg 4,
  Quellklasse LAN). Falscher Hash, fremdes Label und fremder Name endeten sofort mit
  RST als `spam`. Ein Frame der Probe-MAC gab nach 278 ms frei (gleiche Uhr, Ziel
  < 100 ms auf dem Pi verfehlt, Folge gering); die Marke steht in beiden Tabellen,
  danach waren Alias und Tabellen weg.
- Ausrollen: erst proxy01, dann vhost01. Ein beta.5-vhost01 an einem beta.2-proxy01
  bekommt immer `bereit: false` (`beta1_nur_register`) und schläft nicht.

## v2.0.0-beta.4 – 12.10.2026

- gb-schlaf: Eine offene Plex-Verbindung (32400) hält vhost01 nicht mehr wach,
  wenn die Gegenstelle seit 15 min keine Daten gesendet hat (`lastrcv` aus
  `ss -Htni`) und der Server seit der Vorrunde höchstens 64 KiB übertragen hat
  (`bytes_acked`; `verbindung_ruhe_ports` = [32400], `verbindung_ruhe_sekunden`
  = 900, `verbindung_ruhe_bytes` = 65536). Gemessen 12.10.: eine Plex-App im
  Mobilnetz hielt ihre Websocket-Verbindung offen, hatte seit 6 h nichts mehr
  gesendet (3 Datensegmente insgesamt), der Server schickte alle paar Sekunden
  Statusmeldungen – das Veto `verbindung:32400` verhinderte jeden Tagschlaf.
  Blättern und Abspielen senden Anfragen und halten wach wie bisher; Wiedergabe
  erkennen weiterhin `/status/sessions` und die Bandbreite. Ein Download über
  eine einzige Anfrage (Client sendet nur ACKs, `lastrcv` wächst) bleibt dank
  `bytes_acked` ein Veto (Review 12.10.). Fehlen `lastrcv` (ss lässt 0 weg),
  `bytes_acked`, die Infozeile oder die Vorrunde, zählt die Verbindung; ein
  Abfragefehler ist `verbindungen_unklar` und vergisst die Vorrunde. Neue
  Tatsache `verbindungen_ruhend` je Port. Jellyfin-Apps senden alle ~30 s
  `KeepAlive`; dort greift `lastrcv` nicht, 8096 ist deshalb nicht Standard.

## v2.0.0-beta.3 – 07.10.2026

- gb-schlaf: Ein Job (`job:<unit>`) startet die 45-min-Ruhe erst neu, wenn
  dieselbe Unit in zwei aufeinanderfolgenden Runden läuft; in jeder Runde, in
  der er läuft, bleibt er ein Veto. Vorher setzten No-op-Läufe kurzer Timer-Jobs
  (etwa ein Staging-Job alle 15 min, je ~10 ms) die Ruhe zurück, weil ihre Timer
  (`AccuracySec=1min`) genau dann anlaufen, wenn die Runde den Manager abfragt
  (07.10.: Start jeweils in derselben Zehntelsekunde wie die Runde). vhost01
  hätte so nie 45 min Ruhe erreicht (größte Lücke 30 min). Nach dem Dienststart und nach
  einer Runde mit Unklar-Befund zählt jeder laufende Job als schon gelaufen.
  Andere Vetos und Nutzung starten die Ruhe unverändert sofort neu.

## v2.0.0-beta.2 – 07.10.2026

- Aktiver Schlaf für vhost01 (`"mode": "aktiv"` + `"dependencies_verified": true`):
  Tagschlaffenster aus `/etc/media-staging.conf`, 20 min Mindestabstand zum
  Fensterende, 45 min Ruhe (persistent je Boot-ID), 10 min Mindestwachzeit nach
  Start/Resume, höchstens 6 Zyklen in 24 h, sonst 24 h Sperre.
- Ablauf: `rtcwake -m no -t` auf Fensterende minus Vorlauf mit Rückleseprobe
  aus sysfs, frische Schlussprüfung, logind `CanSuspend`, block-Inhibitoren,
  PCI-Weckflag der NIC (`power/wakeup`), Logeintrag und atomarer Zustand vor `systemctl suspend`;
  `aufgewacht` mit Schlafdauer.
- `raid_degradiert_erlaubt` (Standard false); RAID-Aktionen bleiben Veto.
- Plex-Bandbreite: Nutzung je Triple über `bandbreite_schwelle_bytes`
  (262144) in 180 s; Neustart nur bei kleinerem Zähler oder fehlendem Bucket
  mitten im Fenster (rollendes Fenster hielt beide Wächter dauerhaft unklar).
- Unit `gb-schlaf.service` ersetzt `gb-schlaf-schatten.service`: zusätzlich
  nur `CAP_SYS_BOOT`, `reboot`/`kexec` per SystemCallFilter gesperrt.
- Neuer Befehl `gb-wecken <host> [--nur-senden]` auf proxy01 mit fester
  MAC-Tabelle `/etc/greenbuddy/wecken.json`; wiederholt standardmäßig alle
  15 s bis zu 180 s, bis TCP antwortet; ein kaputtes Broadcast-Ziel blockiert
  das andere nicht mehr (Exit 3, wenn gar nichts hinausging).
- Testisolation: der GB1-Bereinigungstest liest keine Unit-Verzeichnisse des
  Testrechners mehr (vorher Zeitüberschreitung auf Rechnern mit vielen Units).
- Review 07.10.26 (aktiver Schlaf):
  - Weitere Verbraucher: Verbindungen auf 445 (Samba) und 8081 (Fileserver) sowie
    von außen auf jeden anderen lauschenden Port sind Veto (`verbindung_ausnahmen`,
    Standard 25565); `smb.service` in den Standard-Jobs; `closing`-Sitzungen
    (Prozesse nach dem Logout) sind Veto `sitzung_closing`; laufende
    `run-*.service`/`run-*.scope` im System- und in den User-Managern
    (`transient_benutzer`) sind Veto.
  - Ruhe nach Dienstneustart nur mit frischem Beobachtungsstempel
    (`/run/greenbuddy/schlaf-takt.json`, höchstens zwei Takte) und ohne offenen
    Schlafeintrag; jedes Aufwachereignis startet die Ruhe neu.
  - `systemctl suspend`: Ausnahmen führen nicht mehr zum Absturz; nach jedem
    Suspendfehler beginnt die Ruhe neu (kein Versuch im Minutentakt).
  - Vorbedingungen: RTC als Weckquelle (`power/wakeup` von rtc0) und keine
    Gen-0-Schläfer (`auto-sleep.timer`/`.service` laufen nicht,
    `delay-after-suspend.service` maskiert oder entfernt).
  - README: Pflichttest RTC-Weckung und Stilllegen der Gen-0-Units vor `mode: aktiv`.

## v2.0.0-beta.1 – 06.10.2026

- GreenBuddy 1 abgelöst; `LICENSE` und `.github/` übernommen.
- Python-Paket `greenbuddy2` (Version `2.0.0b1`), ausschließlich Standardbibliothek,
  mit sechs dünnen Startern und synthetischen Unittests.
- vhost01-Schattenwächter für Plex, Jellyfin, Java/Minecraft, SSH, Claude, Jobs,
  RAID/mdmon, GPU, Threema-Bot, Ansprüche und Zeitfenster.
- Gemeinsame Inhaltsklassifikation, begrenzter pcap-Stromparser und Mitschnitt
  auf vhost01; JSONL-Rotation, Heartbeat und höchstens 14 Tage Quelladressen.
- Trockenprüfung der Fenster/Timer; keine RTC- oder Timeränderung.
- Hostgebundenes, persistentes SSH-Register; `abmelden` ist niemals bereit.
- GDM-Zähler und zweiphasiger Phantom-IP-Test mit Lease, DAD, nft-Isolation,
  GARP-Serie und Freigabe. .110 und .115 sind fest gesperrt.
- Webhook-Baustein mit MAC, Frische, persistenter Deduplizierung/Warteschlange,
  TTL, Limits und geordneter Zustellung mit Quittung. Nicht installiert.
- Getrennte, getestete WOL-Funktion ohne automatische Aufrufer.
- Installer mit Manifest, Backups, bedingtem fapolicyd-Trust/SELinux-Labels,
  Rückbau sowie idempotenter GB1-Bereinigung auf proxy01.
