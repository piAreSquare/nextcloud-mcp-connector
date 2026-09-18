# Feature Research

**Domain:** OAuth-Resource-Server, der ein nach RFC 8693 getauschtes Fremd-Token annimmt (Keycloak Standard Token Exchange, F13-Orchestrator) und es auf ein lokales Nextcloud-Konto abbildet
**Researched:** 2026-09-18
**Confidence:** HIGH für das Keycloak- und MCP-Spec-Verhalten (offizielle Doku, Keycloak-Issue-API, MCP-Spec), MEDIUM für die Marktpraxis vergleichbarer MCP-Gateways (Herstellerblogs)

---

## 0. Was ein von Keycloak getauschtes Token tatsächlich trägt

Diese Feature-Liste steht und fällt mit dem gemessenen Verhalten der Gegenseite. Deshalb zuerst die Belege, danach die Kategorien.

| Beobachtung | Beleg | Confidence |
|---|---|---|
| Standard Token Exchange (V2) ist seit Keycloak 26.2 offiziell unterstützt und ab Werk an; V1 (legacy) ist deprecated und ab Werk aus | keycloak.org Blog 05/2025 "Standard Token Exchange is now officially supported in Keycloak 26.2"; keycloak.org/securing-apps/token-exchange | HIGH |
| `grant_type=urn:ietf:params:oauth:grant-type:token-exchange`, `subject_token_type` **muss** `...:access_token` sein (andere Typen kann V2 nicht) | Keycloak-Doku Token Exchange | HIGH |
| `audience` ist optional, mehrfach erlaubt und nennt die **`client_id` des Ziel-Clients**, nicht eine beliebige URI. Es wirkt als Downscoping der Audiences | Keycloak-Doku Token Exchange | HIGH |
| Der Requester-Client muss **confidential** sein und den Schalter "Standard token exchange" tragen; öffentliche Clients dürfen nicht tauschen. Das `subject_token` muss den Requester in seinem `aud` führen | Keycloak-Doku Token Exchange | HIGH |
| Das Ergebnis-Token trägt: `aud` = die angefragten Ziel-Clients, `azp` = der tauschende Client (also der F13-Orchestrator), `sub` = unverändert die Keycloak-User-Id, dazu `scope`, `resource_access` und `preferred_username`, soweit die Client-Scopes das hergeben | Keycloak-Doku Token Exchange | HIGH |
| **Kein `act`-Claim.** V2 kennt keine Delegations- und keine Subject-Impersonation-Semantik; ein `subject_token` mit `act` oder `may_act` wird ab Werk abgewiesen und gehört in den erst entstehenden Delegation-Flow | keycloak/keycloak Issue #37367, Issue #38279, PR #52504 | HIGH |
| Ein Token-Exchange erzeugt **keine neue Benutzersitzung** in Keycloak | Keycloak-Doku Token Exchange | HIGH |
| `aud` entsteht nicht von selbst. Automatische Audience-Auflösung greift nur, wenn der Ziel-Client eigene Client-Rollen hat, der Client eine Role-Scope-Mapping darauf hat und der Nutzer die Rolle trägt. Sonst braucht es einen expliziten Audience-Mapper (`included.custom.audience`) auf einem Client-Scope | Keycloak Audience-Doku und breite Community-Praxis (DEV, skycloak, digital-blueprint) | MEDIUM-HIGH |
| Nativer RFC-8707-`resource`-Parameter ist in Keycloak **noch nicht fertig**: Issue #14355 ist offen, Meilenstein 26.8, letzte Aktivität 11.09.2026; experimenteller Code ist am 17.03.2026 gemergt (PR #46763) | GitHub-API auf keycloak/keycloak, abgefragt 18.09.2026 | HIGH |
| Der `typ`-Header ist uneinheitlich: seit 26.2 gibt es einen Client-Schalter; neue Clients stellen `at+jwt` aus, bestehende bleiben auf `JWT` | keycloak/keycloak PR #37573, Issue #36696, Discussion #19419 | MEDIUM-HIGH |
| Cross-Domain-Ketten (anderer Realm, andere Domäne) laufen seit Keycloak 26.5 über JWT Authorization Grant (RFC 7523) plus Token Exchange, nicht über V2 allein | keycloak.org Blog 01/2026 "JWT Authorization Grant and Identity Chaining" | MEDIUM |

**Die zwei Konsequenzen, die alles andere bestimmen:**

1. **Ohne `act` gibt es keinen Marker "das ist ein getauschtes Token".** Für den Connector ist das Token äußerlich ein gewöhnliches Nutzer-Token der F13-Realm. Die einzige belastbare Spur der handelnden Partei ist `azp`. Also braucht der Exchange-Pfad eine **azp-Allowlist**, sonst prüft er nur, dass irgendein Client der Realm ein Token für ihn besorgt hat.
2. **Keycloaks `audience` ist eine `client_id`, die MCP-Spec verlangt eine kanonische Resource-URI.** Diese Lücke muss die Audience-Konvention (F13-Entscheidung 1) schließen, nicht der Code. Zwei saubere Wege: die `client_id` des Ziel-Clients **ist** die kanonische Resource-URI des Connectors (`https://cloud.example.org/exapps/mcp_connector/mcp`), oder ein Audience-Mapper schreibt genau diesen Wert zusätzlich hinein. Alles andere erzeugt eine Audience, die der bestehende RFC-8707-Vergleich in `oauth/verifier.py` zu Recht ablehnt.

**Die MCP-Spec setzt die Außengrenze:** MCP-Server "MUST validate that access tokens were issued specifically for them as the intended audience", "MUST only accept tokens that are valid for use with their own resources" und "MUST NOT accept or transit any other tokens" (Authorization, Abschnitt Token Handling). Wer ein Keycloak-Token annimmt, macht die Realm damit zu einem **zweiten Authorization Server dieser Resource**. RFC 9728 erlaubt mehrere Einträge in `authorization_servers`, die Auswahl liegt beim Client (MCP-Spec, Authorization Server Discovery). Heute liefert `oauth/metadata.py` genau einen Eintrag (`"authorization_servers": [base]`).

---

## Feature Landscape

### Table Stakes (Users Expect These)

"Nutzer" ist hier der Betreiber einer Behördeninstanz plus die F13-Seite. Fehlt einer dieser Punkte, ist der Pfad nicht abnahmefähig.

| Feature | Why Expected | Complexity | Notes |
|---------|--------------|------------|-------|
| **Issuer-Allowlist aus Konfiguration** (genau ein oder wenige erlaubte `iss`), kein Vertrauen aus dem Token heraus | Multi-Issuer-Resource-Server ohne Allowlist ist das Lehrbuchloch; Spring Security macht die Allowlist zur Pflicht des Betreibers | LOW | Hauslinie existiert wörtlich in `oauth/oidc.py`: "The issuer is administrator configuration ... Nothing a client, a browser or a response supplies can widen that set." Für den Exchange-Pfad wiederverwenden, nicht neu erfinden |
| **JWKS-Abruf mit Cache, Rotation und fail-closed** | Signaturprüfung ohne Schlüsselrotation bricht bei jedem Key-Rollover der Realm | LOW (Wiederverwendung) | `OidcClient._key` / `_refresh_keys` liefert das fertig: `JWKS_CACHE_SECONDS = 300`, höchstens ein Nachladen je Aufruf, unbekannte `kid` und `kid`-Kollision enden beide in derselben Ablehnung |
| **Algorithmen- und Schlüsseltyp-Allowlist** (nur asymmetrisch, nie `none`, nie `HS*`, nie `oct`) | Klassische Signaturumgehung | LOW (vorhanden) | `_ALLOWED_ALGORITHMS`, `_ALLOWED_KEY_TYPES` in `oauth/oidc.py` decken das ab |
| **Standard-Claims `iss`, `exp`, `nbf`, `iat`, `aud` mit Clock-Skew-Toleranz** | Grundpflicht jedes Resource Servers (OAuth 2.1 Abschnitt 5.2) | LOW | `jwt.decode(..., leeway=_LEEWAY_SECONDS, options={"require": [...]})` existiert; für Access-Tokens die `require`-Liste anpassen (`nonce` gibt es hier nicht) |
| **Audience-Prüfung an der bestehenden RFC-8707-Stelle** gegen die kanonische Resource-URI | MCP-Spec-Pflicht; der Platz existiert (`StoreTokenVerifier._resource`, `check_resource_allowed`) | LOW-MEDIUM | Erwartete Audience als Konfigurationswert mit Default "eigene Resource-URI". MEDIUM nur wegen der Keycloak-Realität aus Abschnitt 0 (client_id gegen URI) |
| **Token-Typ-Prüfung** (`typ` = `at+jwt` oder `JWT`, konfigurierbar; ID-Token wird abgewiesen) | Ein ID-Token, das als Access-Token durchgeht, ist eine stille Rechteausweitung | LOW | Keycloak stellt je nach Client-Alter beides aus (PR #37573). Also beide Werte zulassen, aber nie "typ egal" |
| **azp-Allowlist: welcher Client darf für andere handeln** | Ersatz für das fehlende `act`; ohne sie akzeptiert der Connector jedes Realm-Token mit passender Audience | LOW | Der einzige Punkt, der die Delegation überhaupt sichtbar macht. Gehört in dieselbe Konfigurationsebene wie die Issuer-Allowlist |
| **Konfigurierbares Claim-Mapping auf ein Nextcloud-Konto**, Claim-Name **und** Form als Konfiguration | F13-Entscheidung 2 steht aus; ein fest verdrahteter Claim-Name wäre eine Wette | MEDIUM | Muster liegt vor: `STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1` ist bereits eine benannte Strategie statt einer Verdrahtung. Der Exchange-Pfad braucht mindestens zwei Profile (siehe Differenzierer) |
| **Abweisung statt stiller Anlage, wenn kein Konto passt** | Spec-Note Abschnitt 5; ohne das bekommt der Connector faktisch Anlagerecht | MEDIUM | Existenzprüfung ohne neuen Netzaufruf im heißen Pfad. `audit/accounts.py` kennt den Weg bereits (AppAPI `GET /ocs/v2.php/apps/app_api/api/v1/users`, App-Kontext, keine Impersonation). **Achtung: die Asymmetrie muss sich umdrehen.** Dort bedeutet "unbekannt" = behalten; hier muss "unbekannt" = ablehnen bedeuten, und die dort notierte Unsicherheit über LDAP-Backends (`searchDisplayName('')`) wird damit zur Sperre statt zur Nachsicht |
| **Anschluss an die bestehende Audit-Kette**, Kette über den Principal | Ein Pfad, der nicht im Audit steht, entwertet das Audit-Versprechen des Enterprise-Abschnitts | LOW-MEDIUM | `audit/record.py` plus `oauth/principal.py` (`u:<principal>`). Es gelten die bestehenden Verbote unverändert: kein Parameterwert, keine IP, kein Token, kein Claim-Wert im Klartext |
| **Ab Werk aus, ein Schalter, dokumentierte Defaults** | Spec-Note Abschnitt 5; ein Store-Release darf für 99 Prozent der Installationen nichts ändern | LOW | Reiht sich in `config.select_mode` ein: gegenseitig ausschließende Modi statt Vorrangregeln |
| **Fehlerverhalten nach Spec: 401 mit `WWW-Authenticate` und `resource_metadata`, 403 bei fehlendem Scope, keine Begründungs-Orakel** | MCP-Spec Error Handling; eine Fehlermeldung, die verrät, welcher Claim gefehlt hat, ist ein Mapping-Orakel | LOW | Der Server hat das Muster schon; der Exchange-Pfad darf keine feinere Auskunft geben als der bestehende |
| **Kurze Tokenlebensdauer akzeptieren, keine Refresh-Logik im Connector** | Getauschte Tokens sind Access-Tokens; Refresh gehört auf die Orchestrator-Seite | LOW | Keycloak gibt Refresh-Tokens im Exchange nur, wenn der Betreiber es ausdrücklich erlaubt. Der Connector fasst sie nicht an |

### Differentiators (Competitive Advantage)

| Feature | Value Proposition | Complexity | Notes |
|---------|-------------------|------------|-------|
| **Mandantentrennung über die Audience-Konvention** (ein Bezeichner je Connector-Instanz statt einer Realm-weiten Audience) | Ein Token aus Instanz A ist an Instanz B wertlos. Genau die Frage aus F13-Entscheidung 1 | LOW im Code, HIGH im Abstimmungsbedarf | Empfehlung an F13: Ziel-Client-`client_id` = kanonische Resource-URI der Instanz. Das erfüllt RFC 8707 und Keycloaks client_id-basierte `audience` in einem Wert, solange Keycloak den `resource`-Parameter nicht nativ kann (Issue #14355, Meilenstein 26.8) |
| **Benannte Mapping-Profile statt eines Claim-Namens**, mit einem ausdrücklichen LDAP-Profil | Laut Feldberichten die häufigste Fehlerquelle: `user_oidc` mit "Use unique user id" an erzeugt eigene Hash-Ids und trifft das LDAP-Konto nie | MEDIUM | Mindestens: (a) `sub` über die vorhandene `user_oidc_unique_uid_sub_v1`-Ableitung, (b) direktes Claim-zu-Login-Name-Profil für LDAP-Instanzen, in denen `mapping-uid` und `ldapExpertUsernameAttr` aufeinander abgestimmt sind. Beide enden im selben Abgleich gegen die Kontoliste |
| **Offener, nachprüfbarer Testfall im Repo** (Fixture aus anonymisiertem Beispiel-Token und Realm-Export) | Die Spec-Note verspricht es wörtlich: "den Testfall lege ich offen im Connector-Repo ab, damit er nachprüfbar ist und nicht nur behauptet" | LOW, blockiert durch F13-Entscheidung 3 | Bis zum Beispiel-Token: Fixture aus einem selbst gebauten Realm einer lokalen Keycloak-Instanz, klar als Annahme markiert und später ersetzt |
| **Audit-Zeile nennt die handelnde Partei zusätzlich zum Subjekt** ("azp X handelte für Konto Y") | Keycloak V2 schreibt kein `act`; wer die Delegation trotzdem im Log hat, kann sie belegen. Genau das Argument, mit dem F13 vom Dienstkonto wegkommt | LOW-MEDIUM | Neue Spalte oder ein fester Herkunftsschlüssel im bestehenden Record, kein neues Subsystem. Wert ist eine konfigurierte Client-Id, kein Freitext aus dem Token |
| **Trockenlauf-Kommando für die Einrichtung** (Beispiel-Token gegen die aktive Konfiguration prüfen und sagen, an welcher Regel es scheitert) | Die Diagnose gehört zum Administrator, nicht in die HTTP-Antwort. Spart genau die zwei Runden, die die Spec-Note vermeiden will | MEDIUM | Reiht sich neben `exapp/audit_verify.py` ein. Läuft nie im heißen Pfad und gibt nur dort Klartext, wo schon Admin-Rechte sind |
| **PRM-Eintrag nur, wenn der Pfad an ist** | Spec-sauber (RFC 9728 erlaubt mehrere AS), ohne dass generische MCP-Clients bei 99 Prozent der Installationen plötzlich eine fremde Realm sehen | LOW | `oauth/metadata.py` Zeile 167 ist die eine Stelle. Bewusster Entscheid nötig: Ein zweiter Eintrag ist ehrlich, kann aber Clients in den falschen Flow schicken. Empfehlung: an den Schalter koppeln und in den Release-Notizen begründen |
| **Skriptbare Einrichtung über `occ oauth2:add-client`** | Aus der Spec-Note Abschnitt 6; für Landesinstanzen der Unterschied zwischen Anleitung und Playbook-Zeile | LOW | Reine Dokumentation plus ein Provisionierungsbeispiel; verifiziert für NC 34.0.4 und 35.0.0 |
| **Zwei-Konten-Negativbeweis für den Exchange-Pfad** | "Der Assistent sieht nie mehr als der Nutzer" muss auch für den neuen Weg gemessen sein, nicht behauptet | MEDIUM | Bestehendes Muster aus v1.0 wiederverwenden: Token für Konto A, Zugriff auf eine Ressource von Konto B, erwartet 403/404 aus Nextcloud |

### Anti-Features (Commonly Requested, Often Problematic)

| Feature | Why Requested | Why Problematic | Alternative |
|---------|---------------|-----------------|-------------|
| **Stille Kontoanlage / Just-in-time-Provisioning** | Rollout auf Landesinstanzen ohne vorherige Synchronisation | Der Connector bräuchte Anlagerecht in Nextcloud, also mehr Rechte als jeder Nutzer, den er vertritt. Auf LDAP-Instanzen entstehen Doubletten neben dem Verzeichniskonto, und das Versprechen "sieht nie mehr als der angemeldete Nutzer" wird prüfbar falsch | Abweisung plus Trockenlauf-Diagnose. Provisionierung ist Aufgabe von `user_oidc`, LDAP oder dem SCIM-Weg, den Nextcloud 35 mitbringt |
| **Token-Introspection (RFC 7662) im heißen Pfad** | Sofortige Rücknahme eines Tokens | Ein fremder Dienst im heißen Pfad jedes Werkzeugaufrufs, gegen die ausdrückliche Hauslinie in `oauth/verifier.py` (D-34, D-37) und gegen Spec-Note Abschnitt 5. Zudem erzeugt ein Exchange in Keycloak gar keine Sitzung, deren Ende man abfragen könnte | Lokale Signaturprüfung, kurze Tokenlaufzeit der Realm, JWKS-Cache als einziger Netzaufruf. Falls ein Betreiber Introspection zwingend braucht: optionaler Zusatz mit eigenem Cache, nie Default |
| **Das empfangene Token an Nextcloud weiterreichen (Token-Passthrough)** | Spart das Mapping komplett | Von der MCP-Spec ausdrücklich verboten ("MUST NOT accept or transit any other tokens", "MUST NOT pass through the token it received"). Nextcloud könnte damit ohnehin nichts anfangen | Mapping auf ein Konto, danach der bestehende Credential-Weg (AppAPI-Kontext beziehungsweise hinterlegte Zugangsdaten) |
| **E-Mail-Adresse oder Anzeigename als Kontoschlüssel** | Liest sich am Token am natürlichsten | OIDC Core 5.7: nur `iss` und `sub` zusammen sind ein stabiler Bezeichner; `email` und `preferred_username` dürfen ausdrücklich nicht als eindeutige Kennung dienen, sie können sich ändern und wiederverwendet werden | `sub` als Anker, `preferred_username` nur als Mapping-Eingabe eines ausdrücklich gewählten Profils, immer mit Abgleich gegen ein existierendes Konto |
| **`sub` blind als Nextcloud-Benutzerkennung nehmen** | "sub ist doch die Id" | Keycloaks `sub` ist eine Realm-UUID und trifft keine Nextcloud-Kennung. Auf LDAP-Instanzen fallen Anmeldename und interne Kennung ohnehin auseinander | Benannte Ableitungsprofile plus Abgleich; genau das Muster, das `user_oidc_unique_uid_sub_v1` schon abbildet |
| **Issuer aus dem Token entdecken und dann vertrauen** | "Multi-Issuer ohne Konfiguration" | Der Angreifer wählt den Issuer und damit die JWKS-URL: Vertrauensumgehung plus SSRF | Allowlist aus der Konfiguration, Discovery nur gegen den konfigurierten Issuer, alle Endpunkte auf dessen Origin. Steht so bereits in `oauth/oidc.py` |
| **Rollen aus `realm_access` / `resource_access` im Connector auswerten** | "Wir haben doch Rollen im Token" | Verschiebt die Rechteentscheidung von Nextcloud in den Connector und schafft eine zweite, driftende Rechtequelle | Rechte bleiben in Nextcloud. Scopes höchstens als Verengung, nie als Erweiterung |
| **Subject-Impersonation / Admin-Exchange "beliebiger Nutzer per Dienstkonto"** | Bequemster Weg für einen Orchestrator | Keycloak V2 kann es nicht (Issue #37367), und es ist genau der Dienstkonto-Weg, den F13 loswerden will | Standard-Exchange mit dem Nutzer-Token als `subject_token`; die Identität bleibt beim Nutzer |
| **Mehrere Identitätswege gleichzeitig in einer Anfrage zulassen** (Exchange-Bearer und Basic und AppAPI-Header) | "Robustheit" | Vorrangregeln sind die Fehlerquelle, an der Rechtegrenzen unbemerkt kippen | Gegenseitig ausschließende Modi, wie `config.select_mode` sie heute schon durchsetzt: der Exchange-Pfad wird ein fünfter Modus, kein Überbau |
| **Eigene Zwischenspeicherung der getauschten Tokens für Wiederverwendung** | Spart Exchange-Aufrufe | Tokenhaltung ohne Sitzungsbindung; der Connector würde fremde Bearer horten, die er nicht widerrufen kann | Der Orchestrator tauscht je Aufruf und hält den Cache auf seiner Seite (so machen es die Gateways, siehe Vergleich) |

---

## Feature Dependencies

```
Schalter "Exchange-Pfad an" (ab Werk aus)
    └──requires──> Issuer-Allowlist (Konfiguration)
                       └──requires──> JWKS-Client mit Cache und Rotation   [vorhanden: oauth/oidc.py]
                                          └──requires──> Algorithmen-Allowlist [vorhanden]

Audience-Prüfung (RFC 8707)
    └──requires──> kanonische Resource-URI          [vorhanden: metadata.RESOURCE_SUFFIX, verifier._resource]
    └──requires──> F13-Entscheidung 1 (Audience-Konvention)

azp-Allowlist ──ersetzt──> act-Claim (den Keycloak V2 nicht schreibt)

Claim-Mapping auf ein Konto
    └──requires──> Mapping-Profil (F13-Entscheidung 2)
    └──requires──> Kontoexistenz-Prüfung
                       └──requires──> AppAPI-Benutzerliste im App-Kontext  [vorhanden: audit/accounts.py]
                       └──requires──> umgekehrte Asymmetrie (unbekannt = ablehnen)

Werkzeugaufruf unter dem gemappten Konto
    └──requires──> Identitätsauflösung an der Transportgrenze [vorhanden: verifier.IdentitySource, OAUTH_STATE_ATTR]
    └──requires──> Credential-Weg des Betriebsmodus
                       ├── ExApp-Modus: AppAPI-Header mit der Kennung      [vorhanden: nextcloud/credentials.py]
                       └── Standalone: hinterlegte Verbindung des Kontos   [vorhanden seit 0.2.0, PR #6]

Audit-Anschluss ──enhances──> Werkzeugaufruf   [vorhanden: audit/record.py, oauth/principal.py]

PRM-Eintrag für den zweiten Authorization Server ──conflicts──> stille Voreinstellung
Golden-Fixture aus echtem Realm-Export ──blocked-by──> F13-Entscheidung 3
```

### Dependency Notes

- **Alles hängt am Schalter:** Der Exchange-Pfad ist ein fünfter, gegenseitig ausschließender Modus neben `stdio`, `exapp`, `http_passthrough`, `http_static_bearer`. Wird er als sechster Vorrang über die bestehenden gelegt, entsteht genau die Vorrangfrage, die `select_mode` heute vermeidet.
- **Die Audience-Prüfung hängt an einer fremden Entscheidung, nicht an Code:** Der Vergleichspunkt existiert seit v1.0. Was fehlt, ist der erwartete Wert. Deshalb ist der Code entscheidungsunabhängig baubar, die Abnahme nicht.
- **Kontoexistenz ist die riskanteste Wiederverwendung:** `audit/accounts.py` ist bewusst nachsichtig gebaut ("unknown, so every account exists"). Für den Exchange-Pfad ist genau diese Voreinstellung gefährlich. Die Funktion darf wiederverwendet werden, ihre Auswertung nicht.
- **Die Antwort auf "wie handelt der Connector dann?" ist modusabhängig:** Im ExApp-Modus genügt die gemappte Kennung, weil AppAPI-Header (`AUTHORIZATION-APP-API` als base64 von `<user>:<app_secret>`) sie tragen. Standalone braucht eine bereits bestehende Verbindung des Kontos. Wird das nicht früh entschieden, verspricht die Konfiguration einen Pfad, den die halbe Installationsbasis nicht gehen kann.
- **`azp`-Allowlist und `act` schließen sich nicht aus, sie lösen sich ab:** Sobald Keycloak Delegation liefert, wird `act` die bessere Quelle. Die Konfiguration sollte deshalb "erlaubte handelnde Partei" heißen und nicht "erlaubtes azp".

---

## MVP Definition

### Launch With (v1.6, entscheidungsunabhängig baubar)

- [ ] Fünfter Modus mit eigenem Schalter, ab Werk aus, dokumentierte Defaults
- [ ] Issuer-Allowlist, JWKS-Cache mit Rotation, fail-closed, Algorithmen-Allowlist (Wiederverwendung aus `oauth/oidc.py`)
- [ ] Standard-Claims `iss`, `exp`, `nbf`, `iat`, `aud` mit Clock-Skew
- [ ] `typ`-Prüfung, die `at+jwt` und `JWT` kennt und ID-Tokens abweist
- [ ] Audience-Prüfung an der bestehenden RFC-8707-Stelle, erwarteter Wert als Konfiguration mit Default "eigene Resource-URI"
- [ ] Allowlist der handelnden Partei (`azp`), weil Keycloak V2 kein `act` schreibt
- [ ] Mapping als benanntes Profil, mindestens `sub`-basiert und ein direkt abbildendes Profil für LDAP-Instanzen
- [ ] Kontoexistenz-Prüfung mit umgekehrter Asymmetrie: Zweifel bedeutet Ablehnung
- [ ] Audit-Anschluss samt handelnder Partei, unter den bestehenden Inhaltsverboten
- [ ] Spec-konformes Fehlerverhalten ohne Begründungs-Orakel

### Add After Validation (v1.6.x, sobald F13 antwortet)

- [ ] Golden-Fixture aus echtem Beispiel-Token und Realm-Export (Trigger: F13-Entscheidung 3)
- [ ] Festgeschriebene Audience-Konvention samt Mandantennachweis (Trigger: F13-Entscheidung 1)
- [ ] Zweiter Eintrag in `authorization_servers`, gekoppelt an den Schalter (Trigger: Owner-Entscheid, ob die PRM den Fremd-AS ausweisen soll)
- [ ] Trockenlauf-Kommando für Administratoren
- [ ] Zwei-Konten-Negativbeweis auf dem Exchange-Pfad, gemessen statt behauptet

### Future Consideration (v2+)

- [ ] `act`-Auswertung, sobald Keycloak Delegation ausliefert (heute Issue #38279, nicht in V2)
- [ ] Identity Chaining über Domänengrenzen (JWT Authorization Grant, Keycloak 26.5) für Landesinstanzen mit eigener Realm je Haus
- [ ] Optionale Introspection als ausdrücklich gewählter Zusatz mit eigenem Cache, nie als Default
- [ ] Scope-gestützte Verengung der Werkzeugmenge (Step-up nach MCP-Spec), erst wenn F13 Scopes überhaupt setzt

---

## Feature Prioritization Matrix

| Feature | User Value | Implementation Cost | Priority |
|---------|------------|---------------------|----------|
| Schalter, ab Werk aus | HIGH | LOW | P1 |
| Issuer-Allowlist plus JWKS-Wiederverwendung | HIGH | LOW | P1 |
| Standard-Claims plus Skew | HIGH | LOW | P1 |
| Audience-Prüfung an der 8707-Stelle | HIGH | LOW | P1 |
| `typ`-Prüfung | MEDIUM | LOW | P1 |
| azp-Allowlist | HIGH | LOW | P1 |
| Mapping-Profile plus Ablehnung ohne Konto | HIGH | MEDIUM | P1 |
| Kontoexistenz-Prüfung mit umgekehrter Asymmetrie | HIGH | MEDIUM | P1 |
| Audit-Anschluss mit handelnder Partei | HIGH | LOW | P1 |
| Golden-Fixture aus echtem Realm-Export | HIGH | LOW | P2 (blockiert) |
| Mandantentrennung über Audience-Konvention | HIGH | LOW im Code | P2 (blockiert) |
| PRM-Eintrag für den zweiten AS | MEDIUM | LOW | P2 |
| Trockenlauf-Kommando | MEDIUM | MEDIUM | P2 |
| Zwei-Konten-Negativbeweis | HIGH | MEDIUM | P2 |
| `act`-Auswertung | LOW (heute) | MEDIUM | P3 |
| Identity Chaining über Domänen | MEDIUM | HIGH | P3 |

---

## Competitor Feature Analysis

| Feature | Solo agentgateway / Envoy AI Gateway / TrueFoundry (MCP-Gateways) | IBM mcp-context-forge | Spring-Security-Resource-Server (klassisch, Multi-Issuer) | Unser Ansatz |
|---------|---|---|---|---|
| Wo wird getauscht | Am Gateway, je Werkzeugaufruf, mit Cache für Agent-Schleifen | Am Gateway | Nicht Teil der Bibliothek | Auf der Orchestrator-Seite (F13). Der Connector tauscht nie selbst, er nimmt nur an |
| Vertrauensanker | Konfigurierter IdP je Route | Konfigurierter externer IdP | Allowlist der Issuer im Resolver, ausdrücklich Pflicht | Issuer-Allowlist in der Betreiberkonfiguration, Discovery nur gegen diesen Issuer |
| Identität nach unten | Downstream-Token mit dem Nutzer als `sub`, kein geteiltes Dienstkonto | Vorab bereitgestellte SSO-Nutzer, Prüfung gegen die eigene Nutzerdatenbank | Nur Authentifizierung, Mapping ist Anwendungssache | Claim zu Nextcloud-Konto über benanntes Profil, Abgleich gegen die Instanz |
| Unbekannter Nutzer | Teils Just-in-time-Anlage | Ablehnung; Rollen aus der Datenbank sind Pflicht, Tokenprüfung allein genügt nicht | Anwendungssache | Ablehnung, ausdrücklich keine Anlage |
| Kennung als Schlüssel | Kanonische Id (`oid`/`sub`), E-Mail ausdrücklich nie | Vorab abgeglichene Nutzer | Anwendungssache | `sub`-Anker plus optionales Login-Namen-Profil, E-Mail nie |
| Delegationsnachweis | Teils `actorToken` (Entra-eigen, nicht RFC 8693) | Gateway-Log | Nicht vorgesehen | Audit-Zeile mit handelnder Partei, weil Keycloak V2 kein `act` liefert |
| Hot Path | Lokale Signaturprüfung, Token-Cache | Lokale Prüfung | Lokale Prüfung, JWKS-Cache | Lokale Prüfung, JWKS als einziger Netzaufruf, Kontoliste zwischengespeichert |

**Was auffällt:** Alle vergleichbaren Systeme sitzen als Gateway *vor* dem Zielsystem und tauschen selbst. Der Connector ist der seltenere Fall, nämlich das Zielsystem, das ein von fremder Hand getauschtes Token annimmt. Dadurch entfallen die Gateway-typischen Sorgen (Client-Secrets, Token-Cache, Exchange-Latenz) und es bleibt genau eine harte Frage übrig: Wie wird aus einem Fremd-Claim ein lokales Konto, ohne die Rechtegrenze zu verschieben.

---

## Offene Punkte, die Recherche nicht klären kann

- **Welchen Wert F13 in `aud` schreibt** (Entscheidung 1). Recherche kann nur sagen, welche Werte Keycloak überhaupt setzen kann: Ziel-`client_id`, Audience-Mapper-Wert, und ab Keycloak 26.8 vermutlich der `resource`-Parameter.
- **Ob die F13-Instanzen `preferred_username` überhaupt in den getauschten Tokens führen.** Das hängt an den Client-Scopes des Ziel-Clients, nicht an Keycloak allgemein. Ohne Beispiel-Token ist jede Annahme darüber ungedeckt.
- **Ob die Zielinstanzen LDAP-gebunden sind** und wie dort `mapping-uid` beziehungsweise `ldapExpertUsernameAttr` gesetzt sind. Das entscheidet, welches Mapping-Profil in der Praxis das genutzte ist.
- **Ob die AppAPI-Benutzerliste auf LDAP-Backends vollständig antwortet.** In `audit/accounts.py` steht das ausdrücklich als unvermessene Annahme (A1). Für den Exchange-Pfad wird daraus ein Messpunkt, kein Restrisiko.

---

## Sources

**HIGH (offizielle Doku, API-Abfragen, Spezifikationen)**
- https://www.keycloak.org/securing-apps/token-exchange (Parameter, Claims im Ergebnis-Token, confidential-Pflicht, keine neue Sitzung, V1 deprecated)
- https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2 (GA seit 26.2)
- https://www.keycloak.org/2026/01/jwt-authorization-grant (Identity Chaining, RFC 7523 plus RFC 8693, Keycloak 26.5)
- GitHub-API `repos/keycloak/keycloak/issues/14355`, abgefragt 18.09.2026: `state=open`, `milestone=26.8`, `updated_at=2026-09-11` (RFC 8707 nativ noch nicht geliefert)
- GitHub-API `repos/keycloak/keycloak/pulls/46763`, `merged_at=2026-03-17` (experimentelle Resource-Indicators)
- keycloak/keycloak Issues #37367, #38279, PR #52504, PR #37573, Issue #36696 (keine Delegation in V2, `act`/`may_act` abgewiesen, `typ`-Schalter)
- https://modelcontextprotocol.io/specification/draft/basic/authorization (Token Handling: MUST validate audience, MUST NOT accept or transit other tokens; Resource-Parameter, kanonische URI)
- https://modelcontextprotocol.io/specification/draft/basic/authorization/security-considerations (Access Token Privilege Restriction, kein Passthrough an Upstream)
- https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery (mehrere `authorization_servers` erlaubt, Auswahl beim Client, RFC 9728 Abschnitt 7.6)
- https://www.rfc-editor.org/rfc/rfc8693.html (act, may_act, client_id, Impersonation gegen Delegation)
- OpenID Connect Core 1.0 Abschnitt 5.7 (nur `iss` plus `sub` sind stabil; `email`, `preferred_username` dürfen nicht als eindeutige Kennung dienen)
- Repo-Belege im eigenen Code: `src/mcp_connector/oauth/oidc.py` (JWKS-Cache, Allowlists, `azp`-Regel, `user_oidc_unique_uid_sub_v1`), `oauth/verifier.py` (RFC-8707-Vergleich, Identität einmal je Anfrage), `oauth/metadata.py:167` (`authorization_servers`), `audit/accounts.py` (AppAPI-Benutzerliste, Asymmetrie-Regel, Annahme A1), `nextcloud/credentials.py` (AppAPI-Header), `oauth/principal.py` (Principal-Regel, LDAP-Fall)

**MEDIUM (Herstellerblogs, Community-Praxis, verifiziert gegen mindestens eine zweite Quelle)**
- https://docs.solo.io/agentgateway/2.3.x/mcp/token-exchange/obo/obo-entra/ und https://agentgateway.dev/blog/2026-07-12-agentgateway-token-exchange-jwt-assertion-entra-obo/ (Gateway-seitiger Exchange, Identität statt Dienstkonto)
- https://aigateway.envoyproxy.io/blog/multi-user-mcp-header-forwarding/ (Per-User-Identität an der Gateway-Schicht)
- https://www.truefoundry.com/docs/ai-gateway/mcp/mcp-server-oauth-azure-obo (Entra OBO, kein RFC 8693)
- IBM/mcp-context-forge Issue #6583 (vorab bereitgestellte SSO-Nutzer statt Anlage)
- https://skycloak.io/blog/keycloak-mcp-server-401-audience-rfc-8707/ (Audience-Mapper als Behelf, solange Keycloak `resource` nicht kann)
- https://docs.spring.io/spring-security/reference/servlet/oauth2/resource-server/multitenancy.html (Issuer-Allowlist als Pflicht des Betreibers)
- help.nextcloud.com und s3lph.me zur `user_oidc`-LDAP-Abbildung ("Use unique user id" abschalten, `mapping-uid` an das LDAP-Attribut angleichen)

---
*Feature research for: Annahme getauschter Tokens (RFC 8693) im Nextcloud MCP Connector*
*Researched: 2026-09-18*
