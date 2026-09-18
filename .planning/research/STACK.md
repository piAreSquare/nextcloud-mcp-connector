# Stack Research

**Domain:** Nextcloud MCP-only ExApp, Milestone v1.6 "F13 Token Exchange Identity Mapper"
(Annahme fremder, nach RFC 8693 getauschter Keycloak-Tokens: JWKS, Standard-Claims,
Claim-Mapping, Audit-Anschluss)
**Researched:** 2026-09-18
**Confidence:** HIGH für alles, was gegen PyPI, gegen die PyJWT-Sicherheitshinweise und gegen
den installierten Quelltext (`.venv`, `src/mcp_connector/oauth/oidc.py`, `verifier.py`,
`mcp/server/auth/*`) gelesen wurde. MEDIUM für die Keycloak-Claim-Konventionen, die aus der
Keycloak-Doku plus Sekundärquellen stammen und erst mit dem Beispiel-Token aus Entscheidung 3
der Spec-Note belegt sind. LOW für nichts, was hier als Empfehlung steht.

**Diese Datei ersetzt die v1.5-Stack-Recherche vom 2026-08-28.** Der Kernstack (Python 3.13,
`mcp>=2.0,<3`, httpx, lxml, uv, AppAPI/HaRP, SQLite, stdlib-Audit) wird nicht angetastet und
hier nicht erneut begründet. Es geht ausschließlich um die JWKS-Validierung fremder Tokens.

---

## Antwort in drei Sätzen

**Es kommt keine einzige neue Laufzeit-Abhängigkeit dazu, aber eine Untergrenze muss steigen:**
PyJWT bleibt die Bibliothek, die Version muss von `>=2.13,<3` auf `>=2.14,<3` angehoben und der
Lock von 2.13.0 auf 2.14.0 gezogen werden, weil 2.14.0 vom 11.09.2026 eine reine
Sicherheitsfreigabe ist, deren Befunde genau den Code treffen, den dieser Milestone baut
(JWKS-Abruf, `kid`-Behandlung, JWK-Parsing).
**`PyJWKClient` wird trotzdem nicht benutzt:** er ist synchron auf `urllib` gebaut und würde im
heißen Pfad jedes Werkzeugaufrufs den Event-Loop blockieren; die asynchrone JWKS-Maschinerie
existiert seit PR #6 bereits in `oauth/oidc.py` (Cache mit Verfallszeit, Rotation über
unbekannte `kid`, Algorithmus-Allowlist, Schlüsseltyp-Allowlist, Größenlimit, keine Umleitungen)
und wird für den Exchange-Pfad herausgelöst statt zweitgeschrieben.
**Zwei Fähigkeiten fehlen dieser vorhandenen Maschinerie für den neuen Bedrohungsfall**, und
beide sind eigener Code, kein Paket: eine Abkühlzeit gegen die Verstärkung durch unbekannte
`kid` (PyJWT löst dasselbe Problem in 2.14 mit `cooldown_duration=30`) und ein Single-Flight,
damit gleichzeitige Anfragen nicht gleichzeitig abrufen.

---

## Recommended Stack

### Core Technologies

| Technology | Version | Purpose | Why Recommended |
|------------|---------|---------|-----------------|
| `pyjwt[crypto]` | **`>=2.14,<3`** (heute 2.14.0, 11.09.2026; Lock steht auf 2.13.0) | Header lesen, Signatur prüfen, Standard-Claims prüfen, JWK zu Schlüsselobjekt | Schon direkte Abhängigkeit (`oauth/oidc.py` nutzt sie), schon von `mcp` selbst verlangt (`pyjwt[crypto]>=2.10.1`), und 2.14.0 schließt fünf Befunde, die ausschließlich den JWKS-Pfad betreffen. Details unten unter "Warum 2.14 keine Kür ist". |
| `cryptography` | `>=50,<51` (heute 50.0.1; Lock steht auf 50.0.0) | RSA/EC/EdDSA-Verifikation unter PyJWT, Testschlüssel erzeugen | Bereits direkte Abhängigkeit seit Phase 03-02. 50.0.1 ist ein reiner Wheel-Neubau gegen OpenSSL 4.0.2, kein API-Wechsel: mitziehen, wenn der Lock ohnehin angefasst wird. |
| `httpx` | `>=0.28,<0.29` (unverändert, 0.28.1 ist weiterhin die aktuelle Fassung der 0.x-Linie) | JWKS und Discovery abrufen | Die Projektregel aus `docs/dependency-audit.md` gilt weiter: eigener Code spricht `httpx`, weil `respx` `httpx` mockt und nicht `httpx2`. `oauth/oidc.py` macht es bereits so, inklusive eigenem Client ohne geteilten Pool gegenüber der fremden Vertrauensdomäne (T-06-14). |
| `mcp` | `>=2.0,<3` (unverändert, 2.0.0 installiert) | Transportgrenze, Token-Endpunkt, `TokenVerifier`-Protokoll | Neu und für diesen Milestone relevant: das SDK trägt serverseitig bereits den SEP-990-Assertion-Grant (`AuthSettings.identity_assertion_enabled`, `OAuthAuthorizationServerProvider.exchange_identity_assertion`, `JwtBearerRequest` im Token-Handler). Das ist ein fertiger Andockpunkt, der nichts kostet. Siehe "Zwei Einbauorte". |
| Python | 3.13 (unverändert) | `asyncio.Lock` für Single-Flight, `time.monotonic` für Abkühlzeit und Cache, `hmac.compare_digest` | Alles, was über PyJWT hinaus gebraucht wird, steht in der Standardbibliothek. |

### Supporting Libraries

| Library | Version | Purpose | When to Use |
|---------|---------|---------|-------------|
| `respx` (dev) | `>=0.23.1` (vorhanden) | JWKS-Abrufe, Rotation, 500er, Umleitungen und Zeitüberschreitungen im Test nachstellen | Für jeden Test des neuen JWKS-Moduls. Kein echter Keycloak nötig, solange das Beispiel-Token aus Entscheidung 3 der Spec-Note fehlt. |
| `cryptography` (dev-Nutzung) | wie oben | Testschlüsselpaare erzeugen und daraus JWKS-Dokumente bauen | Ersetzt jedes Zusatzpaket zur Schlüsselerzeugung. Es braucht kein `jwcrypto` und kein `authlib` nur zum Bauen eines Test-JWKS. |
| `pytest` (dev) | `>=9.1.1` (vorhanden) | Tests | Unverändert. |

### Development Tools

| Tool | Purpose | Notes |
|------|---------|-------|
| `uv` | Lock und Sync | `uv lock --upgrade-package pyjwt --upgrade-package cryptography` nach der Anhebung in `pyproject.toml`, danach `uv sync`. Die Untergrenze im Manifest allein ändert den Lock nicht. |
| ruff / pyright / vulture | Qualitätsgates | Unverändert, gelten für das neue Modul wie für jedes andere. Neuer Code lokal grün vor dem Commit. |
| `docs/dependency-audit.md` | Nachweis der Paketlegitimität | Braucht einen Nachtrag: PyJWT-Zeile mit 2.14.0 und dem Grund der Anhebung. Neue Pakete gibt es nicht zu prüfen, das ist der Punkt. |

## Installation

```bash
# pyproject.toml: eine Zeile ändern
#   "pyjwt[crypto]>=2.13,<3"  ->  "pyjwt[crypto]>=2.14,<3"

uv lock --upgrade-package pyjwt --upgrade-package cryptography
uv sync
uv run pytest -q
```

Kein `uv add`. Das ist das Ergebnis dieser Recherche in einer Zeile.

---

## Warum 2.14 keine Kür ist

PyJWT 2.14.0 (11.09.2026) ist eine Sicherheitsfreigabe. Fünf der Befunde liegen im JWKS-Pfad,
und drei davon treffen Code, den dieser Milestone schreibt oder bereits geerbt hat:

| Hinweis | Was er beschreibt | Warum er uns betrifft |
|---------|-------------------|-----------------------|
| `GHSA-2gx3-rcp4-g85q` | Ein unbekanntes `kid` im ungeprüften Header erzwingt je Anfrage einen JWKS-Abruf, auch gegen einen frischen Cache. Ein Angreifer ohne gültiges Token erzeugt damit eine Anfrage nach außen je Anfrage nach innen. Behoben in 2.14 mit einer Abkühlzeit von 30 Sekunden, mit Serialisierung gleichzeitiger Entscheidungen und mit `cooldown_duration` als Stellschraube. | **Das ist exakt das Verhalten unseres eigenen `OidcClient._key`**: `if not fresh or kid not in self._keys.keys: await self._refresh_keys(now)`. Im ID-Token-Pfad war das hinter einem Browser-Fluss versteckt, im Exchange-Pfad steht es an der Transportgrenze und nimmt Angreifereingaben bei jedem Werkzeugaufruf. Die Abkühlzeit muss also in unseren Code, nicht nur in die Bibliothek. |
| `GHSA-9v7f-9g4p-ffgj` | `PyJWKClient` folgte Umleitungen beim JWKS-Abruf, ein umgeleitetes Ziel galt als vertrauenswürdige Schlüsselquelle. Behoben in 2.14. | Unser Abrufweg macht es schon richtig (`follow_redirects=False`, Gleich-Origin-Prüfung gegen den Issuer). Der Hinweis belegt, dass diese Entscheidung kein Übermaß war, und er ist das stärkste Argument gegen `PyJWKClient` auf 2.13. |
| `GHSA-w6j9-cwv2-h6wq`, `GHSA-8wjv-2p76-3863` | Fehlerhafte JWK-Set-Einträge lassen `AttributeError`/`TypeError` entkommen, tief verschachtelte JWS/JWK-Eingaben erzeugen unbehandelte Rekursionsfehler. Behoben in 2.14: ein kaputter Eintrag wird übersprungen statt das ganze Set zu kippen. | Unser `_usable_key` fängt nur `jwt.PyJWTError` um `jwt.PyJWK(entry)`, und `jwt.get_unverified_header(token)` fängt ebenfalls nur `PyJWTError`. Auf 2.13 wird aus einem bösartigen Token oder einem kaputten JWKS-Eintrag damit eine unbehandelte Ausnahme an der Transportgrenze statt einer Abweisung. Das ist der Unterschied zwischen fail-closed und 500. |
| `GHSA-r6x4-923q-g947` und drei weitere | Härtung der HMAC-Schlüsselprüfung gegen Public-Key-Material als JWK, JWKS, Array, DER oder PEM. | Betrifft uns nur mittelbar, weil `HS*` in `_ALLOWED_ALGORITHMS` gar nicht vorkommt. Gratis-Tiefenverteidigung, falls jemand die Allowlist je aufweicht. |
| `GHSA-jq35-7prp-9v3f` (bereits in 2.13) | Die Allowlist `algorithms=[...]` war umgehbar, wenn mit einem `PyJWK`-Objekt dekodiert wurde: der Header-`alg` wurde geprüft, verifiziert wurde mit dem am Schlüssel gebundenen Verfahren. | Erklärt, warum unser Muster (rohes Schlüsselobjekt plus explizite Allowlist plus eigener Vergleich von JWKS-`alg` und Header-`alg`) beibehalten werden soll. Ab 2.13 wäre auch die Übergabe des `PyJWK` selbst sicher; wechseln muss man deshalb nicht. |

Kompatibilität: `mcp` 2.0.0 verlangt `pyjwt[crypto]>=2.10.1`, die Anhebung kollidiert also mit
nichts. 2.14.0 enthält keine für uns relevante Bruchstelle; die Umbauten am `JWKSetCache` stehen
im noch unveröffentlichten Abschnitt des Changelogs und betreffen ohnehin nur `PyJWKClient`.

---

## Die Architekturentscheidung, die der Stack nicht abnimmt: zwei Einbauorte

Die Bibliothek ist in beiden Fällen dieselbe. Der Ort entscheidet über die Kosten im heißen Pfad.

**Weg A, direkte Annahme an der Transportgrenze.** Das fremde Token ist der Bearer auf `/mcp`.
`verifier.py` bekommt einen zweiten Zweig: kein Store-Treffer, aber ein Token, dessen `iss` der
konfigurierte Exchange-Issuer ist, wird gegen das JWKS geprüft und auf ein Konto gemappt. Das ist
das, was der F13-Orchestrator erwartet, weil er das getauschte Token einfach weiterreicht. Preis:
eine Signaturprüfung je Werkzeugaufruf (RS256-Verifikation liegt im Bereich einiger Zehntel
Millisekunden, das ist tragbar) und ein Cache, der wie der vorhandene Fünf-Sekunden-Cache
funktionieren muss, aber nur bis `exp` reichen darf.

**Weg B, Assertion-Grant nach SEP-990.** Das fremde Token wird an unserem `/token` mit
`grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer` eingelöst; wir geben ein eigenes Token
aus, und der heiße Pfad bleibt Wort für Wort der heutige (Store, RFC-8707-Audience,
Sperrprüfung, Audit, Fünf-Sekunden-Cache). Das SDK trägt diesen Weg bereits:
`identity_assertion_enabled` in `AuthSettings`, `JwtBearerRequest` im Token-Handler,
`exchange_identity_assertion(client, params)` als Provider-Haken, Bewerbung in den
Metadaten, und der Handler weist öffentliche Clients vorher ab.

Empfehlung: **das JWKS- und Claim-Modul so bauen, dass es beide bedient** (eine Funktion "Token
zu geprüften Claims", ohne Wissen über Transport oder Store), **Weg A als Vorgabe umsetzen**,
weil er die Erwartung des Orchestrators trifft, und Weg B als Andockpunkt dokumentieren. Die vier
offenen F13-Entscheidungen ändern daran nichts; sie ändern nur Konfigurationswerte.

---

## Integrationspunkte im vorhandenen Code

| Datei | Was dort passiert | Was der Milestone anfasst |
|-------|-------------------|---------------------------|
| `oauth/oidc.py` (462 Zeilen) | Enthält bereits alles Schwierige: `_KeyCache`, `_refresh_keys`, `_usable_key`, `_ALLOWED_ALGORITHMS`, `_ALLOWED_KEY_TYPES`, `MAX_RESPONSE_BYTES`, `_LEEWAY_SECONDS = 60`, `JWKS_CACHE_SECONDS = 300`, eigener httpx-Client ohne Cookies und ohne Umleitungen. | Diese Teile in ein neues `oauth/jwks.py` herauslösen und von beiden Seiten nutzen. Kein Zweitschreiben: zwei JWKS-Implementierungen in einem Projekt sind zwei Stellen, an denen eine Abkühlzeit fehlen kann. Die Herauslösung ist reine Umstellung, kein Verhaltenswechsel, und die vorhandenen Tests (`tests/unit/test_oauth_oidc.py`) halten sie fest. |
| `oauth/verifier.py` | `StoreTokenVerifier.verify_token` (Store, Fünf-Sekunden-Cache, RFC-8707-Prüfung über `check_resource_allowed`, Sperrprüfung über `get_client`) und `resolve_identity` (liefert `OAuthIdentity`). | Der zweite Zweig gehört hierher, aber **nicht in dieselbe Methode**: ein eigener Verifier, der das `IdentitySource`-Protokoll erfüllt und dem `StoreTokenVerifier` vorgeschaltet oder nachgeschaltet wird, hält die heutige Methode unverändert und damit ihre Tests gültig. Die Audience-Prüfung dockt an derselben Stelle an (`check_resource_allowed(row.resource, self._resource)`), nur mit `aud` aus den Claims statt aus der Store-Zeile. |
| `oauth/principal.py` | Zentrale Identitätsregel: `principal_of` (Konto-Id, ersatzweise Anmeldename), `login_name_of` (was Basic-Auth braucht), `same_principal` (konstante Zeit). | Das Claim-Mapping endet hier und nirgends sonst. Der LDAP-Fall aus Entscheidung 2 der Spec-Note ist genau die Unterscheidung, die dieses Modul schon trennt. Kein neuer Identitätsbegriff. |
| `deps.py` / `OAuthIdentity` | Trägt `nc_user` **und** `app_password`; die Anmeldedaten kommen heute aus der Store-Zeile der Einwilligung. | **Die offene Frage mit der größten Wirkung, und sie ist keine Bibliotheksfrage:** ein über Exchange gemapptes Konto hat kein App-Passwort im Store. Entweder die Anmeldung läuft im ExApp-Modus über den AppAPI-Kanal (`exapp/auth.py`, Nutzerkennung im Header, Nextcloud prüft), oder der Exchange-Pfad setzt eine zuvor eingerichtete Verbindung desselben Kontos voraus, oder es braucht einen dritten Weg. Alle drei kosten kein Paket, aber sie gehören in ARCHITECTURE und in die Roadmap, nicht in den Stack. |
| `config.py` | `select_mode`, plus die `NC_MCP_OIDC_*`-Gruppe aus dem Standalone-OAuth. | Vorschlag für die neue Gruppe in derselben Schreibweise: `NC_MCP_EXCHANGE_ENABLED` (ab Werk aus, wie die Spec-Note zusagt), `NC_MCP_EXCHANGE_ISSUER`, `NC_MCP_EXCHANGE_AUDIENCE`, `NC_MCP_EXCHANGE_ACCOUNT_CLAIM`, `NC_MCP_EXCHANGE_ALGORITHMS`. Die vier F13-Entscheidungen sind damit Werte und kein Umbau. Der Schalter ist explizit und wird nicht aus dem Gesetztsein der anderen Werte geraten (D-27, keine stillen Rückfälle). |
| `audit/record.py` | Kette je Prinzipal (`u:<principal>`). | Der Exchange-Aufruf schreibt in die Kette des gemappten Prinzipals. Damit die Herkunft sichtbar bleibt, gehört die Zugangsart als Feld dazu. Kein neues Paket, eine Zeile mehr im Datensatz. |

---

## Alternatives Considered

| Recommended | Alternative | When to Use Alternative |
|-------------|-------------|-------------------------|
| Eigene asynchrone JWKS-Schicht auf PyJWT | `jwt.PyJWKClient` (in PyJWT enthalten, 2.14 mit `cooldown_duration`) | Nur in synchronem Code oder in einem Skript. In einem ASGI-Server müsste jeder Abruf über `anyio.to_thread.run_sync` laufen, weil `urllib.request.urlopen` blockiert; dazu fehlen ihm Gleich-Origin-Prüfung gegen den Issuer, Größenlimit auf der Antwort, Schlüsseltyp-Allowlist und die Behandlung eines doppelt vergebenen `kid`. Wir hätten also einen Thread-Pool-Umweg und trotzdem eine Hülle drumherum. Sein Nutzen für uns ist die Vorlage: 30 Sekunden Abkühlzeit, Serialisierung, Cache nie bei Fehlern leeren. |
| PyJWT | `joserfc` 1.7.5 (29.08.2026) | Wenn JWE, JWT-Verschlüsselung oder eine vollständige JOSE-Abdeckung gebraucht würde. Sauber gepflegte Bibliothek desselben Autors wie Authlib, aber sie bringt **keinen** HTTP-Abruf mit, das JWKS-Holen bliebe unser Code. Sie ersetzt also nur den Teil, den wir schon haben, und kostet ein neues Paket im Solo-Betrieb. |
| PyJWT | `Authlib` 1.8.0 (30.08.2026) | Wenn der Connector einen vollständigen OAuth-Autorisierungsserver von der Stange brauchte. Er hat seinen eigenen, an das MCP-SDK gebunden, seit v1.0 im Store. Authlib zöge eine zweite OAuth-Weltsicht in dasselbe Projekt. |
| PyJWT | `python-jose` 3.5.0 (28.05.2025) | Nie. Letzte Freigabe über ein Jahr alt, Geschichte mit Algorithmus-Confusion-Befunden, mehrere Krypto-Hinterlegungen. |
| PyJWT + `cryptography` | `jwcrypto` 1.6.1 | Nur wenn JWKS-Dokumente auch erzeugt werden müssten und `cryptography` dafür zu umständlich wäre. Für Testschlüssel reicht `cryptography`. |
| `respx` gegen ein nachgestelltes JWKS | Ein echter Keycloak im Test (Container) | Erst wenn der Realm-Export aus Entscheidung 3 vorliegt, und dann als optionaler Lauf hinter einem eigenen pytest-Marker wie `integration` und `matrix`. Kein Keycloak im Vorgabe-Testlauf: die Vorgabe startet heute bewusst nichts. |
| `httpx` `>=0.28,<0.29` | `httpx2` (transitiv über `mcp` vorhanden) | Nicht für eigenen Code, solange `respx` nur `httpx` mockt. Die Regel steht seit `docs/dependency-audit.md` und gilt unverändert. |

## What NOT to Use

| Avoid | Why | Use Instead |
|-------|-----|-------------|
| `PyJWKClient` im heißen Pfad | Synchron auf `urllib`; blockiert den Event-Loop bei jedem Abruf und bei jeder Zeitüberschreitung (Vorgabe 30 Sekunden) | Das herausgelöste asynchrone `oauth/jwks.py` auf `httpx` |
| Unbegrenzter Neuabruf bei unbekanntem `kid` | `GHSA-2gx3-rcp4-g85q`: eine Angreiferanfrage erzeugt einen Abruf nach außen, ohne dass ein gültiges Token nötig wäre. Unser geerbter Code tut genau das | Abkühlzeit von 30 Sekunden nach jedem erfolgreichen Abruf, `asyncio.Lock` als Single-Flight, kurzes Gedächtnis für kürzlich abgewiesene `kid` |
| `jku` oder `x5u` aus dem Token-Header lesen | Der Angreifer benennt damit die Schlüsselquelle. Auch PyJWT weist inzwischen Nicht-HTTP-Schemata in `PyJWKClient` ab, was zeigt, wohin dieser Weg führt | JWKS-Adresse ausschließlich aus Discovery des konfigurierten Issuers, Gleich-Origin geprüft, wie `oidc.py` es schon macht |
| `options={"verify_signature": False}` für irgendetwas außer dem Header | Ungeprüfte Claims dürfen nie eine Entscheidung tragen | `jwt.get_unverified_header` allein für `alg` und `kid`, alles andere erst nach `jwt.decode` |
| `verify_aud` ausschalten, weil Keycloak ab Werk `"aud": "account"` setzt | Damit fiele der RFC-8707-Schutz, der der Grund ist, warum es diesen Andockpunkt gibt: ein Token für einen anderen Dienst würde hier gelten | Audience-Konvention als Pflichtkonfiguration (`NC_MCP_EXCHANGE_AUDIENCE`), Abweisung bei Fehlen. Das ist F13-Entscheidung 1, und bis sie da ist, bleibt der Pfad aus |
| Ein Nextcloud- oder Keycloak-Admin-Client als Abhängigkeit | Für "existiert dieses Konto?" genügt der vorhandene OCS-Weg über `nextcloud/clients` | Vorhandene Nextcloud-Schicht |
| `requests`, `aiohttp`, ein zweiter HTTP-Stapel | Drei HTTP-Bibliotheken in einem Solo-Projekt | `httpx` |
| Stille Kontoanlage bei unbekanntem Claim | Die Spec-Note sagt Abweisung ausdrücklich zu, und eine Anlage wäre eine Rechtegrenze, die der Connector selbst zieht | Abweisung, im Audit als solche sichtbar |

---

## Fallstricke, die der Stack nicht abnimmt

1. **Algorithmus-Confusion.** `algorithms=[...]` immer explizit, `HS*` und `none` niemals in der
   Liste (`_ALLOWED_ALGORITHMS` in `oidc.py` erledigt das bereits), zusätzlich der vorhandene
   Vergleich zwischen dem im JWKS deklarierten `alg` und dem Header-`alg`. Keycloak signiert ab
   Werk mit RS256; die Konfiguration bleibt trotzdem eine Liste, kein fest verdrahteter Wert.
   Grundlage ist RFC 8725 (JWT Best Current Practices).
2. **`kid`-Behandlung.** Ein `kid` ist Pflicht (Keycloak setzt ihn immer). Ein `kid`, das im JWKS
   mehr als einmal vorkommt, macht dieses `kid` unbrauchbar, statt einen der Schlüssel zu wählen;
   diese Regel steht schon in `_refresh_keys` und muss die Herauslösung überleben.
3. **Cache-Verfallszeit und Rotation.** 300 Sekunden Cache plus Neuabruf bei unbekanntem `kid`
   ist das richtige Paar: Keycloak hält alte Schlüssel im JWKS, bis die damit ausgestellten Tokens
   abgelaufen sind, ein neues `kid` taucht also vor dem Cache-Ablauf auf. Mit Abkühlzeit heißt
   das: ein frisch rotierter Schlüssel kann bis zu 30 Sekunden warten. Das ist der bewusste Preis.
4. **fail-closed, aber nicht cache-löschend.** Ein nicht erreichbares JWKS führt zur Abweisung der
   Anfrage. Es darf aber nicht den zuletzt erfolgreich geholten Schlüsselsatz leeren. Genau diese
   Verwechslung war `GHSA-fhv5-28vv-h8m8` in PyJWT (ein `finally`-Block schrieb `None` in den
   Cache und machte aus einem Aussetzer einen Totalausfall). Unser Code holt heute nur bei Erfolg
   neu, und das muss so bleiben.
5. **Cross-JWT-Confusion.** Keycloak setzt `typ` an zwei Stellen mit verschiedenen Werten: im
   JOSE-Header `JWT`, im Claim-Satz `Bearer`. Ein ID-Token, ein Refresh-Token und ein Access-Token
   desselben Realms sind alle vom selben Schlüssel signiert. Ohne Prüfung der Tokenart nimmt der
   Exchange-Pfad ein ID-Token an, das nie dafür gedacht war. RFC 8725 Abschnitt 3.11 nennt das
   beim Namen; SEP-990 verlangt für den Assertion-Weg sogar ein eigenes `typ`
   (`oauth-id-jag+jwt`). Welche Prüfung greift, hängt an F13-Entscheidung 3 und gehört als
   Konfiguration vorbereitet.
6. **Clock-Skew.** 60 Sekunden Toleranz wie in `oidc.py` (`_LEEWAY_SECONDS`), auf `exp`, `nbf`
   und `iat`. `nbf` setzt Keycloak in der Regel nicht: die Prüfung muss "wenn vorhanden" lauten,
   nicht "erforderlich", sonst weist der Pfad korrekte Tokens ab. `iss` und `exp` dagegen sind
   Pflichtfelder in `options={"require": [...]}`.
7. **`sub` gegen `preferred_username`.** `sub` ist stabil und opak, `preferred_username` ist
   veränderlich und bei LDAP-gebundenen Instanzen nicht die interne Kennung. Das ist F13-
   Entscheidung 2 und die von der Spec-Note selbst benannte häufigste Fehlerquelle. Der Claim-Name
   bleibt deshalb konfigurierbar, und das Ergebnis läuft durch `principal.py`, nicht an ihm vorbei.
8. **Antwortgröße und Schlüsselzahl.** `MAX_RESPONSE_BYTES = 256 KiB` und `_MAX_KEYS = 20` stehen
   schon da. Ein fremder Issuer ist keine vertrauenswürdige Datenquelle, auch wenn er
   konfiguriert ist.

---

## Version Compatibility

| Package A | Compatible With | Notes |
|-----------|-----------------|-------|
| `pyjwt` 2.14.0 | `mcp` 2.0.0 (verlangt `pyjwt[crypto]>=2.10.1`) | Keine Kollision, die Anhebung der Untergrenze ist frei |
| `pyjwt` 2.14.0 | `cryptography` 50.x | Das `crypto`-Extra verlangt `cryptography`; 50.0.1 ist gegenüber 50.0.0 nur ein Wheel-Neubau (OpenSSL 4.0.2) |
| `httpx` 0.28.1 | `respx` 0.23.1 | Bestehendes Paar, Grund für den Verzicht auf `httpx2` in eigenem Code |
| `httpx2` (transitiv über `mcp`) | eigener Code | Bewusst nicht. Regel aus `docs/dependency-audit.md`, unverändert |
| Python 3.13 | alles oben | `pyjwt` verlangt `>=3.9`, `cryptography` `>=3.9`, keine Untergrenze in unsere Richtung |

---

## Sources

- PyPI JSON-API, abgefragt am 18.09.2026: `pyjwt` 2.14.0 (11.09.2026), `cryptography` 50.0.1
  (25.08.2026), `httpx` 0.28.1 (06.12.2024), `joserfc` 1.7.5 (29.08.2026), `authlib` 1.8.0
  (30.08.2026), `python-jose` 3.5.0 (28.05.2025), `jwcrypto` 1.6.1 (15.09.2026);
  `mcp` 2.0.0 `requires_dist` mit `pyjwt[crypto]>=2.10.1` und `httpx2>=2.5.0`. HIGH
- PyJWT-Changelog (`github.com/jpadilla/pyjwt`, `CHANGELOG.rst`, Stand 18.09.2026) und die
  Sicherheitshinweise `GHSA-2gx3-rcp4-g85q`, `GHSA-9v7f-9g4p-ffgj`, `GHSA-jq35-7prp-9v3f`,
  `GHSA-fhv5-28vv-h8m8`, `GHSA-8wjv-2p76-3863`. HIGH
- Quelltext `jwt/jwks_client.py` in zwei Fassungen gelesen: installiert 2.13.0 aus `.venv`,
  aktuell aus `master` (mit `cooldown_duration`, `_NoRedirectHandler`, `threading.RLock`). HIGH
- Quelltext dieses Projekts: `src/mcp_connector/oauth/oidc.py`, `verifier.py`, `principal.py`,
  `config.py`, `deps.py`, `docs/dependency-audit.md`, `pyproject.toml`, `uv.lock`. HIGH
- Quelltext MCP-SDK 2.0.0 aus `.venv`: `mcp/server/auth/handlers/token.py` (`JwtBearerRequest`,
  `identity_assertion_enabled`), `mcp/server/auth/provider.py` (`exchange_identity_assertion`
  mit den SEP-990-Verarbeitungsregeln), `mcp/server/auth/settings.py`, `mcp/server/auth/routes.py`,
  `mcp/client/auth/extensions/identity_assertion.py`. HIGH
- Keycloak: "Standard Token Exchange is now officially supported in Keycloak 26.2"
  (keycloak.org, 05/2025) und `keycloak.org/securing-apps/token-exchange` zu `audience`,
  `requested_token_type` und der Herkunft des `aud`-Claims. MEDIUM
- Keycloak-Token-Konventionen (`typ: Bearer` im Claim-Satz gegenüber `JWT` im JOSE-Header, `azp`
  statt `client_id`, `"aud": "account"` ab Werk, JWKS unter
  `/realms/{realm}/protocol/openid-connect/certs`, Rotation mit Weiterhalten alter Schlüssel):
  mehrere übereinstimmende Sekundärquellen, nicht gegen eine laufende Instanz geprüft. MEDIUM,
  aufzulösen mit dem Beispiel-Token und dem Realm-Export aus Entscheidung 3 der Spec-Note.
- RFC 8725 (JWT Best Current Practices) für Algorithmus-Allowlist und Cross-JWT-Confusion,
  RFC 8693 für den Tausch selbst, RFC 8707 für die Audience, die hier schon andockt. HIGH

---
*Stack research for: JWKS-Validierung fremder Keycloak-Tokens im Nextcloud MCP Connector*
*Researched: 2026-09-18*
