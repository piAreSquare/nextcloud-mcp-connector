# Architecture Research

**Domain:** Ein fünfter Identitätsweg in einer ausgelieferten MCP-ExApp: ein fremdes, nach RFC 8693 getauschtes Keycloak-JWT wird geprüft und auf ein Nextcloud-Konto abgebildet (v1.6 F13 Token Exchange Identity Mapper)
**Researched:** 2026-09-18
**Confidence:** HIGH für alle Aussagen über die eigene Codebasis (Datei und Zeile gelesen, nicht erinnert), HIGH für das Verhalten von `check_resource_allowed` im installierten MCP-SDK (Quellcode gelesen), HIGH für Keycloaks Standard Token Exchange V2 (offizielle Keycloak-Doku über Context7), MEDIUM für `occ user:auth-tokens:add` ohne Nutzerpasswort (Doku gelesen, nicht gemessen), MEDIUM für das Durchreichen eines fremden JWT durch HaRP (dieselbe Strecke trägt heute unsere opaken Tokens, die Größenordnung ist aber eine andere)

**Kernaussage in fünf Sätzen.** Der Exchange-Pfad braucht keinen sechsten Modus in `config.select_mode` und keine Änderung an `exapp/middleware.py`: die Transportgrenze nimmt bereits jedes Objekt, das dem Protokoll `IdentitySource` genügt (`oauth/verifier.py:152`), und die beiden Einbaustellen sind genau zwei Zeilen, `entry_exapp.py:113` und `entry_oauth.py:210`. Die richtige Bauform ist deshalb eine Prüferkette: erst der bestehende `StoreTokenVerifier` (lokaler SQLite-Treffer, fünf Sekunden Cache), und nur wenn der `None` sagt und der Exchange-Pfad eingeschaltet ist, der neue `ExchangeVerifier`; damit ist "die vier bestehenden Wege werden nicht angefasst" keine Disziplin, sondern Bauform, weil ein heute gültiges Token den neuen Prüfer nie erreicht. Die eigentliche Architekturfrage ist nicht die Token-Prüfung, sondern woher der gemappte Nutzer seine Nextcloud-Anmeldedaten bekommt, und dort stehen genau zwei tragfähige Wege gegeneinander: AppAPI-Impersonation mit `APP_SECRET` (nur im ExApp-Betrieb, kostet keine Provisionierung, macht aber die Signatur des fremden IdP zum Äquivalent des Instanz-Geheimnisses) gegen eine vorab gebundene Autorisierung mit eigenem App-Passwort je Konto (funktioniert in beiden Betriebsarten, kostet einen einmaligen Browser-Schritt je Nutzer, fügt aber keine einzige neue Vollmacht hinzu). Die Standalone-OAuth-Maschinerie aus PR #6 liefert dabei weniger, als die Spec-Note annimmt: `oidc.py` liefert JWKS-Abruf, Schlüsselrotation, Algorithmen-Allowlist und ID-Token-Prüfung als fertiges Muster, aber das App-Passwort kommt dort weiterhin aus Login Flow v2 im Browser (`oauth/consent.py:394-455`), also aus einem Weg, den ein Maschine-zu-Maschine-Aufruf konstruktionsbedingt nicht gehen kann. Und eine Korrektur an der Spec-Note, die vor dem zweiten Treffen bei F13 landen sollte: Keycloak unterstützt den `resource`-Parameter aus RFC 8693 laut eigener Doku noch nicht, die Audience eines getauschten Tokens ist eine Keycloak-Client-Id und keine Resource-URL, weshalb die RFC-8707-Prüfung in `verifier.py:246` zwar die richtige konzeptionelle Andockstelle, aber nicht die richtige Funktion ist.

---

## Teil 0: Die Randbedingungen, die dieser Meilenstein erbt

Alles aus dem Code gelesen. Diese acht Punkte entscheiden jede Bauentscheidung weiter unten mit.

| # | Randbedingung | Beleg |
|---|---------------|-------|
| R1 | Es gibt **fünf** Modi, nicht vier. `Mode` ist `stdio, exapp, oauth, http_passthrough, http_static_bearer`; `oauth` ist der Standalone-Betrieb aus PR #6 und wird über `NC_MCP_AUTH_MODE=oauth` ausdrücklich gewählt, nie geraten. | `config.py:87`, `config.py:231` (`select_mode`), `config.py:259` (`oauth_configured`) |
| R2 | Die Identität wird **einmal je Anfrage an der ASGI-Grenze** aufgelöst und in `request.state` abgelegt; der synchrone Credential-Layer liest nur noch. | `exapp/middleware.py:242` (`_deposit`), `deps.py:311` (`_oauth_identity`) |
| R3 | Die Transportgrenze nimmt **jeden** `TokenVerifier` und fragt per `isinstance(..., IdentitySource)`, ob er auch eine Identität liefern kann. Ein Prüfer ohne Identitätshälfte hinterlegt nichts, und der Credential-Layer verweigert dann von selbst. | `exapp/middleware.py:257-262`, `oauth/verifier.py:152-163` |
| R4 | Der Pausenschalter je Konto liest `identity.principal` aus demselben `request.state`. Wer dort eine Identität hinterlegt, ist automatisch vom Schalter erfasst. | `exapp/middleware.py:177-215` (`_switch_refusal`) |
| R5 | Das Audit-Log hängt an genau derselben Naht: `deps.resolve_caller` baut den `Caller` aus der hinterlegten `OAuthIdentity` (Principal, client_id, auth_id, client_name), `audit/record.py:236` schreibt daraus die Kette `u:<principal>`. Wer eine `OAuthIdentity` hinterlegt, ist ohne eine Zeile in `audit/` protokolliert. | `deps.py:139-183`, `audit/record.py:227-250`, `audit/store.py:185` (`user_chain`) |
| R6 | Es gibt ein etabliertes Muster für einen **reservierten Pseudo-Client**: `CONNECT_CLIENT_ID = "urn:mcp-connector:browser-onboarding"`, als `clients`-Zeile mit `allowed=False` angelegt, damit die Fremdschlüssel der `flows`- und `authorizations`-Tabelle greifen, ohne dass eine echte Registrierung existiert. | `oauth/connect.py:83`, `oauth/connect.py:213` |
| R7 | PyJWT ist **direkte** Abhängigkeit (`pyjwt[crypto]>=2.13,<3`) und wird heute in genau einer Datei benutzt: `oauth/oidc.py`. Die Spec-Note nennt an dieser Stelle `oauth/cimd.py`, das ist sachlich falsch und sollte vor dem Versand korrigiert werden. | `pyproject.toml:18`, `grep "import jwt" src/` = eine Fundstelle |
| R8 | Die SDK-Auth-Schicht ist in den relevanten Modi **nicht** beteiligt: `server/__init__.py:44` ruft `deps.build_auth()` einmal beim Import, und das liefert `(None, None)`, sobald kein statischer Bearer gesetzt ist. Im ExApp- und im Standalone-Betrieb prüft ausschließlich unsere Middleware. Es gibt also nur eine Stelle, an der ein zweiter Prüfer einzuhängen wäre, nicht zwei. | `server/__init__.py:44-59`, `deps.py:212` |

---

## Teil 1: Die bestehende Architektur, am Code nachvollzogen

### Die fünf Wege und ihre Anmeldedaten

| Modus | ausgelöst durch (`config.select_mode`) | Nextcloud-Anmeldedaten | Credential-Zweig |
|---|---|---|---|
| `stdio` | `headers is None` | Umgebung (`NC_MCP_USER`, `NC_MCP_APP_PASSWORD`) | `deps.py:105` |
| `exapp` | `APP_ID` und `APP_SECRET` gesetzt | Nutzerkennung aus `AUTHORIZATION-APP-API`, Geheimnis ist `APP_SECRET` | `deps.py:234` |
| `oauth` | `NC_MCP_AUTH_MODE=oauth` | App-Passwort aus der gespeicherten Autorisierung | `deps.py:270` |
| `http_static_bearer` | `NC_MCP_STATIC_BEARER` gesetzt | Umgebung, durch den Bearer geschützt | `deps.py:105` |
| `http_passthrough` | Rest | Basic-Anmeldedaten der Anfrage | `deps.py:339` |

Zwei Dinge daran sind für diesen Meilenstein entscheidend. Erstens: im `exapp`-Modus entscheidet die Nutzerkennung im signierten AppAPI-Header allein, welcher der zwei Kanäle gilt; ist sie leer, geht `_credentials_from_appapi` in `_credentials_from_oauth` (`deps.py:267`). Der Exchange-Pfad ist also ein Fall von "AppAPI-Handschlag gültig, Nutzerkennung leer", und damit genau der Zweig, den der OAuth-Bearer heute schon benutzt. Zweitens: `Credentials` kennt nur zwei Authentisierungsarten, `basic` und `appapi` (`nextcloud/credentials.py:18-20`). Ein dritter Wert wäre eine neue Authentisierungsart gegenüber Nextcloud, und die gibt es nicht; der Exchange-Pfad wird eine der beiden benutzen.

### Der heutige heiße Pfad, einmal durchgezeichnet (ExApp, OAuth-Zweig)

```
MCP-Client
    |  Authorization: Bearer <opakes Token dieses Servers>
    v
HaRP (signiert AUTHORIZATION-APP-API, Nutzerkennung leer, weil kein NC-Credential)
    v
RequireAppApi.__call__                         exapp/middleware.py:125
    |-- require_appapi(request)                exapp/auth.py:80      -> 401 ohne Hinweis
    |-- _bearer_is_valid(request)              exapp/middleware.py:221
    |     |-- StoreTokenVerifier.verify_token  oauth/verifier.py:217
    |     |     SHA-256-Digest -> 5-s-Prozesscache -> SQLite: access_tokens, authorizations
    |     |     RFC-8707-Audience: check_resource_allowed(row.resource, public_url + /mcp)
    |     |     AUTH-07: get_client(..., may_fetch=False)
    |     |     -> AccessToken(claims={auth_id, client_name})
    |     '-- _deposit                         exapp/middleware.py:242
    |           StoreTokenVerifier.resolve_identity  oauth/verifier.py:276
    |           laedt Autorisierung, entschluesselt App-Passwort (AES-GCM, aad=auth_id)
    |           -> request.state.oauth_identity = OAuthIdentity(...)
    |-- _switch_refusal                        exapp/middleware.py:177   -> 403 access_disabled
    |-- _deposit_recorder                      exapp/middleware.py:157
    v
MCP-Transport -> Tool -> deps.resolve_clients  deps.py:107
    |-- resolve_credentials -> _credentials_from_appapi (user leer) -> _credentials_from_oauth
    |     liest request.state.oauth_identity, baut Credentials(mode=basic)
    v
httpx -> Nextcloud (Basic: Login-Name + App-Passwort)
    |
    '-- graceful/finally -> audit.record.note -> deps.resolve_caller -> Kette u:<principal>
```

Kein Netzaufruf im heißen Pfad außer dem einen nach Nextcloud. Genau diese Eigenschaft muss der Exchange-Pfad erhalten, und er kann es, weil ein JWKS-Cache der einzige neue Fremdabruf ist und der nur bei unbekanntem `kid` anläuft.

### Was die Standalone-OAuth-Maschinerie aus PR #6 wirklich beisteuert

Die Spec-Note sagt, das gemergte Stück sei "die zweite Hälfte des Exchange-Pfads". Das stimmt für die Prüfmechanik und stimmt nicht für die Anmeldedaten.

**Wiederverwendbar, fertig und erprobt (`oauth/oidc.py`, 462 Zeilen):**

- JWKS-Abruf mit Cache (`JWKS_CACHE_SECONDS = 300`), höchstens ein Nachladen je Aufruf bei unbekanntem `kid` (`oidc.py:316` `_key`, `oidc.py:333` `_refresh_keys`)
- Schlüssel-Hygiene: nur `RSA/EC/OKP`, nie `oct`, `use`/`key_ops` müssen Verifikation erlauben, ein doppelt vergebener `kid` macht den `kid` unbrauchbar statt einen der beiden zu wählen (`oidc.py:388` `_usable_key`)
- Algorithmen-Allowlist rein asymmetrisch, `HS*` und `none` sind nie erlaubt (`oidc.py:66`)
- Claim-Prüfung über PyJWT mit `issuer`, `audience`, `leeway=60`, `options={"require": [...]}` (`oidc.py:281-292`)
- Eigener HTTP-Client für die fremde Vertrauensdomäne: kein gemeinsamer Pool mit dem Nextcloud-Pfad, keine Redirects, keine Cookies, Antwortgröße begrenzt (`oidc.py:353-380`)
- Eine benannte Mapping-Strategie mit Versionssuffix statt eines fest verdrahteten Claim-Namens (`oidc.py:160` `user_oidc_unique_uid_sub_v1`, `oidc.py:310` `account_id_for`)

**Nicht wiederverwendbar:** der Weg zum App-Passwort. Im Standalone-Betrieb kommt es weiterhin aus Nextclouds Login Flow v2, gepollt in `oauth/consent.py:394`, und wird erst nach `loginflow.account(...)` unter der kanonischen Konto-Id gespeichert (`consent.py:438` -> `store.create_authorization`, `store.py:772`). Der OIDC-Teil aus PR #6 beweist ausschließlich, **welcher Browser** die Zustimmung erteilt (`oauth/oidc_identity.py:36` `identifies`, gestützt auf `store.redeem_browser_proof`, `store.py:1785`). Er erzeugt keine Anmeldedaten. Ein Maschine-zu-Maschine-Aufruf hat weder Browser noch Cookie und kann diesen Weg nicht gehen.

---

## Teil 2: Wo der Exchange-Pfad andockt

### E1: Kein sechster Modus, sondern ein zweiter Prüfer in einer Kette

`select_mode` bleibt unverändert. Begründung aus dem Code, nicht aus Geschmack:

1. Ein sechster Modus müsste sich aus Umgebung **und Anfrage** entscheiden, denn dieselbe Instanz muss weiter gewöhnliche OAuth-Clients bedienen (Claude.ai) und zusätzlich F13-Aufrufe annehmen. `select_mode` ist aber eine reine Funktion aus Umgebung plus Header und kennt bewusst keine "es kommt drauf an, was im Bearer steht"-Verzweigung. Ein Modus je Token wäre genau der stille Fallback, den `deps.py:33-36` und `entry_oauth.load_settings` ausdrücklich verbieten.
2. Der Credential-Layer braucht keinen neuen Zweig, solange der Exchange-Pfad eine `OAuthIdentity` hinterlegt: `_credentials_from_oauth` liest nur `request.state` (R2).
3. Die Transportgrenze ist bereits auf genau diese Erweiterung ausgelegt (R3): Parameter statt Import, Protokoll statt Basisklasse.

**Bauform:** ein neues, kleines Kompositum `ChainedVerifier` (oder `verifier.chain(...)`), das selbst `verify_token` und `resolve_identity` implementiert und beides an seine Glieder delegiert.

```python
# neu, oauth/verifier.py oder oauth/exchange.py
class ChainedVerifier:
    """Erst der Store, dann der Exchange. Reihenfolge ist die Sicherheit."""

    async def verify_token(self, token: str) -> AccessToken | None:
        access = await self._store_verifier.verify_token(token)   # lokal, 5-s-Cache
        if access is not None or self._exchange is None:
            return access
        return await self._exchange.verify_token(token)           # nur wenn eingeschaltet

    async def resolve_identity(self, access: AccessToken) -> OAuthIdentity | None:
        if access.claims and access.claims.get(EXCHANGE_CLAIM):
            return await self._exchange.resolve_identity(access)
        return await self._store_verifier.resolve_identity(access)
```

Vier Eigenschaften, die diese Reihenfolge trägt:

- Ein heute gültiges Token trifft den neuen Prüfer **nie**, weil der Store zuerst antwortet. Das ist die Garantie "die vier bestehenden Wege werden nicht angefasst" als Bauform statt als Vorsatz.
- Ist der Exchange-Pfad aus (Werkszustand), ist `self._exchange is None` und die Kette ist verhaltensgleich mit dem heutigen Prüfer. Ein Test, der das behauptet, ist billig zu schreiben.
- Die Weiche in `resolve_identity` läuft über einen eigenen Claim im `AccessToken` und nicht über Zustand zwischen den zwei Aufrufen. Das SDK-Modell bietet `claims` genau dafür an, und `AUTH_ID_CLAIM`/`CLIENT_NAME_CLAIM` (`verifier.py:88`, `:96`) sind der Präzedenzfall.
- `provider.on_revocation(verifier.invalidate)` (`entry_exapp.py:117`) muss die Kette treffen, nicht nur das erste Glied. Also bekommt die Kette ein `invalidate()`, das beide Caches leert. Das ist eine Zeile und eine Testzeile.

**Genaue Einbaustellen:**

| Datei | Zeile heute | Änderung |
|---|---|---|
| `entry_exapp.py` | 113 `verifier = StoreTokenVerifier(...)` | `verifier = chain(StoreTokenVerifier(...), exchange_verifier_or_none(env, store))` |
| `entry_exapp.py` | 117 `provider.on_revocation(verifier.invalidate)` | unverändert, wenn die Kette `invalidate` anbietet |
| `entry_oauth.py` | 210 / 212 | dieselbe Zeile, dieselbe Änderung |
| `exapp/middleware.py` | keine | keine. Das ist das Ziel. |
| `config.py` `select_mode` | keine | keine. Nur neue `ENV_*`-Konstanten plus ein `exchange_settings(env)`-Leser am Ende der Datei, in der Form der schon vorhandenen Leser (`audit_log_enabled` bei `config.py:554`). |

### E2: Die Audience dockt am richtigen Ort, aber nicht an der richtigen Funktion an

Die Spec-Note sagt: "Der Platz, an dem eure Audience-Konvention andockt, existiert also schon" und meint die RFC-8707-Prüfung in `verifier.py:246`. Konzeptionell richtig, mechanisch nicht übertragbar, und das ist eine belegbare Korrektur:

- Die vorhandene Prüfung ist `check_resource_allowed(requested, configured)` aus dem SDK. Der Quellcode (`.venv/Lib/site-packages/mcp/shared/auth_utils.py`) macht **URL-Vergleich**: Schema und Netloc müssen gleich sein, der Pfad muss ein Präfix sein. Für zwei Werte ohne Schema und Host degeneriert das zu einem Pfad-Präfix-Vergleich auf beliebigen Zeichenketten, also zu einer Regel, die niemand beabsichtigt hat.
- Keycloak stellt bei Standard Token Exchange V2 die Audience aus dem `audience`-Parameter, und der nimmt **Client-Ids**, keine Resource-URLs. Die Keycloak-Doku sagt zum `resource`-Parameter nach RFC 8693 wörtlich "Not supported yet" (Vergleichstabelle V2 gegen V1 in `docs/guides/securing-apps/token-exchange.adoc`). Ein herabgestuftes Token trägt dann `"aud": ["target-client2"]` und `"azp": "requester-client"`.

**Folge für den Bau:** eigener Vergleich, kein Aufruf von `check_resource_allowed`. Die Audience des Exchange-Pfads ist eine konfigurierte Zeichenkette (oder eine kleine Liste), verglichen in konstanter Zeit auf UTF-8-Bytes, so wie `principal.same_principal` es vormacht (`oauth/principal.py:88`). `aud` kann laut JWT-Spezifikation Zeichenkette oder Liste sein, beides muss behandelt werden; PyJWT nimmt `audience=` und prüft das selbst korrekt, das ist der billigste Weg.

**Folge für das zweite Treffen mit F13 (Entscheidung 1 der Spec-Note):** die Frage "fester Bezeichner, Basis-URL oder Wert aus der `tenant.yml`" hat damit eine Vorzugsantwort. Empfehlung an F13: eine Keycloak-Client-Id je Connector-Instanz, stabil und sprechend, zum Beispiel `nextcloud-mcp-<instanz>`. Unsere Konfiguration heißt `NC_MCP_EXCHANGE_AUDIENCE` und nimmt genau diesen Wert; der dokumentierte Default ist die Resource-URL dieser Instanz (`public_url + /mcp`), damit die Konfiguration auch dann noch passt, wenn Keycloak den `resource`-Parameter eines Tages nachreicht. Zusätzlich empfehlenswert: ein optionales `NC_MCP_EXCHANGE_AZP` (welcher Requester-Client darf tauschen), weil `azp` der einzige Claim ist, der den Orchestrator von jedem anderen Client desselben Realms unterscheidet.

---

## Teil 3: Die Kernfrage: woher kommen die Nextcloud-Anmeldedaten für ein gemapptes Konto

Das ist die eine Frage, die dieser Meilenstein entscheiden muss, und sie ist **noch nicht entschieden**. Die Spec-Note umgeht sie, weil sie annimmt, die Standalone-Maschinerie löse sie mit. Sie löst sie nicht (Teil 1, letzter Abschnitt). Es gibt drei Wege, zwei davon tragen.

### Weg A: AppAPI-Impersonation (nur ExApp-Betrieb)

Der Container besitzt `APP_SECRET` und kann jedes Konto der Instanz ansprechen, indem er `AUTHORIZATION-APP-API: base64("<user>:<APP_SECRET>")` setzt (`nextcloud/credentials.py:96` `appapi_auth_headers`). Genau das tut der AUTH-01-Pfad heute für den Nutzer, den HaRP benannt hat. Der Exchange-Pfad würde denselben Mechanismus benutzen, nur dass der Name aus dem geprüften JWT kommt statt aus dem HaRP-Header.

- **Kosten:** null Provisionierung. Kein App-Passwort, kein Browser-Schritt, kein neues Geheimnis im Container. Ein neuer Nutzer in Keycloak funktioniert sofort.
- **Preis:** die Signatur des fremden IdP wird zum funktionalen Äquivalent von `APP_SECRET`. Wer ein Token für `aud=<unsere Audience>` ausstellen kann, handelt als jedes Konto der Instanz. Die Fähigkeit ist nicht neu (der Container hat sie seit v1.0), neu ist, dass eine **zweite Partei** bestimmen darf, welches Konto gemeint ist.
- **Code-Fläche:** `OAuthIdentity` bekommt ein Feld mit Default (`credential: str = CREDENTIAL_APP_PASSWORD`), damit kein bestehender Konstruktionsort bricht; `deps._credentials_from_appapi` reicht seine `settings` an `_credentials_from_oauth` weiter, das einen zweiten Zweig bekommt, der `Credentials(mode=MODE_APPAPI, user=..., secret=settings.app_secret, ...)` baut. Zwei kleine, gut testbare Änderungen an `deps.py`.
- **Notwendige Gegengewichte, alle lokal und billig:** ab Werk aus; exakter Audience-Vergleich; Issuer fest konfiguriert; nur asymmetrische Algorithmen; **eine Konten-Allowlist oder eine Gruppenbindung**, damit ein kompromittierter IdP nicht sofort den Administrator bedeutet; der Pausenschalter gilt automatisch (R4); Audit-Zeile je Aufruf (R5).
- **Was Weg A nicht braucht:** eine Existenzprüfung des Kontos im heißen Pfad. Ein nicht existierender Nutzer führt zu einem 401 von Nextcloud selbst, also fail-closed ohne Netzaufruf von uns. Die Forderung "Abweisung statt stiller Anlage" ist damit erfüllt, weil wir ohnehin kein Konto anlegen können.

### Weg B: Vorab gebundene Autorisierung mit eigenem App-Passwort (beide Betriebsarten)

Je Konto existiert genau eine gespeicherte Autorisierung unter einem reservierten Pseudo-Client (Muster R6, zum Beispiel `urn:mcp-connector:token-exchange`). Der Exchange-Pfad bildet das Token auf einen Principal ab und sucht diese eine Zeile; findet er keine, ist der Aufruf abgewiesen.

- **Kosten:** ein einmaliger Browser-Schritt je Nutzer (Login Flow v2), also Provisionierung.
- **Preis:** keine neue Vollmacht. Der Connector kann danach genau das, was er vorher konnte, und jede Bindung ist in Nextcloud unter "Geräte und Sitzungen" sichtbar und widerrufbar, dazu auf unserer Verbindungsseite (`oauth/connections.py:336` listet über `store.authorizations_of_user(principal)`).
- **Code-Fläche:** ein neuer Store-Lesezugriff (`binding_of(principal, client_id)`, eine SELECT-Zeile; `authorizations_of_user` bei `store.py:941` fragt bereits `COALESCE(nc_account_id, nc_user) = ? AND revoked_at IS NULL`, es fehlt nur der Client-Filter, kein Schema-Wechsel) plus eine Provisionierungs-Route, die im Wesentlichen `oauth/connect.py` ist, nur dass sie speichert statt anzeigt.
- **Geschenkt dazu:** `resolve_identity` muss gar nicht neu geschrieben werden. Trägt der `ExchangeVerifier` in `verify_token` den `AUTH_ID_CLAIM` der gefundenen Bindung ein, kann die Kette die bestehende `StoreTokenVerifier.resolve_identity` (`verifier.py:276`) unverändert benutzen: Entschlüsselung, Widerrufsblick und Maskierung inklusive. Das ist der eleganteste Teil des ganzen Entwurfs.
- **Der offene Betriebspunkt:** wie kommen 500 Konten einer Landesinstanz zu ihrer Bindung. `occ user:auth-tokens:add <uid>` (früher `user:add-app-password`) existiert und kann ein App-Passwort erzeugen, aber das Ergebnis müsste anschließend in unseren Store gelangen, wofür es heute keinen Weg gibt und für den ein Klartext-App-Passwort durch eine Konfiguration wandern würde. Das ist schlechter als der Browser-Schritt. MEDIUM confidence, nicht gemessen.

### Weg C: Dienstkonto oder gemeinsames Konto

Ausdrücklich verworfen. Das ist genau der Zustand, den die Spec-Note als heutigen Notbehelf beschreibt und den der Meilenstein ablösen soll, und er bricht das Kernversprechen ("der Assistent sieht nie mehr als der angemeldete Nutzer").

### Empfehlung und die Entscheidung, die der Owner treffen muss

| Kriterium | Weg A (Impersonation) | Weg B (gebundene Autorisierung) |
|---|---|---|
| Betriebsarten | nur `exapp` | `exapp` und `oauth` |
| Provisionierung je Nutzer | keine | einmalig im Browser |
| Neue Vollmacht | ja: IdP-Signatur wirkt wie `APP_SECRET` | keine |
| Sichtbar und widerrufbar für den Nutzer | nein (nur Pausenschalter) | ja, an zwei Stellen |
| Code-Fläche | `deps.py` plus ein Feld an `OAuthIdentity` | Store-Lesezugriff plus Provisionierungs-Route |
| Passt zur F13-Erzählung "Identität kommt vom IdP" | vollständig | teilweise (Konto bleibt vorab gebunden) |
| Aufwand bis zum ersten echten Durchstich | klein | mittel bis groß |

**Empfehlung:** Weg A als Ziel, Weg B als Rückfallebene für den Standalone-Betrieb, und beide teilen rund achtzig Prozent des Codes (JWKS, Claims, Mapping, Audience, Konfiguration, Kette, Audit). Die Reihenfolge ist deshalb nicht "erst A oder erst B", sondern: erst der gemeinsame Teil, dann die eine Zeile, die den Credential-Weg wählt. Wer zuerst gebaut wird, kann bis unmittelbar vor dieser Phase offenbleiben.

**Was der Owner entscheiden muss, in einem Satz:** Darf die Signatur eines fremden Identity Providers in einer Instanz, die diesen Schalter einschaltet, so wirken wie das Instanz-Geheimnis der ExApp, abgesichert durch Audience, Issuer, Konten-Allowlist, Pausenschalter und Audit-Kette? Ein Ja ist Weg A und macht F13 sofort betriebsfähig. Ein Nein ist Weg B und kostet je Nutzer einen Browser-Schritt.

**Was F13 dazu beitragen muss:** Entscheidung 2 der Spec-Note (Konto-Claim) wird bei Weg A härter, nicht weicher. Bei Weg B fängt eine falsche Abbildung damit auf, dass keine Bindung gefunden wird; bei Weg A landet eine falsche Abbildung auf einem existierenden Konto. Der LDAP-Fall (Anmeldename ungleich interner Kennung) ist damit kein Randfall, sondern die Kernfrage des Testfalls, den wir aus ihrem Beispiel-Token bauen.

---

## Teil 4: Neue und geänderte Komponenten, explizit getrennt

### Neu

| Komponente | Datei | Verantwortung | Bemerkung |
|---|---|---|---|
| Exchange-Prüfer | `oauth/exchange.py` | `verify_token` für ein fremdes JWT: Issuer, Signatur, Standard-Claims, Audience, Mapping, Ergebnis als `AccessToken` mit Claims | implementiert `IdentitySource` nur dann vollständig, wenn Weg A gebaut wird |
| Prüferkette | `oauth/verifier.py` (Ergänzung) oder `oauth/chain.py` | Reihenfolge Store vor Exchange, Weiche in `resolve_identity`, gemeinsames `invalidate()` | ~60 Zeilen, der Rest ist Delegation |
| JWKS-Client | `oauth/jwks.py` | Abruf, Cache mit Verfallszeit, Rotation, fail-closed | **Alternative prüfen:** der Kern steht bereits in `oidc.py:316-386`. Empfehlung: `_KeyCache`, `_usable_key`, `_refresh_keys` und den gehärteten `_request` aus `oidc.py` in ein `oauth/jwks.py` herausziehen und `OidcClient` darauf umstellen, statt eine zweite Implementierung danebenzulegen. Das ist eine Umstellung ohne Verhaltensänderung, mit vorhandenen Tests abgesichert, und sie verhindert genau die Sorte Doppelpflege, die später eine Sicherheitslücke in nur einer der zwei Kopien schließt. |
| Mapping-Konfiguration | `oauth/exchange.py` oder `oauth/mapping.py` | benannte Strategien Claim -> Principal, in der Form von `STRATEGY_USER_OIDC_UNIQUE_UID_SUB_V1` | mindestens drei Strategien, siehe Teil 5 |
| Reservierter Client | Konstante neben `CONNECT_CLIENT_ID` | `urn:mcp-connector:token-exchange`, `allowed=False` | nur bei Weg B nötig, bei Weg A nützlich als Audit-Kennzeichen |
| Bindungs-Lesezugriff | `oauth/store.py` (neue Methode) | eine Autorisierung je Principal und reserviertem Client | nur Weg B, kein Schema-Wechsel |
| Provisionierungs-Route | `oauth/exchange_enroll.py` | Login Flow v2 -> `create_authorization` unter dem reservierten Client | nur Weg B, ~`connect.py` mit Speichern statt Anzeigen |
| Doku | `docs/token-exchange.md` | Variablen, Keycloak-Seite, Betriebsregeln, die vier F13-Entscheidungen als benannte Andockpunkte | am Muster von `docs/standalone-oauth.md` |

### Geändert

| Komponente | Datei:Funktion | Änderung | Risiko |
|---|---|---|---|
| Konfiguration | `config.py` (Ende der Datei) | neue `ENV_EXCHANGE_*`-Konstanten, `exchange_configured(env)`, `exchange_settings(env)` | niedrig. `select_mode` wird **nicht** angefasst. |
| ExApp-Aufbau | `entry_exapp.py:113` | Kette statt einzelnem Prüfer | niedrig, eine Zeile plus Fabrik |
| Standalone-Aufbau | `entry_oauth.py:210` | dieselbe | niedrig |
| Identitätsobjekt | `oauth/verifier.py:112` `OAuthIdentity` | nur bei Weg A: ein Feld mit Default (`credential`), `__repr__` zieht mit | niedrig, Default hält alle Konstruktionsorte |
| Credential-Layer | `deps.py:234` und `deps.py:270` | nur bei Weg A: `settings` durchreichen, zweiter Zweig für Impersonation | mittel. Das ist die Stelle, an der ein Fehler zur falschen Identität führt. Zwei-Konten-Negativbeweis als Integrationstest, nach dem Muster von `tests/integration/test_permission_fidelity_exapp.py`. |
| OIDC-Client | `oauth/oidc.py` | nur bei der empfohlenen Herauslösung: benutzt `oauth/jwks.py` statt eigener Kopie | niedrig, verhaltensgleich, durch bestehende Unit-Tests abgesichert |
| Doku-Bestand | `README*.md`, `docs/faq.md` | ein Satz, dass der Weg existiert und ab Werk aus ist | niedrig, aber Pflicht (Wahrheitsregel des Projekts) |

### Ausdrücklich unverändert

`exapp/middleware.py`, `config.select_mode`, `server/__init__.py`, `audit/record.py`, `audit/store.py`, alle 21 Werkzeuge, das Schema-Budget (kein neues Werkzeug), das Store-Schema (bei Weg A gar nicht, bei Weg B nur um eine Abfrage erweitert).

---

## Teil 5: Datenflüsse, was sich ändert und was nicht

### Neuer Pfad, Weg A (Impersonation)

```
F13-Orchestrator
    |  1. Keycloak: RFC-8693-Tausch, audience=<unsere Audience>
    |  2. POST /mcp, Authorization: Bearer <JWT>
    v
HaRP (signiert AUTHORIZATION-APP-API, Nutzerkennung leer)
    v
RequireAppApi.__call__                      exapp/middleware.py:125   UNVERAENDERT
    |-- _bearer_is_valid -> ChainedVerifier.verify_token              NEU
    |     |-- StoreTokenVerifier.verify_token -> None (kein Store-Treffer)
    |     '-- ExchangeVerifier.verify_token                            NEU
    |           a) ungepruefter Header: alg in Allowlist, kid vorhanden
    |           b) ungepruefter iss == konfigurierter Issuer, sonst sofort None
    |              (verhindert, dass ein fremdes JWT einen JWKS-Abruf ausloest)
    |           c) Schluessel aus dem JWKS-Cache, hoechstens ein Nachladen
    |           d) jwt.decode(issuer=, audience=, leeway=60, require=[iss,exp,aud,sub])
    |           e) Mapping-Strategie: Claim -> Principal
    |           f) optionale Konten-Allowlist
    |           -> AccessToken(claims={EXCHANGE_CLAIM, subject, client_name})
    |-- _deposit -> ChainedVerifier.resolve_identity -> ExchangeVerifier
    |     -> request.state.oauth_identity = OAuthIdentity(
    |            nc_user=<gemappt>, principal=<gemappt>, app_password="",
    |            credential=CREDENTIAL_IMPERSONATE, client_id="urn:...:token-exchange")
    |-- _switch_refusal                     exapp/middleware.py:177   WIRKT AUTOMATISCH
    |-- _deposit_recorder                                             UNVERAENDERT
    v
Tool -> deps.resolve_credentials -> _credentials_from_appapi (user leer)
    -> _credentials_from_oauth: credential == impersonate             NEUER ZWEIG
    -> Credentials(mode=appapi, user=<gemappt>, secret=APP_SECRET)
    v
httpx -> Nextcloud (AppAPI-Header, Rechtepruefung findet in Nextcloud statt)
    |
    '-- audit.record.note -> Kette u:<gemappter principal>            WIRKT AUTOMATISCH
```

### Neuer Pfad, Weg B (gebundene Autorisierung)

Identisch bis Schritt (f). Danach: `store.binding_of(principal, EXCHANGE_CLIENT_ID)`; keine Zeile bedeutet Abweisung mit 401; eine Zeile liefert `auth_id`, das als `AUTH_ID_CLAIM` in den `AccessToken` wandert. `resolve_identity` bleibt die vorhandene Store-Implementierung, der Credential-Zweig in `deps.py` bleibt unverändert, und der Aufruf geht mit Basic und dem gebundenen App-Passwort nach Nextcloud.

### Was sich am heißen Pfad messbar ändert

| Größe | heute | mit Exchange (Weg A) | mit Exchange (Weg B) |
|---|---|---|---|
| Nextcloud-Abrufe je Werkzeugaufruf | 1 | 1 | 1 |
| Lokale SQLite-Lesezugriffe | 1 bis 2 (Cache-Miss) | 0 bis 1 (Pausenschalter) | 2 bis 3 |
| Fremd-Netzabrufe | 0 | 0, außer bei unbekanntem `kid` (JWKS) | dito |
| Kryptooperationen | HMAC-Vergleich | eine Signaturprüfung je Cache-Miss | dito |

Die Signaturprüfung ist der einzige neue CPU-Posten und der Grund, warum der Exchange-Prüfer einen eigenen kurzen Positiv-Cache braucht: dieselbe Fensterlogik wie `VALIDATION_CACHE_TTL` (`store.py:180`, fünf Sekunden), zusätzlich gedeckelt auf `exp - now`, mit demselben harten Obergrenzen-Verhalten wie `CACHE_LIMIT` (`verifier.py:106`: bei Erreichen leeren statt klug kürzen).

---

## Teil 6: Das Mapping, und warum der LDAP-Fall die eigentliche Arbeit ist

Drei Namen, die in diesem Projekt schon streng auseinandergehalten werden (`oauth/principal.py`, Moduldokumentation): **Anmeldename** (`nc_user`, das was Basic-Auth braucht), **Principal** (`nc_account_id`, kanonische Konto-Id, Grundlage von Pausenschalter, Besitz und Audit-Kette) und **Anzeigename** (nur zum Lesen). Ein Claim-Mapping muss sagen, **welchen der drei** es trifft.

Empfohlene benannte Strategien, alle mit Versionssuffix nach dem Muster `user_oidc_unique_uid_sub_v1`:

| Strategie | Claim | Ergebnis | Wann richtig |
|---|---|---|---|
| `login_name_v1` | konfigurierbar, typisch `preferred_username` | Anmeldename | Instanz ohne LDAP, Keycloak spiegelt die Nextcloud-Anmeldenamen |
| `account_id_v1` | konfigurierbar, typisch ein eigener Claim | Principal direkt | wenn F13 die kanonische Kennung im Token führen kann, der sauberste Fall |
| `user_oidc_unique_uid_sub_v1` | `sub` | Principal, abgeleitet als SHA-256 von `"<provider_id>_0_<sub>"` | Instanz, die Nutzer über `user_oidc` mit "unique user id" führt. **Code existiert bereits** (`oidc.py:160`) und ist im Standalone-Betrieb erprobt |
| (bewusst nicht gebaut) | `email` | - | brauchte eine Suche in Nextcloud im heißen Pfad; wenn überhaupt, dann nur zur Bindungszeit in Weg B |

Zwei Regeln, die aus dem Bestand folgen und in die Umsetzung gehören:

1. **Bei Weg A muss die Strategie den Anmeldenamen liefern**, denn der AppAPI-Header nimmt die Nutzerkennung, mit der Nextcloud das Konto auflöst. Der Principal für Pausenschalter und Audit ist derselbe Wert, solange keine kanonische Id bekannt ist; das entspricht genau dem Legacy-Zweig, den `principal_of` (`principal.py:69`) für ExApp-Zeilen ohne Konto-Id schon kennt. Wer den Principal sauber haben will, muss ihn einmal auflösen und das kostet einen Nextcloud-Abruf, also Bindungszeit statt Aufrufzeit. **Das ist ein echter Zielkonflikt und gehört als Entscheidung in die Phase, nicht in den Code.**
2. **Bei Weg B liefert die Strategie den Principal**, weil die Bindung genau danach gesucht wird und die Zeile den Anmeldenamen ohnehin mitbringt.

Der Testfall aus Entscheidung 3 der Spec-Note (Beispiel-Token plus Realm-Export) gehört als anonymisierte Fixture nach `tests/fixtures/` und als Unit-Test gegen jede Strategie ins Repo, öffentlich, wie in Abschnitt 7 der Note zugesagt. Bis er da ist, wird gegen selbst erzeugte Schlüssel und selbst gebaute Tokens getestet; das prüft die Mechanik, nicht die Struktur.

---

## Teil 7: Der Audit-Anschluss kostet fast nichts

Die Spec-Note verspricht: "ein über Exchange handelnder Aufruf ist genauso nachvollziehbar wie jeder andere". Aus R5 folgt, dass dieses Versprechen ohne eine Zeile in `audit/` erfüllt ist, sofern die hinterlegte Identität eine echte `OAuthIdentity` ist (`deps._oauth_identity` prüft `isinstance`, `deps.py:324`). Dann gilt automatisch:

- Kette `u:<principal>` (`audit/store.py:185`), also dieselbe Kette, in die AppAPI-Aufrufe desselben Kontos schreiben
- `client_id` in der Zeile: der reservierte Bezeichner, damit ein Prüfer Exchange-Aufrufe von Claude-Aufrufen unterscheiden kann, ohne dass ein neues Feld nötig wäre
- `client_name`: sinnvoll der `azp` aus dem Token, gereinigt und gekappt, denn `audit/record.py:131` schickt jeden Namen durch `printable(...)`
- `auth_id`: bei Weg B die Bindungs-Zeile, bei Weg A leer oder ein stabiler Bezeichner des Exchange-Pfads

Eine Sache fehlt und sollte bewusst entschieden werden: **abgewiesene** Exchange-Versuche stehen nirgends. `audit/record.py:227` schreibt nur nach einem Werkzeugaufruf, und ein 401 an der Transportgrenze erreicht den Recorder nie (er wird erst nach den drei Prüfungen hinterlegt, `middleware.py:157`). Für einen Behörden-Betrieb ist "ein fremdes Token wurde abgewiesen" aber oft die interessantere Zeile als der erfolgreiche Aufruf. Das ist eine Erweiterung der Audit-Kette um eine Zeilenart (nach dem Muster `KIND_SWITCH`), kein Umbau, und es gehört als eigener, kleiner Punkt in die Roadmap, nicht in die Exchange-Phase selbst.

---

## Teil 8: Empfohlene Baureihenfolge mit Abhängigkeiten

```
P1 JWKS-Herauslösung        (unabhaengig, keine Verhaltensaenderung)
        |
        v
P2 Exchange-Prüfer, rein    (haengt an P1; kein Wiring, kein Store, reine Funktionen)
        |
        +--> P3 Konfiguration + Schalter   (haengt an P2 fuer die Feldnamen)
        |
        v
P4 Kette + Einbau in beide Entry-Points    (haengt an P2, P3)
        |
        v
P5 Credential-Weg  A oder B                (haengt an P4; OWNER-ENTSCHEIDUNG)
        |
        v
P6 Nachweis, Doku, Haertung                (haengt an P5)
```

| Phase | Inhalt | Warum an dieser Stelle | Abhängig von |
|---|---|---|---|
| **P1** | `oauth/jwks.py` aus `oidc.py` herauslösen, `OidcClient` darauf umstellen | Ohne diesen Schritt entstehen zwei JWKS-Implementierungen in einem Repo, und die zweite erbt die Härtungen der ersten nicht. Verhaltensgleich, durch bestehende Unit-Tests gedeckt, deshalb zuerst und billig. | - |
| **P2** | Signatur- und Claim-Prüfung, Audience-Vergleich, Mapping-Strategien, alles als freistehende, testbare Funktionen ohne Server | Das sind die "entscheidungsunabhängigen Teile" aus Abschnitt 3 der Spec-Note. Sie lassen sich vollständig gegen selbst erzeugte Schlüssel testen, also ohne F13. | P1 |
| **P3** | `ENV_EXCHANGE_*`, `exchange_settings`, fail-closed bei halber Konfiguration, ab Werk aus | Muss vor dem Einbau stehen, damit der Einbau den Aus-Zustand als Normalfall bauen kann statt ihn nachzurüsten. | P2 |
| **P4** | Kette, `invalidate()`, zwei Zeilen in den Entry-Points, plus ein Test, der beweist, dass der Aus-Zustand verhaltensgleich mit heute ist | Ab hier ist der Pfad im Prozess vorhanden und weist alles ab, weil noch kein Credential-Weg existiert. Das ist ein guter, sicherer Zwischenstand. | P2, P3 |
| **P5** | Der Credential-Weg. Weg A: `OAuthIdentity`-Feld plus `deps.py`-Zweig plus Konten-Allowlist plus Zwei-Konten-Negativbeweis. Weg B: Store-Lesezugriff plus Provisionierungs-Route plus Sichtbarkeit auf der Verbindungsseite. | Erst hier wird der Pfad betriebsfähig, und erst hier fällt die Vollmacht-Entscheidung an. Alles davor ist ohne sie baubar, genau wie die Spec-Note es zusagt. | P4, Owner-Entscheidung |
| **P6** | `docs/token-exchange.md`, README-Sätze, Integrationstest gegen eine echte Keycloak-Instanz (die `nextcloud-docker-dev`-Topologie bringt Keycloak mit, siehe STACK-Notiz im CLAUDE.md), Rate-Limit-Verhalten des JWKS-Abrufs, Header-Größe messen | Nachweise brauchen den fertigen Pfad. Der Keycloak-Container ist die Stelle, an der die Annahmen über `aud` und `azp` zum ersten Mal echt werden. | P5 |

**Was zwischen P2 und P5 an F13 hängt und was nicht.** Nichts aus P1 bis P4 braucht eine der vier F13-Entscheidungen. Audience-Konvention und Konto-Claim werden Konfigurationswerte mit dokumentierten Defaults, das Beispiel-Token wird eine Test-Fixture, und der Exchange-Ziel-Eintrag auf F13-Seite ist reine Betriebsdoku. Genau das war die Zusage der Spec-Note, und die Architektur hält sie ein.

---

## Teil 9: Anti-Muster, die hier konkret drohen

**A1: Den Exchange-Pfad in `select_mode` einbauen.**
Was daran falsch ist: der Modus wäre dann prozessweit, also entweder Exchange oder gewöhnliches OAuth, und eine Instanz könnte nicht beides bedienen. Ein Modus, der pro Anfrage aus dem Bearer entschieden wird, ist definitionsgemäß der stille Fallback, den `deps.py:33` verbietet.
Stattdessen: Kette hinter der Transportgrenze, ein Modus wie bisher.

**A2: `check_resource_allowed` für die Exchange-Audience wiederverwenden.**
Was daran falsch ist: die Funktion vergleicht URLs hierarchisch (SDK-Quellcode gelesen). Mit Keycloak-Client-Ids degeneriert sie zu einem Präfix-Vergleich auf Zeichenketten, und `mcp/unter` würde gegen `mcp` passen.
Stattdessen: exakter Vergleich in konstanter Zeit gegen eine konfigurierte Allowlist, `aud` als Zeichenkette und als Liste behandelt.

**A3: Bei unbekanntem Token sofort den JWKS-Satz nachladen.**
Was daran falsch ist: jeder Fremde könnte mit einem selbst gebauten JWT einen ausgehenden Abruf auslösen. Der bestehende `_key` (`oidc.py:316`) lädt höchstens einmal je Aufruf nach, aber er lebt hinter einem ratenbegrenzten Browser-Callback; der Exchange-Prüfer sitzt im unauthentisierten heißen Pfad.
Stattdessen: erst den ungeprüften `iss` gegen die Konfiguration halten, dann eine Mindestzeit zwischen zwei Nachladeversuchen erzwingen, und einen unerreichbaren Schlüsselsatz als Abweisung behandeln, nie als Durchlass.

**A4: Ein zweites `OAuthIdentity`-ähnliches Objekt einführen.**
Was daran falsch ist: `deps._oauth_identity` prüft `isinstance(identity, OAuthIdentity)` (`deps.py:324`) und `resolve_caller` baut den Audit-`Caller` daraus. Ein eigenes Objekt hieße, beide Stellen zu ändern, und die Audit-Kette eines Exchange-Aufrufs wäre stillschweigend leer statt falsch, also unbemerkt.
Stattdessen: dieselbe Klasse, höchstens um ein Feld mit Default erweitert.

**A5: Die Identität ins Werkzeug durchreichen.**
Was daran falsch ist: kein Werkzeug hat einen Nutzerparameter, und das ist die Kernabwehr gegen den confused deputy (T-01-12, im Moduldokument von `deps.py`). Ein Exchange-Pfad, der einen Nutzer als Werkzeugparameter nähme, wäre ein anderes Produkt.
Stattdessen: alles an der Transportgrenze, wie heute.

**A6: Die Store-Prüfung überspringen, wenn das Token wie ein JWT aussieht.**
Was daran falsch ist: die Reihenfolge Store-zuerst ist die Garantie dafür, dass bestehende Tokens den neuen Code nie erreichen. Eine Vorsortierung nach Tokenform gäbe diese Garantie auf, um einen lokalen SQLite-Lesezugriff zu sparen, den der Fünf-Sekunden-Cache ohnehin meistens erspart.
Stattdessen: immer Store zuerst, Exchange nur bei `None`.

---

## Teil 10: Integrationspunkte, tabellarisch

### Nach außen

| Gegenstelle | Muster | Fallstricke |
|---|---|---|
| Keycloak (F13) | JWKS unter `<issuer>/protocol/openid-connect/certs`, Discovery unter `<issuer>/.well-known/openid-configuration`; wir sind reiner Resource Server und rufen nur den Schlüsselsatz ab | `resource`-Parameter nach RFC 8693 wird von Keycloak noch nicht unterstützt; `aud` ist eine Client-Id, `azp` der tauschende Client; Realm-Rotation ändert `kid`, deshalb Cache mit Verfallszeit und fail-closed |
| HaRP / AppAPI | unverändert; `/mcp` ist PUBLIC, der 401 kommt von uns | Ein Keycloak-Zugriffstoken ist typischerweise ein bis vier Kilobyte groß, unsere heutigen Tokens sind kurz. Header-Obergrenzen von HaRP und jedem Reverse Proxy davor **einmal messen**, bevor jemand behauptet, der Weg trage. |
| Nextcloud | unverändert. Weg A benutzt den vorhandenen AppAPI-Header-Weg, Weg B den vorhandenen Basic-Weg. | Kein neuer Aufruf, keine neue Route, keine neue Berechtigung |

### Nach innen

| Grenze | Kommunikation | Anmerkung |
|---|---|---|
| `entry_*` -> Prüferkette | Konstruktorparameter | die zwei einzigen Zeilen, die der Einbau ändert |
| Kette -> Transportgrenze | `TokenVerifier` plus `IdentitySource` (Protokolle) | `middleware.py` bleibt unangetastet |
| Transportgrenze -> Credential-Layer | `request.state.oauth_identity` (`OAUTH_STATE_ATTR`) | eine Konstante, zwei Seiten, keine dritte |
| Transportgrenze -> Audit | `request.state.audit_recorder` (`AUDIT_STATE_ATTR`) | wirkt automatisch mit |
| Exchange -> Store | nur bei Weg B, ein Lesezugriff | keine Schreiboperation im heißen Pfad |
| `oauth/exchange.py` -> `oauth/jwks.py` | Funktionsaufruf | die einzige neue Abhängigkeit innerhalb des Pakets; `exchange.py` darf nichts aus `exapp/` importieren (die Schichtregel aus `audit/record.py`) |

---

## Teil 11: Offene Punkte, ehrlich benannt

1. **Die Credential-Entscheidung (Weg A oder Weg B)** ist nicht getroffen und kann nicht von der Recherche getroffen werden: sie ist eine Vollmachtsfrage, keine technische. Teil 3 legt beide Wege mit Preis und Kosten vor.
2. **Principal gegen Anmeldename bei Weg A**: ob der Exchange-Pfad die kanonische Konto-Id einmal auflöst (ein Nextcloud-Abruf zur Bindungs- oder Erstaufrufzeit, saubere Audit-Kette) oder beim Anmeldenamen bleibt (kein Abruf, Legacy-Zweig von `principal_of`), ist offen.
3. **Header-Größe über HaRP** mit einem echten Keycloak-Token: nicht gemessen. Vor dem ersten Durchstich messen.
4. **Abgewiesene Exchange-Versuche im Audit-Log**: heute konstruktionsbedingt unsichtbar. Eigener kleiner Punkt für die Roadmap.
5. **`occ user:auth-tokens:add` ohne Nutzerpasswort**: Doku gelesen, Verhalten nicht gemessen. Nur relevant, falls Weg B eine skriptbare Provisionierung bekommen soll.
6. **Die vier F13-Entscheidungen** bleiben Konfiguration mit dokumentierten Defaults; für Entscheidung 1 liegt mit Teil 2 jetzt eine begründete Vorzugsantwort vor, die vor dem zweiten Treffen in die Spec-Note gehört, zusammen mit der Korrektur `cimd.py` zu `oidc.py`.

---

## Sources

**Eigene Codebasis (HIGH, gelesen am 2026-09-18):** `src/mcp_connector/config.py`, `oauth/verifier.py`, `oauth/store.py`, `oauth/oidc.py`, `oauth/oidc_identity.py`, `oauth/consent.py`, `oauth/connect.py`, `oauth/principal.py`, `oauth/loginflow.py`, `exapp/middleware.py`, `exapp/auth.py`, `deps.py`, `nextcloud/credentials.py`, `audit/__init__.py`, `audit/record.py`, `audit/store.py`, `entry_exapp.py`, `entry_oauth.py`, `server/__init__.py`, `pyproject.toml`, `docs/standalone-oauth.md`, `tests/contract/test_module_boundaries.py`

**MCP-SDK (HIGH, installiertes Paket gelesen):** `.venv/Lib/site-packages/mcp/shared/auth_utils.py`, `check_resource_allowed`

**Keycloak (HIGH, offizielle Doku über Context7, `/keycloak/keycloak`):** `docs/guides/securing-apps/token-exchange.adoc` (Standard Token Exchange V2 nach RFC 8693, Verhalten des `audience`-Parameters, `resource`-Parameter "Not supported yet", Beispiel eines herabgestuften Tokens mit `azp` und `aud`), `docs/documentation/server_admin/topics/clients/oidc/con-audience.adoc`

**Nextcloud (MEDIUM, Doku, nicht gemessen):** [occ-Handbuch](https://docs.nextcloud.com/server/stable/admin_manual/occ_command.html), [Nutzer- und Gruppenbefehle](https://docs.nextcloud.com/server/stable/admin_manual/occ_users.html) zu `user:auth-tokens:add` als Nachfolger von `user:add-app-password`

**Projektkontext:** `.planning/PROJECT.md`, `C:\Users\Student\Desktop\F13-Spec-Note-Identity-Mapper-2026-09-16.md` (Stand 18.09.)

---
*Architecture research for: F13 Token Exchange Identity Mapper (v1.6)*
*Researched: 2026-09-18*
