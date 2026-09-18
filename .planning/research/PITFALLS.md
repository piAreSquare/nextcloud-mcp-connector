# Pitfalls Research

**Domain:** Einem bestehenden OAuth-Resource-Server (eigener Mini-AS, lokale Tokenprüfung gegen einen SQLite-Store, strikter Berechtigungs-Durchgriff, Audit-Kette) die Annahme fremder, nach RFC 8693 getauschter IdP-Tokens beibringen (v1.6 "F13 Token Exchange Identity Mapper")
**Researched:** 2026-09-18
**Confidence:** HIGH für alles, was den Code-Stand dieses Repos betrifft (`oauth/verifier.py`, `oauth/oidc.py`, `oauth/principal.py`, `oauth/throttle.py`, `oauth/store.py`, `exapp/middleware.py`, `deps.py`, `audit/store.py`, `audit/accounts.py`, `config.py` direkt gelesen). HIGH für das Verhalten von PyJWT 2.13.0 (installierte Quelle `jwt/api_jwt.py`, `jwt/algorithms.py` gelesen) und für `check_resource_allowed` (installierte Quelle `mcp/shared/auth_utils.py` gelesen). MEDIUM-HIGH für Keycloaks Standard Token Exchange (offizielle Keycloak-Doku und Keycloak-Blog, nicht gegen eine Instanz gemessen). MEDIUM für die Nextcloud-Seite des Konto-Mappings (Doku, Issues, Community-Threads, nicht gemessen; genau das ist Entscheidung 2 und Punkt 3 der Spec-Note). LOW für alles, was von F13s vier Antworten abhängt: das ist hier bewusst als Entscheidungsfläche markiert und nicht als Befund.

Diese Datei ist gegen den Code nach Release 0.2.1 geschrieben, also nach dem Merge der
Standalone-OAuth-Maschinerie (PR #6, DaniW42). Jedes "Wie vermeiden" nennt die Stelle, an die
die Änderung gehört, weil ein Pitfall ohne Adresse eine Warnung ist und kein Plan.

## Die Ein-Absatz-Fassung

Der Connector hat heute genau einen Tokenbegriff: ein Token ist ein 256-Bit-Zufallswert, den
dieser Server selbst ausgegeben hat, und die Prüfung ist ein indizierter Lookup in der eigenen
SQLite-Datei ohne einen einzigen Netzaufruf (`oauth/verifier.py`, Modul-Docstring, D-34/D-37).
Der Exchange-Pfad bricht drei Annahmen dieser Konstruktion auf einmal: die Signatur kommt von
einem fremden Schlüssel, die Identität kommt aus einem Claim statt aus einer Zeile, die dieser
Server selbst geschrieben hat, und im heißen Pfad jedes Werkzeugaufrufs kann plötzlich ein
ausgehender HTTPS-Abruf stehen. Genau daran hängen die gefährlichen Fehler, und sie sind fast
alle Integrationsfehler und keine Kryptofehler: PyJWT 2.13 wehrt die Lehrbuch-Angriffe (alg
none, PEM als HMAC-Secret) von sich aus ab, und `oauth/oidc.py` enthält bereits eine
vorbildliche JWKS-Prüfung. Die Löcher entstehen daneben. Erstens an der Nahtstelle: wenn der
fremde Prüfer als Rückfallebene in `StoreTokenVerifier.verify_token` gehängt wird statt als
zweiter, per Form eindeutig ausgewählter Pfad. Zweitens an der Audience: `check_resource_allowed`
aus dem SDK ist eine Präfixprüfung über URL-Pfade und keine exakte Gleichheit, und PyJWTs
`aud`-Prüfung ist ohne `strict_aud` ein "irgendeines von mehreren passt". Drittens am Konto:
der Wert, den dieses Projekt für jede Identitätsentscheidung benutzt, ist der kanonische
Account-Id (`oauth/principal.py`), nicht der Anmeldename und erst recht nicht ein Claim; wer
hier den Anmeldenamen einsetzt, hebelt den Pausenschalter aus und spaltet die Audit-Kette,
ohne dass irgendein Test rot wird. Viertens am Credential: ein getauschtes Token beweist eine
Identität, liefert aber kein Nextcloud-Geheimnis, und `OAuthIdentity` braucht eines; wer diese
Frage nicht vor dem ersten Code beantwortet, landet automatisch bei Impersonation über ein
Dienstkonto, also bei genau dem Durchgriff, den dieses Projekt in v1.5 für OpenProject
ausgeschlossen hat. Fünftens an der Last: `oauth/throttle.py` nimmt die MCP-Route absichtlich
vom Limit aus, mit der Begründung, ein Tool-Aufruf werde aus dem Prozess-Cache beantwortet.
Diese Begründung stimmt ab dem Exchange-Pfad nicht mehr.

---

## Critical Pitfalls

### Pitfall 1: Der fremde Prüfer wird zur Rückfallebene des eigenen

**What goes wrong:**
`StoreTokenVerifier.verify_token` bekommt am Ende ein "und wenn der Store nichts kennt, probier
es als JWT". Damit entsteht eine Kette statt einer Entscheidung. Drei Folgen: jedes unbekannte
Bearer-Token läuft jetzt erst durch einen Store-Lookup und danach durch Signaturprüfung samt
möglichem JWKS-Abruf (siehe Pitfall 5), die einheitliche Ablehnung wird zur Aussage über den
inneren Ablauf (Timing: Store-Treffer ist schnell, JWT-Pfad ist langsam), und `OAuthIdentity`
hat zwei Erzeuger mit unterschiedlichen Wahrheiten über `auth_id`, `client_id` und
`app_password`. Der eigentliche Schaden kommt später: `resolve_identity` prüft heute
`AUTH_ID_CLAIM` und antwortet `None`, wenn er fehlt ("ein Token eines anderen Prüfers, nichts
hier darf darauf handeln"). Ein Exchange-Pfad, der sich einen `auth_id`-Wert ausdenkt, um durch
diese Tür zu kommen, macht die Aussage des Docstrings falsch, ohne sie zu ändern.

**Why it happens:**
Es ist die kleinste Änderung. Der Verifier ist bereits an der Transportgrenze verdrahtet
(`exapp/middleware.py:_bearer_is_valid`), das Request-State-Protokoll steht, und ein `if row is
None:` gibt es schon. Ein zweiter Verifier bedeutet dagegen, `entry_exapp`/`entry_oauth`,
Middleware-Verdrahtung und Tests anzufassen.

**How to avoid:**
Zwei Prüfer, ein Dispatcher, und die Auswahl fällt **vor** jeder Prüfung anhand einer
strukturellen, nicht geheimen Eigenschaft. Diese Eigenschaft ist hier eindeutig und nachprüfbar:
eigene Access-Tokens sind `secrets.token_urlsafe(TOKEN_BYTES)` (`oauth/provider.py:976`), also
aus dem Alphabet `A-Za-z0-9-_` und **ohne Punkt**; ein kompaktes JWS hat genau zwei Punkte und
einen dekodierbaren Header. Regel: kein Punkt bedeutet Store-Pfad und nur Store-Pfad; zwei
Punkte bedeuten Exchange-Pfad und nur Exchange-Pfad, und nur wenn der Exchange-Pfad konfiguriert
ist; alles andere ist sofort `None`. Kein `try/except`, kein `or`, kein zweiter Versuch nach
einem Fehlschlag. Das ist dieselbe Regel, die `deps.py` bereits als D-27 führt ("kein Fallback
in beide Richtungen"), nur an einer neuen Stelle. Der Exchange-Pfad erzeugt seine eigene
Identitätsstruktur und benutzt `AUTH_ID_CLAIM` nur dann, wenn er tatsächlich eine Zeile dieses
Servers meint (siehe Pitfall 8).

**Warning signs:**
Ein Diff, der `verify_token` verlängert, statt eine Datei hinzuzufügen. Ein Test, der nur
"gültiges Exchange-Token funktioniert" prüft und keinen, der "eigenes Token darf den fremden
Pfad nie erreichen und umgekehrt" prüft. Ein `auth_id`, das im Exchange-Pfad aus einem Claim
gebaut wird.

**Phase to address:**
P2 (Andocken an die Transportgrenze), und zwar vor P3 (Mapping): die Weiche entscheidet, wie
alles darunter aussieht.

---

### Pitfall 2: Die Audience wird mit `check_resource_allowed` geprüft, das ist eine Präfixprüfung

**What goes wrong:**
Die Spec-Note sagt zu Recht, der Platz für die Audience-Konvention existiere schon (RFC 8707,
`oauth/verifier.py`). Der Platz existiert, aber die dort benutzte Funktion hat eine Semantik,
die für eigene Tokens richtig und für fremde falsch ist. `mcp.shared.auth_utils.check_resource_allowed`
vergleicht Schema und Host exakt und den **Pfad als Präfix** ("hierarchical matching"): ein
Token mit `aud = https://nc.example/mcp/tenant-b` besteht die Prüfung gegen die konfigurierte
Ressource `https://nc.example/mcp`. Wenn F13 den Mandanten in den Audience-Pfad schreibt, was
bei Entscheidung 1 der Spec-Note eine der naheliegenden Antworten ist, dann trennt diese Prüfung
die Mandanten nicht, sondern sie fasst sie zusammen. Der zweite Teil desselben Fehlers steckt in
PyJWT: `jwt.decode(..., audience=[...])` ohne `strict_aud` besteht, sobald **irgendeine** der
übergebenen Audiences in der `aud`-Liste des Tokens vorkommt, und Keycloak-Tokens tragen
regelmäßig mehrere Einträge (klassisch `account` neben dem Ziel). Eine großzügig konfigurierte
Liste wird so zur Oder-Verknüpfung.

**Why it happens:**
Beides sieht nach "ist schon gelöst" aus. Die SDK-Funktion steht bereits im Verifier, PyJWT
nimmt ein `audience`-Argument entgegen, und ein Test mit genau einer Audience ist grün.

**How to avoid:**
Für den fremden Pfad exakte Zeichenkettengleichheit gegen einen je Issuer konfigurierten
Audience-Wert, nicht `check_resource_allowed`. In PyJWT `options={"strict_aud": True}` setzen,
solange F13 eine einzelne Audience ausstellt: `strict_aud` verlangt, dass beide Seiten
einzelne Zeichenketten sind und exakt gleich (verifiziert in `jwt/api_jwt.py:_validate_aud`).
Ist eine Mehrfach-Audience unvermeidbar, dann exakte Mitgliedschaftsprüfung gegen genau einen
erwarteten Wert plus eine Allowlist auf `azp`. Zusätzlich `options={"require": ["iss", "sub",
"aud", "exp", "iat"]}`, weil PyJWT ohne `require` ein fehlendes `nbf` oder `iat` klaglos
durchlässt. Und: den fremden Audience-Wert nicht in `AccessToken.resource` schreiben, wo die
RFC-8707-Prüfung des eigenen Pfads ihn wiederfindet; das sind zwei Begriffe mit einem Namen.
Empfehlung für Entscheidung 1 gegenüber F13: die Audience ist instanzspezifisch und leitet sich
aus `config.public_url` plus `RESOURCE_SUFFIX` ab, also genau der Wert, den dieser Server für
seine eigenen Tokens schon benutzt. Eine generische Audience wie `nextcloud` macht ein Token
für Instanz A an Instanz B gültig.

**Warning signs:**
`check_resource_allowed` im neuen Code. Ein `audience=`-Argument, das aus einer per Komma
getrennten Umgebungsvariablen gebaut wird. Kein Test mit einem Token, dessen `aud` ein
Unterpfad der konfigurierten Ressource ist.

**Phase to address:**
P1 (fremder Tokenprüfer), Gegenprobe in P6 mit dem Beispiel-Token aus Entscheidung 3.

---

### Pitfall 3: Ein JWKS-Cache für mehrere Issuer, und eine `kid` gilt plötzlich überall

**What goes wrong:**
Mehr-Issuer-Betrieb wird gebaut, indem `OidcSettings.issuer` zu einer Liste wird oder indem ein
gemeinsamer Cache `kid -> key` entsteht. Damit kann ein Schlüssel von Issuer A die Signatur
eines Tokens prüfen, das `iss = B` behauptet. `kid` ist ein frei gewählter Bezeichner ohne
Eindeutigkeitsgarantie über Aussteller hinweg; zwei Keycloak-Realms können dieselbe `kid`
tragen. Die zweite Variante desselben Fehlers: die `jwks_uri` oder der Discovery-Aufruf wird aus
dem **ungeprüften** `iss` des Tokens abgeleitet. Dann bestimmt der Angreifer, welchen Server
dieser Connector fragt, und "Vertrauen bei der ersten Begegnung" wird zur Architektur. `oauth/oidc.py`
verhindert das heute mit zwei Regeln, die man beim Kopieren leicht verliert: der Issuer ist
Administratorkonfiguration, und `_same_origin` verbietet jeden Abruf, der die Issuer-Herkunft
verlässt.

**Why it happens:**
"Multi-Issuer" klingt nach einer Schleife über eine Liste. Und der bestehende Client ist so
sauber geschrieben, dass er wie die natürliche Erweiterungsstelle wirkt: eine Einladung, aus
einem konfigurierten Provider mehrere zu machen.

**How to avoid:**
Eine geschlossene Registry: ein Dictionary, dessen Schlüssel der exakte Issuer-String aus der
Konfiguration ist und dessen Wert eine eigene Client-Instanz mit eigenem Schlüssel-Cache ist.
Der ungeprüfte `iss` aus dem Token dient ausschließlich als **Nachschlagewert in dieser
Registry**, niemals als Eingabe für eine URL. Ist er nicht enthalten, endet die Prüfung sofort.
Danach wird mit `issuer=<genau diesem konfigurierten Issuer>` dekodiert, sodass der signierte
`iss` gegen den Vertrauensanker laufen muss, aus dem der Schlüssel kam. Trailing-Slash-Regel und
`_require_https_origin` aus `oauth/oidc.py` übernehmen, nicht neu erfinden. Für v1.6 ist ein
einziger konfigurierbarer Issuer der ehrlichere Zuschnitt; die Registry kostet dann fast nichts
und verhindert, dass der zweite Issuer später als Liste angeflanscht wird.

**Warning signs:**
`issuer: tuple[str, ...]` in einer Settings-Klasse. Ein Cache, dessen Schlüssel nur die `kid`
ist. Ein `httpx`-Aufruf, dessen URL irgendwo aus `claims["iss"]` stammt. Ein deaktiviertes
`_same_origin`, weil "unser Keycloak steht hinter einem anderen Hostnamen".

**Phase to address:**
P1.

---

### Pitfall 4: Der Algorithmus wird dem Token entnommen

**What goes wrong:**
Beim Nachbauen der Prüfung entsteht `jwt.decode(token, key, algorithms=[header["alg"]])`. Damit
bestimmt der Absender, welches Verfahren geprüft wird. PyJWT 2.13 fängt die zwei bekanntesten
Fälle noch ab: `alg: none` verlangt `key is None` und ist ohne `"none"` in der Liste gar nicht
erreichbar, und `HMACAlgorithm.prepare_key` verweigert ausdrücklich PEM-, SSH- und JWK-JSON-
förmige Schlüssel als HMAC-Secret ("Defense against algorithm-confusion attacks", verifiziert in
`jwt/algorithms.py:325`). Was bleibt, ist das, was der Bibliothek egal ist: ein JWKS-Eintrag mit
`kty: oct` wäre ein echtes Symmetrisches, und ein Schlüssel mit `use: enc` ist kein
Signaturschlüssel. Dazu die stille Variante: `alg` im Header sagt RS256, der gefundene
JWKS-Eintrag deklariert ES256, und wer beides nicht gegeneinander prüft, akzeptiert eine
Verwechslung, die ein Aussteller gar nicht vorgesehen hat.

**Why it happens:**
Man braucht `header["alg"]`, um überhaupt den passenden Schlüssel auszuwählen, und von dort ist
es ein Zeichen bis in das `algorithms`-Argument.

**How to avoid:**
Den Block aus `oauth/oidc.py` wiederverwenden statt nachbauen: `_ALLOWED_ALGORITHMS` (nur
asymmetrisch), `_ALLOWED_KEY_TYPES` ohne `oct`, `_usable_key` mit `use`/`key_ops`-Prüfung, die
Ablehnung doppelter `kid`, und die zwei Zeilen, die der Kern sind: `header["alg"]` muss in den
**konfigurierten** Algorithmen enthalten sein, und ein im JWKS deklariertes `alg` muss zum
Header passen. Wenn der Code geteilt wird, dann als gemeinsames Modul und nicht als Copy; wenn
er kopiert wird, dann mit einem Test je Regel im neuen Pfad. Default wie gehabt `RS256`,
konfigurierbar, und niemals eine Konfiguration, die HS\* zulässt.

**Warning signs:**
`algorithms=` bekommt einen Wert, der aus dem Token stammt. `jwt.decode` mit
`options={"verify_signature": False}` irgendwo außerhalb einer reinen Header-Inspektion.
Ein neues `_ALLOWED_KEY_TYPES` ohne die `oct`-Ausnahme.

**Phase to address:**
P1.

---

### Pitfall 5: Ein unbekanntes `kid` wird zum Verstärker, und die MCP-Route ist absichtlich ungedrosselt

**What goes wrong:**
`oauth/oidc.py:_key` holt bei unbekannter `kid` einmal den Schlüsselsatz nach. Das ist die
richtige Antwort auf Schlüsselrotation und im Browserfluss harmlos, weil dort erst ein
state- und nonce-gebundener Consent vorausgegangen ist. Im Exchange-Pfad steht dieselbe Logik
hinter einem anonymen Bearer: jede Anfrage mit zufälliger `kid` kostet einen ausgehenden
HTTPS-Abruf gegen Keycloak plus JSON-Parsing, bezahlt von einem Angreifer mit einem
HTTP-Request. Das ist eine Verstärkung gegen den fremden IdP und gegen den eigenen Prozess
zugleich, und sie ist vor-authentisch erreichbar. Verschärfend kommt eine Annahme dieses Repos
ins Rutschen: `oauth/throttle.py` nimmt die MCP-Route ausdrücklich vom Limit aus, mit der
Begründung, ein Tool-Aufruf komme mit geprüftem Bearer und werde aus dem Prozess-Cache des
Verifiers beantwortet. Ab dem Exchange-Pfad stimmt das nicht mehr: dort steht RSA-Prüfung und
womöglich Netzverkehr vor jeder Identität. Dazu ein zweiter Effekt ohne Angreifer: ein langsamer
IdP hängt seine Latenz an jeden Werkzeugaufruf, und ohne Single-Flight laufen bei
Cache-Ablauf alle gleichzeitigen Anfragen zusammen in denselben Abruf.

**Why it happens:**
Der bestehende Code funktioniert und wird deshalb übernommen. Der Unterschied liegt nicht im
Code, sondern darin, wer ihn erreichen kann.

**How to avoid:**
Vier Maßnahmen, alle klein:
1. Negativ-Karenz je Issuer: höchstens ein Nachholabruf pro Zeitfenster (60 Sekunden sind der
   in der Praxis empfohlene Wert). Innerhalb der Karenz wird ein unbekanntes `kid` abgelehnt,
   ohne zu holen.
2. Single-Flight: ein `asyncio.Lock` je Issuer, sodass M gleichzeitige Fehltreffer einen Abruf
   ergeben und nicht M.
3. Eine Obergrenze für die Länge des Bearer, bevor irgendetwas dekodiert wird. `MAX_RESPONSE_BYTES`
   deckt Antworten ab, nicht den eingehenden Header; ein 200-KB-JWT ist heute kostenlos zu
   senden.
4. Den Exchange-Pfad als eigene Pfadklasse in `oauth/throttle.py` aufnehmen, gezählt wird die
   **Ablehnung**, nicht der erfolgreiche Tool-Aufruf. Damit bleibt D-37 gewahrt (wir drosseln
   nicht die eigentliche Arbeit dieses Servers) und die Begründung des Throttle-Docstrings wird
   wieder wahr. Der Docstring von `throttle.py` muss in derselben Änderung mitziehen, sonst
   steht dort ein Satz, der nicht mehr gilt.

Zusätzlich: `Cache-Control: max-age` der JWKS-Antwort als Obergrenze respektieren, aber nie als
Untergrenze unter die eigene Karenz fallen, und `_MAX_KEYS` beibehalten.

**Warning signs:**
Ein Lasttest fehlt. Im Keycloak-Log tauchen mehr `certs`-Abrufe auf als Anmeldungen. Die
Antwortzeit von `tools/call` korreliert mit der Erreichbarkeit des IdP. Kein Test, der hundert
Tokens mit hundert verschiedenen `kid` schickt und genau einen ausgehenden Abruf erwartet.

**Phase to address:**
P1 für Karenz und Single-Flight, P5 (Härtung und Last) für Messung, Throttle-Pfadklasse und die
Docstring-Korrektur.

---

### Pitfall 6: Clock-Skew-Toleranz verlängert ein absichtlich kurzlebiges Token

**What goes wrong:**
`_LEEWAY_SECONDS = 60` in `oauth/oidc.py` gilt in PyJWT gleichzeitig für `exp`, `nbf` und `iat`;
eine asymmetrische Toleranz kennt die Bibliothek nicht. Keycloaks Standard Token Exchange gibt
ausdrücklich kurzlebige Tokens aus (laut Keycloak-Doku "short-lived and revoked automatically
after some time"), und es gibt keine Introspection und keine Widerrufsliste im heißen Pfad.
Eine Toleranz von einer Minute auf ein Token mit einer Lebensdauer von einer Minute verdoppelt
dessen Gültigkeit. Der zweite Teil: der bestehende Verifier cached positive Antworten fünf
Sekunden (`VALIDATION_CACHE_TTL`). Für den fremden Pfad ist das eine sinnvolle Ersparnis an
RSA-Prüfungen, aber ein Cache-Eintrag darf `exp` nicht überleben. Der dritte Teil ist eine
Uhrenfrage im Container: `StoreTokenVerifier` benutzt bewusst `time.monotonic` für sein
Cache-Fenster. Claim-Prüfungen brauchen dagegen die Wanduhr, und wer beides aus derselben
Funktion zieht, prüft `exp` gegen die Uptime des Prozesses.

**Why it happens:**
60 Sekunden stehen bereits im Repo und wirken wie eine Hausnummer, die man übernimmt. Und eine
Gültigkeitsprüfung ohne echte Uhr fällt in Tests nicht auf, weil dort beide Uhren gefälscht sind.

**How to avoid:**
Eine eigene, kleinere Toleranz für den Exchange-Pfad (Vorschlag 30 Sekunden, konfigurierbar,
dokumentiert) plus zwei Zusatzregeln, die PyJWT nicht mitbringt: eine maximal akzeptierte
Lebensdauer (`exp - iat <= konfiguriertes Maximum`, Vorschlag 15 Minuten, Ablehnung statt
Kürzung) und ein maximales Alter (`iat` nicht älter als dieselbe Grenze). `exp` und `iat` über
`options={"require": [...]}` verpflichtend machen. Den Cache-Eintrag auf `min(jetzt + 5 s, exp)`
begrenzen. Wanduhr und Monotonuhr als zwei getrennte, injizierbare Funktionen führen. Und in die
Admin-Doku einen Satz, der in einem Behördenkontext gelesen wird: ein getauschtes Token ist bis
`exp` gültig, ein Widerruf auf der F13-Seite wirkt nicht rückwirkend, und die Gegenmaßnahme ist
die kurze Lebensdauer plus der Instanzschalter.

**Warning signs:**
Ein Test, der `exp` nur mit "abgelaufen" und "gültig" prüft und nicht mit "in der Toleranz".
`time.monotonic` in einer Claim-Prüfung. Keine Aussage in der Doku, was ein Widerruf bewirkt.

**Phase to address:**
P1, Dokumentationsteil in P6.

---

### Pitfall 7: Der Claim wird zum Anmeldenamen, nicht zum Principal, und der Pausenschalter merkt es nicht

**What goes wrong:**
Dieses Projekt führt drei Namen für ein Konto und hat die Regel dazu in `oauth/principal.py`
niedergeschrieben: der **Anmeldename** ist das, was Basic-Auth gegen Nextcloud braucht, der
**Principal** ist der kanonische Account-Id und der Wert, den jede Identitätsentscheidung
benutzt, und der Anzeigename ist nur zum Lesen. An drei Stellen hängt daran mehr, als ein neuer
Pfad vermuten lässt:
- Der Pausenschalter wird in `exapp/middleware.py:_switch_refusal` mit `identity.principal`
  abgefragt. Ein Exchange-Pfad, der den Anmeldenamen als Principal hinterlegt, fragt einen
  Schlüssel ab, unter dem niemand pausiert hat: das Konto ist pausiert, der Exchange-Aufruf
  läuft trotzdem. Das ist ein stiller Bruch eines ausgelieferten Sicherheitsversprechens
  (EXAPP-02, D-49), und er wird von keinem bestehenden Test berührt.
- Die Audit-Kette heißt `u:<principal>` (`audit/store.py:user_chain`). Ein zweiter Name spaltet
  die Kette desselben Menschen in zwei Ketten, und der Nachweis "genauso nachvollziehbar wie
  jeder andere Aufruf" ist formal erfüllt und praktisch wertlos.
- Der Sweep (D-11/D-12) fragt über `audit/accounts.existing_users` die Nutzerliste der Instanz
  und löscht die Kette eines Kontos, das darin nicht vorkommt. Steht in der Kette ein Wert, der
  kein Nextcloud-Uid ist (eine E-Mail, ein Keycloak-`sub`, ein LDAP-GUID in falscher
  Schreibweise), dann verschwindet nach der Stillefrist genau der Audit-Bestand, der für F13 der
  Zweck der Übung war.

Dazu die Mapping-Fallen selbst, und die sind gemessen und nicht erfunden: LDAP legt objectGUID
üblicherweise in Großschreibung ab, Keycloak liefert denselben Wert in Kleinschreibung; Nextcloud
vergleicht Uids exakt. Eine "hilfreiche" Kleinschreibung beim Vergleich erzeugt umgekehrt eine
Kollision zwischen zwei Konten, die sich nur in der Schreibweise unterscheiden. Unicode kommt
obendrauf: NFC und NFD sehen gleich aus und sind verschiedene Bytes, und ein Claim ist
fremdbestimmte Eingabe. Und `preferred_username` ist in Keycloak änderbar und nach einer
Umbenennung wiederverwendbar.

**Why it happens:**
Der Claim, den ein IdP liefert, heißt oft genau wie der Anmeldename, und auf einer Testinstanz
ohne LDAP sind Anmeldename und Account-Id identisch. Der Fehler ist auf der Entwicklermaschine
unsichtbar und auf der Zielinstanz die Regel; die Spec-Note nennt das selbst "heute die häufigste
Fehlerquelle in dieser Ecke".

**How to avoid:**
Das Mapping endet beim **Principal** und nirgendwo sonst; der Anmeldename wird separat ermittelt
(siehe Pitfall 8) und nie aus dem Claim abgeleitet. Kein eigener Vergleich: `same_principal`
benutzen, das über `compare_digest` auf UTF-8-Bytes vergleicht und Leerwerte abweist. Die
Normalisierungsentscheidung einmal treffen und hinschreiben; Empfehlung: **keine** Normalisierung,
exakter Byte-Vergleich, plus Ablehnung von Werten mit führendem oder folgendem Leerraum, von
Werten, die nicht NFC-stabil sind, und von Steuerzeichen. Die Regel aus `oauth/oidc.py`
(`sub != sub.strip()` wird abgewiesen) ist dafür die Vorlage. E-Mail als Mapping-Claim ab Werk
verbieten: Adressen sind übertragbar und wiederverwendbar, und eine recycelte Adresse ist eine
Kontoübernahme. Wird sie doch konfiguriert, dann nur mit `email_verified` und mit einem
ausdrücklichen Satz in der Admin-Oberfläche. Für F13 (Entscheidung 2) ist die richtige Frage
nicht "welcher Claim", sondern "welcher Claim trägt den Wert, der in dieser Instanz als
Nextcloud-Account-Id gilt", und die Antwort gehört in eine Konfiguration mit dokumentiertem
Default, nicht in Code. Punkt 3 der Spec-Note, das Beispiel-Token, ist genau deshalb kein
Nice-to-have: ohne es wird gegen eine Annahme getestet.

**Warning signs:**
`.lower()` oder `.casefold()` irgendwo im Mapping. `nc_user=claims[...]` in einem Konstruktor von
`OAuthIdentity`. Kein Test mit LDAP-Schreibweise. Eine Audit-Kette, die nach einigen Wochen
verschwindet. Ein pausiertes Konto, das über Exchange weiterhin antwortet: das gehört als
expliziter Negativtest in den Meilenstein.

**Phase to address:**
P3 (Konto-Mapping) für die Ableitung, P2 für den Pausenschalter, P4 (Audit-Anschluss) für Kette
und Sweep.

---

### Pitfall 8: Das getauschte Token beweist eine Identität und liefert kein Nextcloud-Geheimnis

**What goes wrong:**
`OAuthIdentity` trägt `app_password`, und `StoreTokenVerifier.resolve_identity` antwortet `None`,
wenn keines da ist; `deps.resolve_credentials` baut daraus die Basic-Credentials, mit denen jeder
Aufruf gegen Nextcloud läuft. Ein Exchange-Token liefert davon nichts. Wer diese Frage nicht vor
dem ersten Code beantwortet, landet an einem der drei falschen Ausgänge:
(a) ein Dienstkonto mit Admin-Rechten plus Impersonation, also genau der Durchgriff, den dieses
Projekt für OpenProject in v1.5 begründet ausgeschlossen hat und der das Kernversprechen bricht;
(b) ein App-Passwort, das der Connector für den gemappten Nutzer im Hintergrund selbst anlegt,
also ein Zugang, den der Kontoinhaber nie gesehen hat und der in der Verbindungsübersicht nicht
kündbar ist, mit anderen Worten eine stille Kontoanlage auf der Credential-Ebene, während die
Spec-Note die stille Kontoanlage auf der Kontoebene ausdrücklich ausschließt;
(c) die Umgehung von Nextcloud ganz.

**Why it happens:**
Der Satz "wir mappen auf ein Nextcloud-Konto" klingt vollständig. Er ist es nicht: er sagt, **wer**
handelt, nicht **womit**.

**How to avoid:**
Die Frage explizit als Architekturentscheidung des Meilensteins führen und früh entscheiden. Zwei
tragfähige Ausgänge:
1. **ExApp-Modus mit AppAPI-Impersonation.** Läuft der Connector als ExApp, liefert der
   AppAPI-Kontext den Nutzerkontext ohne App-Passwort; das Exchange-Token bestimmt dann nur den
   Wert, der sonst aus `AUTHORIZATION-APP-API` käme. Das ist der sauberste Weg, hat aber eine
   harte Bedingung: die Vertrauenskette endet dann beim `APP_SECRET`, und die Regel aus
   `deps.py` ("in der ExApp-Verzweigung wird der `Authorization`-Header gar nicht gelesen") muss
   bewusst und eng geöffnet werden, nämlich nur bei leerer Nutzerkennung und nur mit
   eingeschaltetem Exchange-Pfad.
2. **Das Exchange-Token wählt eine bestehende Verbindung aus, es erzeugt keine.** Der gemappte
   Principal muss eine vorhandene, vom Nutzer selbst erteilte Autorisierung besitzen; existiert
   keine, wird abgewiesen mit demselben Wortlaut wie jede andere Ablehnung. Das erhält die
   Kündbarkeit in der Verbindungsübersicht, den Pausenschalter und die Verschlüsselung des
   App-Passworts unverändert, und es macht die Zustimmung des Kontoinhabers zur Voraussetzung.
   Preis: F13 kann einen Nutzer nicht ohne dessen vorherigen Klick anbinden, was ehrlich
   kommuniziert werden muss.

Was in keinem Fall passiert: ein neues Geheimnis anlegen, ein gemeinsames Geheimnis benutzen,
oder `app_password` mit einem Platzhalter füllen, damit `resolve_identity` nicht `None` antwortet.

**Warning signs:**
Ein Entwurf, der JWKS-Prüfung und Mapping beschreibt und die Herkunft des Credentials nicht
nennt. Ein neuer Aufruf gegen die Provisioning-API. Ein `app_password=""` im neuen Pfad. Eine
Konfiguration mit einem Admin-Nutzernamen darin.

**Phase to address:**
P0, also vor P1: diese Entscheidung bestimmt, ob und wie viel der Meilenstein ohne F13s
Antworten bauen kann. Sie ist projektintern zu treffen, nicht in den vier Fragen an Denny
enthalten, und das ist eine Lücke der Spec-Note, die aufzunehmen ist.

---

### Pitfall 9: Ein ID-Token wird als Access-Token akzeptiert

**What goes wrong:**
Keycloak signiert ID-, Access- und Logout-Tokens desselben Realms mit denselben Schlüsseln und
demselben `iss`. Eine Prüfung, die Signatur, `iss`, `exp` und `aud` abhakt, akzeptiert damit ein
ID-Token als Zugriffstoken, sobald dessen `aud` zufällig passt, und ein ID-Token ist genau das
Token, das ein Browser-Client legitim in die Hand bekommt. Ein zweiter Fall derselben Familie:
ein normales, nicht getauschtes Access-Token des Orchestrators, das an den falschen Endpunkt
gerät, oder ein Token eines anderen Clients desselben Realms.

**Why it happens:**
RFC 9068 schreibt für Access-Tokens den Header `typ: at+jwt` vor, und die naheliegende Prüfung
darauf schlägt bei Keycloak fehl, weil Keycloak diesen Header nicht so setzt (bekannte Lücke,
Keycloak-Diskussion #19419). Wer merkt, dass die Prüfung alle echten Tokens abweist, entfernt
sie wieder, statt sie zu ersetzen.

**How to avoid:**
Den Token-Typ positiv prüfen, aber am richtigen Feld: Keycloak trägt den Typ als **Payload-Claim**
`typ` ("Bearer" beim Access-Token, "ID" beim ID-Token). Also: `typ` als geforderter Claim mit
konfigurierbarem Erwartungswert (Default `Bearer`), zusätzlich `azp` gegen eine Allowlist der
Clients, die tauschen dürfen, und `aud` exakt wie in Pitfall 2. Wenn F13 laut Entscheidung 4
einen eigenen Eintrag als Exchange-Ziel pflegt, dann ist dessen Client-Id genau der Wert, gegen
den `aud` läuft, und der austauschende Orchestrator genau der Wert, gegen den `azp` läuft. Den
`at+jwt`-Header akzeptieren, wenn er kommt, aber nicht verlangen, und den Grund als Kommentar
hinterlegen, damit die Prüfung nicht später "korrigiert" wird.

**Warning signs:**
Keine `typ`- und keine `azp`-Prüfung im Code. Ein Test-Token, das aus dem Login-Flow eines
Browsers stammt statt aus einem echten Tausch. Ein auskommentierter `at+jwt`-Check.

**Phase to address:**
P1, Gegenprobe in P6 (ein ID-Token desselben Realms muss abgewiesen werden, und der Test gehört
laut Spec-Note offen ins Repo).

---

### Pitfall 10: Der neue Pfad wird gesprächig, und die Ablehnung wird zum Orakel

**What goes wrong:**
Der bestehende Code hat eine harte Disziplin: eine einheitliche Ablehnung ohne Auskunft darüber,
welche Prüfung gefallen ist (T-03-47), kein Token in irgendeiner Zeile, Fehlergründe nur als
feste Formulierungen (`_refused`). Ein neuer Pfad bricht das aus Debug-Not: die Claims werden
geloggt, damit man das Mapping nachvollziehen kann. Claims eines Behörden-IdP tragen Namen,
E-Mail-Adressen, Organisationseinheiten und Gruppen, oft mehr als der Connector je braucht; ein
Log über diese Werte ist eine zweite Kopie genau der Daten, deren Schutz das Produkt verkauft.
Der zweite Teil ist subtiler: unterschiedliche Fehlermeldungen für "Signatur falsch", "Audience
falsch" und "Konto existiert nicht" machen den Connector zum Kontenverzeichnis der Instanz, und
zwar für jeden, der ein syntaktisch gültiges Token bauen kann.

**Why it happens:**
Ein Mapping, das nicht greift, ist ohne Log nicht zu debuggen, und die Versuchung ist am größten
genau dann, wenn F13s Beispiel-Token noch fehlt.

**How to avoid:**
Der Debug-Bedarf ist real und wird bedient, aber strukturiert: ein Prüfbefehl (in der Art von
`occ`-Kommandos, die dieses Repo schon hat) nimmt ein Token entgegen und sagt dem Administrator
lokal, welche Prüfung gefallen wäre und auf welchen Principal gemappt würde. Im laufenden
Betrieb dagegen: eine Ablehnung, ein Statuscode, eine feste Formulierung im Log, kein Claim-Wert,
kein Token, kein Principal. Ein Test, der die Logausgabe eines fehlgeschlagenen Laufs gegen
`sub`, `email` und den Token-String grept, gehört in dieselbe Phase; das Muster existiert im
Repo bereits als AST-Gate und als Vokabular-Gate und lässt sich übernehmen.

**Warning signs:**
`logger.debug("claims: %s", claims)`. Verschiedene `error_description`-Werte je Prüfschritt.
Ein Exception-Text, der einen Claim-Wert per f-String einbaut.

**Phase to address:**
P1 für die Ablehnungsform, P5 für das Gate, P6 für den Prüfbefehl.

---

### Pitfall 11: Der Exchange-Pfad ist "ab Werk aus" nur im Text

**What goes wrong:**
Die Spec-Note verspricht: der Exchange-Pfad kommt daneben, nicht darüber, und er ist ab Werk aus.
Drei Arten, das zu verlieren: der Pfad benutzt die bestehenden `NC_MCP_OIDC_*`-Variablen, die
heute den IdP der Standalone-Browseranmeldung bezeichnen, womit jede Instanz, die schon
Standalone-OAuth betreibt, unbemerkt fremde Tokens akzeptiert; oder `select_mode` bekommt einen
fünften Modus, der aus einem Header oder aus der Form des Tokens folgt, womit eine Anfrage sich
ihren eigenen Modus aussuchen kann; oder das Einschalten setzt sich aus mehreren Variablen
zusammen, sodass eine halbe Konfiguration einen halben Pfad ergibt. `config.oauth_configured`
zeigt, wie es richtig geht: ein ausdrücklicher Schalter und keine Ableitung aus dem Vorhandensein
anderer Variablen, mit genau dieser Begründung im Docstring.

**Why it happens:**
Variablen wiederzuverwenden spart Konfigurationsfläche, und ein Modus fühlt sich wie das richtige
Abstraktionsniveau an.

**How to avoid:**
Eigener Namensraum `NC_MCP_EXCHANGE_*` (Schalter, Issuer, Audience, Konto-Claim, Algorithmen,
azp-Allowlist, maximale Lebensdauer), ein einzelner ausdrücklicher Schalter als Voraussetzung,
und beim Start eine Validierung, die bei halber Konfiguration mit Exit-Code endet statt pro
Anfrage still zu entscheiden (dasselbe Muster wie `entry_exapp` bei APP\_SECRET plus statischem
Bearer). Kein neuer Modus in `select_mode`: der Exchange-Pfad ist ein zusätzlicher Prüfer
innerhalb eines bestehenden Modus, ausgewählt allein durch Konfiguration. Und ein Test, der bei
leerer Umgebung ein perfekt gültiges Exchange-Token abgewiesen sieht.

**Warning signs:**
`NC_MCP_OIDC_ISSUER` im neuen Code. Ein neuer Zweig in `select_mode`. Eine Standardkonfiguration
in `compose.*.yml`, die den Schalter setzt.

**Phase to address:**
P2, Startprüfung in P2, Doku und Store-Text in P6.

---

### Pitfall 12: Die Audit-Zeile sagt "der Nutzer war es" und verschweigt, wer gehandelt hat

**What goes wrong:**
`Caller` hat vier Felder und ausdrücklich kein fünftes (D-08): Nutzer, Client-Id, Auth-Id,
Client-Name. Auf dem Exchange-Pfad gibt es keinen registrierten OAuth-Client dieses Servers; es
gibt einen fremden Aussteller und eine handelnde Partei, die Keycloak in `azp` festschreibt
(laut Keycloak-Doku und Blog wird `azp` auf die Client-Id des Anfragenden erzwungen), dazu
gegebenenfalls `act` beziehungsweise `may_act` aus RFC 8693. Wenn die Zeile nur den Principal
nennt, steht im Audit "dieser Mensch hat gelesen", obwohl ein Orchestrator in seinem Namen
gelesen hat. Für eine Behörde ist die Delegationskette der Punkt, an dem die Nachvollziehbarkeit
hängt; ohne sie ist das Versprechen "genauso nachvollziehbar wie jeder andere Aufruf" formal
eingehalten und inhaltlich verfehlt.

**Why it happens:**
`Caller` ist bewusst eng, und ein fünftes Feld fühlt sich wie ein Regelbruch an. Also füllt man
`client_id` mit irgendetwas Naheliegendem und ist fertig.

**How to avoid:**
Die Erweiterung als ausdrückliche Entscheidung führen, nicht als Nebenwirkung. Vorschlag:
`client_id` trägt den fremden Aussteller und die handelnde Partei in einer stabilen, nicht
kollidierenden Form (etwa `exchange:<issuer-hash>#<azp>`), `auth_id` bleibt leer oder trägt die
gewählte Verbindung, `client_name` bleibt dem entnommen, was tatsächlich registriert ist, und
ein zusätzliches Feld nur, wenn D-08 dafür fortgeschrieben wird. Was dabei nicht in die Zeile
darf, ist unverändert klar: kein Token, keine Adresse, kein User-Agent, kein Claim-Inhalt. Die
Kette bleibt `u:<principal>` mit dem Principal aus Pitfall 7, damit AppAPI-, OAuth- und
Exchange-Aufrufe desselben Kontos in einer Kette stehen und der Sweep sie nicht wegräumt.

**Warning signs:**
Eine Audit-Zeile eines Exchange-Aufrufs, die von einer OAuth-Zeile nicht zu unterscheiden ist.
`client_id=None` auf dem Exchange-Pfad. Kein `azp` im Code.

**Phase to address:**
P4.

---

### Pitfall 13: Fail-closed wird zu fail-everything

**What goes wrong:**
Die Spec-Note verlangt zu Recht fail-closed bei unerreichbarem Schlüsselsatz. Falsch umgesetzt
heißt das: der Prozess baut den Exchange-Prüfer beim Start, holt Discovery und JWKS, und beendet
sich mit Fehler, wenn Keycloak gerade nicht antwortet. Damit macht eine Störung eines fremden
Dienstes eine App-Store-App unbenutzbar, und zwar auch für die vier bestehenden Zugangsarten,
die mit F13 nichts zu tun haben. Dieselbe Verwechslung in klein: eine JWKS-Störung führt zu 503
statt zu 401, und ein Client interpretiert das als "Server kaputt" statt als "Token abgelehnt".

**Why it happens:**
"Fail-closed" wird als Eigenschaft des Prozesses gelesen statt als Eigenschaft der Entscheidung
über ein einzelnes Token.

**How to avoid:**
Fail-closed gilt für das Token: kein Schlüssel, keine Annahme, Antwort 401 mit der bestehenden
Challenge. Der Prüfer wird verzögert und isoliert aufgebaut; Discovery und erster JWKS-Abruf
passieren beim ersten Bedarf und nicht im Start, und ihr Scheitern ist eine Ablehnung, keine
Ausnahme nach oben. Der Startpfad validiert nur die Konfiguration (Syntax, HTTPS-Herkunft,
Vollständigkeit), nicht die Erreichbarkeit. Die Regeln dafür stehen bereits im Repo: `OidcRefused`
trägt keinen Detailgrund, und `_switch_refusal` zeigt, wann ein 503 angemessen ist (eigener
Store nicht lesbar) und wann nicht.

**Warning signs:**
Ein `await` gegen den IdP in `entry_exapp`/`entry_oauth`. Ein 503 im Exchange-Pfad. Ein Test, der
den IdP nur erreichbar kennt.

**Phase to address:**
P2.

---

## Moderate Pitfalls

### Der Scope wird nicht geprüft, und Keycloak kann hochskalieren

Keycloaks Standard Token Exchange erlaubt ausdrücklich das Hinzufügen von Scopes ("upscoping").
Der Connector führt einen Tool-Scope (`oauth/metadata.TOOL_SCOPE`) und füllt `AccessToken.scopes`
aus der eigenen Zeile. Auf dem fremden Pfad kommen die Scopes aus einem fremden String. Regel:
einen Scope, den dieser Server nicht definiert hat, nie als Berechtigung lesen; wenn ein Scope
gefordert wird, dann konfigurierbar und exakt, und die Abwesenheit ist eine Ablehnung, keine
Vollmacht. Prävention gehört in P1.

### Die Discovery-Herkunftsregel bricht in aufgeteilten Netzen

`_same_origin` verlangt, dass jeder Endpunkt auf derselben HTTPS-Herkunft wie der Issuer liegt.
In openDesk- oder Behördenaufbauten ist der Issuer oft öffentlich und die `certs`-URL intern
(Split Horizon). Der Reflex ist, die Regel abzuschalten. Besser: eine ausdrücklich konfigurierte
JWKS-URL als Ausnahme mit eigener Variable, die weiterhin HTTPS verlangt, plus eine
dokumentierte Begründung; die Regel selbst bleibt der Default. Gehört in P1 und in die Admin-Doku
in P6.

### Der Beispiel-Token fehlt, und getestet wird gegen die eigene Annahme

Punkt 3 der Spec-Note ist als Aufwandssparnis formuliert, ist aber ein Qualitätsrisiko: ohne
Realm-Export und ein echtes Beispiel wird gegen selbst gebaute Tokens getestet, die genau die
Struktur haben, die der Prüfer erwartet. Gegenmaßnahme, solange die Antwort fehlt: ein lokaler
Keycloak im Testaufbau (`juliusknorr/nextcloud-docker-dev` bringt einen mit, laut Stack-Notiz
dieses Projekts), und ein Testkorpus, der bewusst danebenliegt (fehlendes `azp`,
Mehrfach-`aud`, ID-Token, Token eines zweiten Realms, Token mit unbekannter `kid`). P6.

### Zwei Wahrheiten über "der Nutzer existiert"

`audit/accounts.existing_users` ist ausdrücklich für einen Aufruf je Sweep gebaut und liefert die
gesamte Nutzerliste der Instanz; im heißen Pfad benutzt wird daraus ein Instanzabzug je
Werkzeugaufruf. Die Existenzprüfung des Mappings braucht deshalb einen anderen Weg, und der
sauberste ist, gar keine zusätzliche Prüfung zu brauchen: wenn das Mapping auf eine bestehende
Autorisierung zeigt (Pitfall 8, Ausgang 2), ist die Existenz durch die Zeile belegt. P3.

### Der Prozess-Cache des Verifiers wird zum Speicherleck mit Verzögerung

`CACHE_LIMIT = 1024` und Leerung bei Volllauf sind bewusst simpel gewählt. Ein fremder Pfad, der
pro Token zusätzlich Claims oder abgeleitete Principals mitcached, verändert die Größe eines
Eintrags und damit die Rechnung hinter dieser Zahl. Entweder denselben Cache mit derselben
Grenze mitbenutzen oder eine eigene Grenze bewusst setzen und begründen. P1.

### Die Nachricht an den Menschen fehlt

Wird ein Token abgewiesen, weil kein Konto existiert oder keine Verbindung vorliegt, sieht der
Endnutzer im Assistenten nur einen Fehler. Die bestehende Lösung für genau dieses Problem ist der
E5-Ausweg und die Verbindungsseite. Der Exchange-Pfad braucht ein Gegenstück in der Doku für F13,
damit deren Orchestrator die Ablehnung in einen Satz übersetzen kann, der zur Verbindungsseite
führt. P6.

---

## Technical Debt Patterns

| Shortcut | Immediate Benefit | Long-term Cost | When Acceptable |
|----------|-------------------|----------------|-----------------|
| Exchange-Prüfung in `StoreTokenVerifier.verify_token` anhängen | Keine Verdrahtung, kein neuer Einstiegspunkt | Zwei Tokenwelten in einer Funktion, Fallback-Kette, Timing-Orakel, zwei Erzeuger für `OAuthIdentity` | Nie |
| `oauth/oidc.py` kopieren statt teilen | Der Browserpfad bleibt unberührt, kein Regressionsrisiko | Zwei Orte für Schlüsselauswahl und Algorithmenregeln, die auseinanderlaufen; ein Fix trifft nur eine Hälfte | Nur mit Test je Regel im neuen Pfad und einem Kommentar, der auf das Original zeigt |
| `check_resource_allowed` für die fremde Audience | Eine Zeile, konsistent mit dem eigenen Pfad | Präfixsemantik hebelt jede Mandantentrennung über Pfadsuffixe aus | Nie |
| JWKS ohne Karenz und ohne Single-Flight | Weniger Code, Rotation funktioniert sofort | Vor-authentischer Verstärker gegen den eigenen Prozess und gegen Keycloak | Nur im stdio-losen Laboraufbau, nie in einem Artefakt, das den Store erreicht |
| Claims loggen, um das Mapping zu debuggen | Support wird möglich | Zweitkopie personenbezogener Daten im Containerlog, gegen das eigene Datenschutzversprechen | Nur lokal über einen ausdrücklichen Prüfbefehl, nie im Anfragepfad |
| Konfiguration über die bestehenden `NC_MCP_OIDC_*` | Keine neuen Variablen, weniger Doku | Bestehende Standalone-Installationen nehmen unbemerkt fremde Tokens an | Nie |
| `app_password` per Provisioning-API selbst erzeugen | Der Pfad funktioniert sofort ohne Nutzerklick | Zugang, den der Kontoinhaber nie gesehen hat und in der Verbindungsübersicht nicht kündigen kann | Nie |
| Toleranz 60 s aus `oauth/oidc.py` übernehmen | Konsistenz mit bestehendem Code | Verdoppelt die Gültigkeit kurzlebiger Exchange-Tokens | Nur mit zusätzlicher Obergrenze für `exp - iat` |

## Integration Gotchas

| Integration | Common Mistake | Correct Approach |
|-------------|----------------|------------------|
| Keycloak (Standard Token Exchange) | `aud` als Liste großzügig prüfen; `azp` ignorieren | `aud` exakt gegen einen Wert (`strict_aud`), `azp` gegen eine Allowlist der tauschberechtigten Clients; `azp` ist laut Keycloak die Client-Id des Anfragenden |
| Keycloak (Tokentypen) | Auf `typ: at+jwt` im Header prüfen und die Prüfung wieder entfernen, weil sie alles abweist | Payload-Claim `typ` prüfen (Access-Token `Bearer`, ID-Token `ID`); `at+jwt` akzeptieren, aber nicht verlangen, mit Kommentar |
| Keycloak (Sitzung und Widerruf) | Annehmen, ein Widerruf im IdP wirke sofort | Standard Token Exchange erzeugt keine neue Sitzung und die Tokens sind kurzlebig; Widerruf wirkt nicht rückwirkend, also kurze Lebensdauer erzwingen und den Satz in die Doku schreiben |
| Keycloak (JWKS) | Bei jedem unbekannten `kid` nachholen | Nachholen mit Karenz je Issuer, Single-Flight, Obergrenze für Schlüsselanzahl, `oct`- und `enc`-Schlüssel verwerfen |
| PyJWT 2.13 | `jwt.decode` mit Defaults für gut halten | `options={"require": [...]}` und `strict_aud` setzen; ohne `require` sind `nbf`, `iat` und `aud` optional |
| Nextcloud (LDAP) | Anmeldename und Account-Id gleichsetzen | Mapping endet beim Principal (`oauth/principal.py`); objectGUID kommt aus LDAP groß und aus Keycloak klein geschrieben, der Vergleich ist exakt und die Schreibweise ist Konfigurationssache |
| Nextcloud (Konto-Existenz) | `existing_users` je Anfrage aufrufen | Existenz über die bestehende Autorisierung belegen; die Instanzliste bleibt beim Sweep |
| MCP-SDK | Den fremden Audience-Wert in `AccessToken.resource` legen | `resource` bleibt der RFC-8707-Begriff des eigenen Pfads; der fremde Wert lebt in der eigenen Struktur |
| AppAPI/HaRP | Annehmen, ein `Authorization`-Header sei in der ExApp-Verzweigung nutzbar | HaRP reicht durch, was der Client schickt; die Regel "in der Nutzerverzweigung wird der Header nicht gelesen" bleibt, geöffnet wird nur die Verzweigung mit leerer Nutzerkennung |

## Performance Traps

| Trap | Symptoms | Prevention | When It Breaks |
|------|----------|------------|----------------|
| JWKS-Abruf im heißen Pfad | Latenz von `tools/call` korreliert mit dem IdP; Keycloak-Zugriffslog voller `certs`-Abrufe | Karenz plus Single-Flight plus Positivcache, begrenzt durch `exp` | Ab dem ersten Angreifer, ohne Angreifer ab dem ersten IdP-Ausfall |
| Unbekanntes `kid` als Verstärker | CPU- und Socketverbrauch ohne eine einzige gültige Anfrage | Negativ-Karenz, Ablehnung ohne Abruf innerhalb der Karenz | Sofort, vor-authentisch |
| Signaturprüfung vor jeder Identität | Lastspitze bei Tokenflut; MCP-Route ist ungedrosselt | Längenobergrenze für den Bearer, Header-Vorprüfung, eigene Throttle-Pfadklasse für Ablehnungen | Ab einigen hundert Anfragen je Sekunde auf einem kleinen Container |
| Positivcache zu großzügig | Ein abgelaufenes Token wird noch akzeptiert | Cache-Ende auf `min(jetzt + TTL, exp)` | Sofort sichtbar in einem Test mit kurzem `exp` |
| Existenzprüfung über die Instanz-Nutzerliste | Antwortzeit steigt mit der Kontenzahl der Instanz | Existenz aus der eigenen Zeile lesen | Ab einigen tausend Konten pro Instanz |

## Security Mistakes

| Mistake | Risk | Prevention |
|---------|------|------------|
| Fremder Prüfer als Rückfallebene des eigenen | Zwei Identitätsquellen in einer Funktion, Timing-Orakel, widersprüchliche `OAuthIdentity` | Formbasierte Weiche vor jeder Prüfung, kein Fallback (D-27) |
| Präfixvergleich der Audience | Token eines Mandanten gilt bei einem anderen | Exakter Vergleich, `strict_aud` |
| Gemeinsamer Schlüssel-Cache über Issuer | Schlüssel von A verifiziert Token von B | Registry je Issuer, `iss` nur als Nachschlagewert, `issuer=` beim Dekodieren gesetzt |
| `iss` aus dem Token als URL benutzen | SSRF und Vertrauen bei erster Begegnung | Issuer ist Konfiguration; `_same_origin` bleibt |
| Algorithmus aus dem Header | Verfahrensverwechslung | Allowlist, Abgleich Header gegen JWKS-`alg`, keine HS\*, kein `oct` |
| ID-Token als Access-Token | Ein Token, das ein Browser legitim hält, wird zum Serverzugang | `typ`-Claim und `azp` prüfen |
| Mapping auf den Anmeldenamen | Pausenschalter wirkungslos, Audit-Kette gespalten | Mapping endet beim Principal, `same_principal` benutzen |
| E-Mail als Mapping-Claim | Recycelte Adresse übernimmt ein fremdes Konto | Ab Werk verboten; nur mit `email_verified` und Warnhinweis |
| Kleinschreibung beim Kontovergleich | Zwei Konten fallen zusammen | Exakter Byte-Vergleich, Schreibweise ist Konfiguration |
| Unnormalisierter Unicode im Claim | Zwei gleich aussehende Werte, ein Konto zu viel | Entscheidung dokumentieren, Werte ohne NFC-Stabilität und mit Randleerraum abweisen |
| Stille Kontoanlage oder stille Credential-Anlage | Zugang ohne Zustimmung des Kontoinhabers, nicht kündbar | Abweisung statt Anlage, auf beiden Ebenen |
| Claims im Log | Zweitkopie personenbezogener Daten im Containerlog | Feste Formulierungen, Gate-Test gegen Token, `sub` und `email` |
| Unterscheidbare Ablehnungen | Kontenverzeichnis über den Connector | Eine Ablehnung, ein Wortlaut, ein Statuscode |
| Kein Ersteinschaltschutz | Bestehende Installationen nehmen unbemerkt fremde Tokens an | Eigener Namensraum, ein ausdrücklicher Schalter, Startvalidierung |

## UX Pitfalls

| Pitfall | User Impact | Better Approach |
|---------|-------------|-----------------|
| Ablehnung ohne Weg nach vorn | Der Nutzer sieht im Assistenten einen Fehler und weiß nicht, dass eine Verbindung fehlt | Ein dokumentierter, maschinenlesbarer Ablehnungscode für F13 plus ein Satz in der Doku, der auf die Verbindungsseite zeigt |
| Exchange-Verbindungen tauchen in der Verbindungsübersicht nicht auf | Der Kontoinhaber sieht nicht, dass ein Orchestrator in seinem Namen liest | Exchange-Nutzung sichtbar machen, mindestens im Audit und in der Verbindungsseite |
| Admin-Oberfläche erklärt den Schalter nicht | Ein Administrator schaltet fremde Tokens ein, ohne die Audience-Konvention zu verstehen | Beschriftung nennt Issuer, Audience und Konto-Claim ausdrücklich, mit dem Satz "Konten werden nie angelegt" |
| Store-Text nennt Enterprise-Fähigkeiten, die noch nicht tragen | Ein wahrer Satz wird falsch, sobald "Token Exchange" dort auftaucht | Wortlaut erst ändern, wenn der Pfad gemessen ist; dieselbe Lehre wie beim Audit-Log in v1.5 |

## "Looks Done But Isn't" Checklist

- [ ] **JWKS-Prüfung:** oft fehlt die Karenz bei unbekanntem `kid` und das Single-Flight. Prüfen: hundert Tokens mit hundert `kid`-Werten erzeugen genau einen ausgehenden Abruf.
- [ ] **Audience:** oft geprüft, aber mit Präfixsemantik. Prüfen: ein Token mit `aud = <konfigurierte Ressource>/irgendwas` wird abgewiesen.
- [ ] **Issuer:** oft geprüft, aber ohne Bindung an den Schlüssel. Prüfen: ein Token von Realm B, signiert mit dem Schlüssel von Realm B, dessen `kid` zufällig der von Realm A ist, wird abgewiesen.
- [ ] **Tokentyp:** oft nicht geprüft. Prüfen: ein ID-Token desselben Realms wird abgewiesen.
- [ ] **Pausenschalter:** oft nicht gegen den neuen Pfad getestet. Prüfen: Konto pausiert, Exchange-Aufruf endet mit 403 und `access_disabled`.
- [ ] **Audit:** oft nur "es steht eine Zeile da". Prüfen: die Zeile nennt die handelnde Partei, hängt an derselben Kette wie AppAPI-Aufrufe desselben Kontos und überlebt einen Sweep-Lauf mit Kontoprüfung.
- [ ] **Abweisung statt Anlage:** oft nur für das Konto geprüft. Prüfen: auch kein App-Passwort, keine Verbindung und kein Store-Eintrag entstehen bei einem Token ohne passende Autorisierung.
- [ ] **Ab Werk aus:** oft nur behauptet. Prüfen: leere Umgebung, gültiges Token, Antwort 401; und eine halb gesetzte Konfiguration beendet den Start.
- [ ] **Fail-closed:** oft als Prozessabbruch umgesetzt. Prüfen: IdP unerreichbar, ExApp-Pfad und stdio funktionieren weiter, Exchange-Token bekommt 401 und nicht 503.
- [ ] **Keine Leaks:** oft nicht getestet. Prüfen: Log eines fehlgeschlagenen und eines erfolgreichen Laufs enthält weder Token noch `sub` noch `email` noch den Principal.
- [ ] **Lebensdauer:** oft nur `exp` geprüft. Prüfen: ein Token mit achtstündiger Lebensdauer wird abgewiesen, wenn die Obergrenze fünfzehn Minuten ist.

## Recovery Strategies

| Pitfall | Recovery Cost | Recovery Steps |
|---------|---------------|----------------|
| Fremder Prüfer als Fallback gebaut | MEDIUM | Weiche vorziehen, Prüfer trennen, `OAuthIdentity`-Erzeugung auf einen Ort zurückführen; Tests je Pfad nachziehen |
| Präfix-Audience ausgeliefert | HIGH, wenn F13 die Konvention schon nutzt | Exakten Vergleich nachrüsten, die betroffene Audience-Konvention mit F13 neu festschreiben, betroffene Instanzen benennen |
| Mapping auf den Anmeldenamen ausgeliefert | HIGH | Principal-Ableitung korrigieren, Audit-Ketten bleiben gespalten (nicht rückwirkend heilbar), Pausenschalter-Lücke als Sicherheitsnachzieher mit Regressionstest schließen, Zeitraum im Changelog benennen |
| Stille Credential-Anlage ausgeliefert | HIGH | Erzeugte App-Passwörter identifizieren und widerrufen, Nutzer informieren, Pfad auf bestehende Autorisierungen umstellen |
| JWKS-Verstärker ausgeliefert | LOW bis MEDIUM | Karenz und Single-Flight nachrüsten, Keycloak-Betreiber informieren, Lastmessung nachholen |
| Claims im Log gelandet | MEDIUM | Logs rotieren und löschen, Gate-Test nachrüsten, Datenschutzdoku prüfen |
| Start hängt am IdP | LOW | Aufbau verzögern, Startvalidierung auf Konfigurationssyntax beschränken |

## Pitfall-to-Phase Mapping

Die Phasennamen sind Vorschläge; entscheidend ist die Reihenfolge, weil P0 die Form von P1 bis P4
bestimmt.

| Pitfall | Prevention Phase | Verification |
|---------|------------------|--------------|
| 8 Credential-Herkunft | **P0 Entscheidung "womit handelt der gemappte Nutzer"** | Ein schriftlicher Entscheid im Meilenstein, der einen der beiden zulässigen Ausgänge benennt; kein Code vorher |
| 2 Audience, 3 Issuer und `kid`, 4 Algorithmus, 6 Uhr und Lebensdauer, 9 Tokentyp, 5 (Karenz, Single-Flight) | **P1 Fremder Tokenprüfer** | Testkorpus mit den Negativfällen aus der Checkliste, je Regel ein Test, alle gegen einen lokalen Keycloak |
| 1 Weiche, 11 Ersteinschaltschutz, 13 fail-closed, 7 (Pausenschalter) | **P2 Andocken an die Transportgrenze** | Ein eigenes Token erreicht den fremden Pfad nie und umgekehrt; leere Umgebung weist ein gültiges Token ab; IdP aus, ExApp-Pfad läuft; pausiertes Konto wird abgewiesen |
| 7 Mapping, stille Anlage, Groß- und Kleinschreibung, Unicode, E-Mail | **P3 Konto-Mapping** | LDAP-Fall mit abweichender Schreibweise, Unicode-Varianten, E-Mail-Claim ab Werk abgewiesen, Konto ohne Autorisierung abgewiesen |
| 12 Delegationskette, 7 (Kette und Sweep) | **P4 Audit-Anschluss** | Exchange-Zeile nennt die handelnde Partei, hängt an der Kette des Principals, überlebt einen Sweep mit Kontoprüfung |
| 5 Last, 10 Gate gegen Leaks | **P5 Härtung und Last** | Messung der ausgehenden Abrufe unter Tokenflut, Log-Gate grept nach Token, `sub`, `email`; Docstring von `throttle.py` korrigiert |
| 10 Prüfbefehl, Doku, Store-Text, Beispiel-Token | **P6 Nachweis und Doku** | Offen abgelegter Testfall im Repo (Zusage der Spec-Note), Admin-Doku nennt Audience, Claim, Widerrufsverhalten und die Abweisungsregel; Store-Text erst nach Messung |

## Sources

Code dieses Repos, direkt gelesen (HIGH):
- `src/mcp_connector/oauth/verifier.py` (Store-Lookup, RFC-8707-Prüfung, Positivcache, `AUTH_ID_CLAIM`, `CACHE_LIMIT`)
- `src/mcp_connector/oauth/oidc.py` (JWKS-Cache 300 s, `_ALLOWED_ALGORITHMS`, `_ALLOWED_KEY_TYPES`, `_usable_key`, `_same_origin`, `_LEEWAY_SECONDS`, `_MAX_KEYS`, Nachhol-Verhalten in `_key`)
- `src/mcp_connector/oauth/principal.py` (Anmeldename, Principal, `same_principal`)
- `src/mcp_connector/oauth/throttle.py` (MCP-Route ausdrücklich nicht gedrosselt, Begründung)
- `src/mcp_connector/oauth/provider.py:976` und `store.py:367` (eigene Tokens sind `secrets.token_urlsafe`, Lookup über SHA-256)
- `src/mcp_connector/exapp/middleware.py` (Reihenfolge Handshake, Bearer, Pausenschalter; `_deposit`)
- `src/mcp_connector/deps.py` (Credential-Verzweigungen, `Caller` mit vier Feldern, D-27)
- `src/mcp_connector/audit/store.py` (`user_chain`, Sweep) und `audit/accounts.py` (Instanz-Nutzerliste, ein Aufruf je Sweep)
- `src/mcp_connector/config.py` (`select_mode`, `oauth_configured`, `NC_MCP_OIDC_*`)

Installierte Abhängigkeiten, Quelltext gelesen (HIGH):
- PyJWT 2.13.0, `jwt/api_jwt.py` (`_validate_aud` inklusive `strict_aud`, `_validate_exp/nbf/iat`, `require`) und `jwt/algorithms.py` (`NoneAlgorithm.prepare_key`, `HMACAlgorithm.prepare_key` mit der ausdrücklichen Abwehr der Algorithmenverwechslung)
- MCP-SDK, `mcp/shared/auth_utils.py` (`check_resource_allowed` als hierarchische Präfixprüfung)

Externe Quellen (MEDIUM-HIGH):
- https://www.keycloak.org/securing-apps/token-exchange (Inhalt des getauschten Tokens, `azp`, `aud`-Downscoping, `may_act`, keine neue Sitzung, kurze Lebensdauer)
- https://www.keycloak.org/2025/05/standard-token-exchange-kc-26-2 (Standard Token Exchange nach RFC 8693 offiziell unterstützt ab 26.2)
- https://github.com/keycloak/keycloak/discussions/19419 (Keycloak setzt den `typ`-Header nicht auf `at+jwt`, RFC-9068-Lücke)
- https://github.com/fraiseql/fraiseql/issues/1335 und https://github.com/randomizedcoder/agent-seddon/pull/353 (unbekanntes `kid` ohne Negativcache und Karenz als vor-authentischer Verstärker, Gegenmaßnahmen: ein Nachholabruf, Karenz von 60 s, Single-Flight)
- https://github.com/nextcloud/user_saml/issues/406 und https://github.com/nextcloud/server/issues/55284 (Groß- und Kleinschreibung: objectGUID aus LDAP groß, aus Keycloak klein; exakter Abgleich von externem Id und Nextcloud-Uid)
- https://github.com/nextcloud/user_oidc (Mapping-Attribut muss dem internen Benutzernamen der LDAP-Konfiguration entsprechen)

Projektinterne Grundlagen:
- `C:\Users\Student\Desktop\F13-Spec-Note-Identity-Mapper-2026-09-16.md` (Stand 18.09., die vier Entscheidungen, die Ausschlüsse in Abschnitt 5)
- `.planning/PROJECT.md` (Milestone v1.6, Kernversprechen, D-Entscheide) und die v1.5-Fassung dieser Datei (OpenProject-Impersonationsbefund, der hier als Präzedenzfall dient)

---
*Pitfalls research for: F13 Token Exchange Identity Mapper (fremde IdP-Tokens an einem bestehenden Resource-Server)*
*Researched: 2026-09-18*
