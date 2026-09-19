---
phase: 22-konfiguration-kette-und-drosselung
reviewed: 2026-09-19T12:00:00Z
depth: deep
files_reviewed: 13
files_reviewed_list:
  - src/mcp_connector/oauth/chain.py
  - src/mcp_connector/oauth/throttle.py
  - src/mcp_connector/config.py
  - src/mcp_connector/entry_exapp.py
  - src/mcp_connector/entry_oauth.py
  - src/mcp_connector/oauth/jwks.py
  - src/mcp_connector/oauth/exchange.py
  - tests/unit/test_oauth_exchange_chain.py
  - tests/unit/test_oauth_abuse.py
  - tests/unit/test_config.py
  - tests/unit/test_exapp_entry.py
  - tests/unit/test_entry_oauth.py
  - tests/unit/test_oauth_jwks.py
findings:
  critical: 1
  warning: 4
  info: 5
  total: 10
status: issues_found
---

# Phase 22: Code Review Report

**Reviewed:** 2026-09-19
**Depth:** deep (Quergriff auf `exapp/middleware.py`, `oauth/verifier.py`, `oauth/metadata.py`; Diff gegen `f88bbdd` je Datei gelesen)
**Files Reviewed:** 13
**Status:** issues_found

## Summary

Die drei Zusagen der Phase halten dort, wo die Tests sie messen, und die Messungen sind echte: der Aus-Zustand ist mit `is` festgenagelt (dasselbe Objekt an der Grenze, kein Wrapper an der Route), die Weiche fällt strukturell über `looks_like_jws` und beide Richtungen sind mit Attrappen belegt, die beim Aufruf auffliegen, der fremde Claim-Satz reist unter genau einem verschachtelten Schlüssel, ein Widerruf erreicht Store-Cache und Schlüsselsatz und lässt die beiden vor-authentischen Bremsen nachweislich stehen (vier respx-Messungen an `call_count`), und die Drossel zählt genau die JWS-förmigen Bearer, mit `applies`-Kurzschluss vor jedem Zählerzugriff und `_counters == {}` als Beweis. Die Formregel des Headers in `exchange_shaped_request` ist zeichengleich mit der der Transportgrenze (`_BEARER_PREFIX`-Präfix ohne Gross-Klein, `strip()` auf dem Rest, `headers.get` mit denselben Erstes-Vorkommen-Semantiken), das habe ich am Quelltext beider Stellen verglichen. `throttle.py` kennt den Exchange-Pfad tatsächlich nicht, und kein Refusal-Text von `chain.py` trägt einen gelesenen Wert.

Der Kern der Befunde liegt an den Rändern, die kein Test misst. Erstens: der Audience-Default hängt an `config.public_url`, und deren Default ist `http://127.0.0.1:8765`. Ein bewaffneter Exchange-Pfad in einem ExApp ohne gesetzte Public-URL, oder nach dem `IssuerRefused`-Rebuild von `entry_exapp.main`, der die Public-URL absichtlich fallen lässt, läuft damit mit einer Audience, die auf jeder gleich fehlkonfigurierten Instanz identisch ist. Das ist genau die Instanzgrenze, die T-22-03 halten soll, und sie fällt lautlos, entgegen der eigenen Regel des Moduls, dass ein Halbzustand nie bedient wird. Zweitens: die "genau eine INFO-Zeile je Start"-Zusage der Standalone-Hälfte ist auf dem einzigen Produktionspfad (`main`) falsch, dort stehen zwei Zeilen, und der Test, der "einmal" beweist, kombiniert genau diesen Pfad nicht.

Alle Behauptungen unten sind am Quelltext beider Seiten nachvollzogen; wo eine Zahl steht, steht die Zeile daneben.

## Critical Issues

### CR-01: Der Audience-Default degradiert lautlos auf `http://127.0.0.1:8765/mcp` und hebt damit die Instanzgrenze von T-22-03 auf

**File:** `src/mcp_connector/oauth/chain.py:143-146`, dazu `src/mcp_connector/config.py:128` (`DEFAULT_PUBLIC_URL`) und `src/mcp_connector/entry_exapp.py:636` (`resolved.pop(config.ENV_PUBLIC_URL, None)`)

**Issue:** Der Default der Audience ist `f"{config.public_url(source)}{RESOURCE_SUFFIX}"`. `config.public_url` antwortet mit `DEFAULT_PUBLIC_URL = "http://127.0.0.1:8765"`, wenn `NC_MCP_PUBLIC_URL` fehlt oder leer ist (`config.py:343-346`). Zwei erreichbare Wege führen einen **bewaffneten** Exchange-Pfad in diesen Zustand:

1. ExApp ohne Public-URL: `entry_exapp.main` loggt dafür seit Plan 05-04 nur einen Fehler und **bedient weiter** (Zeile 563-594). `build_exapp_app` liest den Namensraum davor (Zeile 104) und bewaffnet die Kette mit der Audience `http://127.0.0.1:8765/mcp`.
2. Der `IssuerRefused`-Rebuild: `main` entfernt die konfigurierte Public-URL aus dem Mapping (Zeile 636) und baut erneut. Auf dem zweiten Bau wird `load_exchange_config(resolved)` erneut ausgeführt und der Audience-Default aus der jetzt fehlenden Public-URL berechnet. Eine Instanz, deren Public-URL das SDK ablehnte, betreibt den Exchange-Pfad ab da mit dem Loopback-Default, obwohl der Operator eine Audience nie angefasst hat, und die zweite INFO-Zeile "the token exchange path is armed" sagt dazu nichts.

Die Folge: jede Instanz in diesem Zustand akzeptiert dieselbe Audience. In genau dem Einsatzbild, für das die Phase gebaut ist (mehrere Behörden-Instanzen hinter demselben F13-Orchestrator, also gleicher Issuer und gleiche `azp`-Allowlist), hält ein Token, das für Instanz A gemünzt wurde, damit auch an Instanz B. Das ist wörtlich der Satz, den der Moduldocstring (Zeile 36-39) und T-22-03 ausschliessen. Der Test `test_the_audience_default_is_the_resource_url_of_this_instance` (`test_oauth_exchange_chain.py:149`) setzt die Public-URL immer; der Fall "bewaffnet ohne Public-URL" steht in keinem Korpus. Dass der Store-Verifier dieselbe Default-Resource benutzt (`verifier.py:198`), ist kein Gegenargument: dessen Tokens sind Zufallswerte gegen den lokalen Store, eine Instanzverwechslung ist dort strukturell unmöglich; beim Exchange-Pfad ist die Audience die **einzige** Instanzbindung eines fremd signierten Tokens.

Das Modul misst sich selbst an "Half configured is never served" (`load_exchange_config`-Docstring, Zeile 127-133). Ein bewaffneter Pfad, dessen Audience ein Platzhalter ist, den kein Betreiber je gesehen hat, ist genau so ein Halbzustand, und er wird bedient statt abgewiesen.

**Fix:** Den Default nur bilden, wenn es eine Quelle für ihn gibt, sonst benannt abweisen:

```python
audience = _optional(source, config.ENV_EXCHANGE_AUDIENCE)
if audience is None:
    if not (source.get(config.ENV_PUBLIC_URL) or "").strip():
        raise ToolError(
            message=(
                f"{config.ENV_EXCHANGE_AUDIENCE} is not set and "
                f"{config.ENV_PUBLIC_URL} names no address to derive it from."
            ),
            hint=_HINT,
        )
    audience = f"{config.public_url(source)}{RESOURCE_SUFFIX}"
```

Damit endet auch der `IssuerRefused`-Rebuild in `entry_exapp.main` für einen bewaffneten Pfad im vorhandenen `except ToolError as second` mit Exitcode 2, was für einen Sicherheitspfad die richtige Antwort ist: das Wachbleiben von Plan 05-04 existiert für die Store-Installation ohne Deploy-Variablen, und wer den Exchange-Namensraum setzt, ist nie diese Installation. Dazu zwei Tests: `load_exchange_config(ARMED ohne NC_MCP_PUBLIC_URL)` ist eine ToolError, die beide Variablennamen nennt, und der Rebuild-Pfad mit bewaffnetem Namensraum endet in SystemExit 2 statt in einem zweiten Bau.

## Warnings

### WR-01: Der bewaffnete Standalone-Start über `main` schreibt die INFO-Zeile zweimal; die Zusage "genau eine Zeile je Start" ist auf dem Produktionspfad falsch und ungetestet

**File:** `src/mcp_connector/entry_oauth.py:157-158`, `219-229`, `419-428`

**Issue:** `main` ruft `load_settings()` (kündigt an, Zeile 158) und danach `build_oauth_app(settings=settings)`. Dort gilt `settings is not None`, also liest Zeile 228 den Namensraum erneut aus `os.environ` und Zeile 229 kündigt **erneut** an. Zwei INFO-Zeilen je bewaffnetem Start. Der Kommentar an Zeile 226-227 ("the announcement stays one line per start either way") und die 22-01-Summary ("es bleibt bei genau einer Zeile je Start") behaupten das Gegenteil. Die beiden Tests decken je einen Aufrufweg einzeln: `test_a_complete_exchange_configuration_is_announced_once_and_without_a_value` ruft nur `load_settings`, `test_the_application_is_announced_once_when_the_settings_are_handed_in` baut die Settings aus einer **unbewaffneten** Umgebung. Die Kombination, die `main` tatsächlich fährt (bewaffnet in beiden Schritten), misst keiner. Kein Sicherheitsschaden, aber eine gemessene Behauptung der Phase, die nicht stimmt, und doppelte Zeilen in genau dem Log, in dem ein Auditor später zählen soll, wie oft der Pfad bewaffnet wurde.

**Fix:** Die Ankündigung an genau eine Stelle: aus `load_settings` entfernen und in `build_oauth_app` nach der endgültigen `exchange_config` ausführen (beide Aufrufwege laufen dort zusammen, `main` baut genau einmal). Dazu ein Test, der den `main`-Weg nachstellt: `load_settings(armed_env)` plus `build_oauth_app(armed_env, settings=...)` und `len(announcements) == 1` über beide Aufrufe zusammen.

### WR-02: `StandaloneSettings.exchange` wird auf dem Settings-Pfad ignoriert; die Kette kann aus einer anderen Quelle gebaut werden als die hereingereichten Settings

**File:** `src/mcp_connector/entry_oauth.py:94-97` (Docstring des Feldes), `218-229`

**Issue:** Zeile 219 liest `resolved.exchange`, Zeile 228 überschreibt es auf dem Settings-Pfad bedingungslos mit dem Ergebnis eines zweiten Umgebungslesens (`env`, bei `main` also `os.environ`). Damit ist das Feld auf dem Pfad, für den es laut Docstring existiert ("so that the application built from them reads the namespace exactly once"), totes Gewicht: der Namensraum wird ein zweites Mal gelesen, und was in den Settings steht, entscheidet nichts. Ein Aufrufer, der Settings mit bewaffnetem `exchange` aus Mapping A baut und `build_oauth_app(settings=...)` ohne `env` ruft, bekommt bei sauberem `os.environ` eine Anwendung **ohne** Kette, ohne Fehler und ohne Zeile: er glaubt bewaffnet und bedient unbewaffnet, das ist die stille Halbkonfiguration, gegen die T-22-02 geschrieben ist, nur eine Ebene höher. Bei `main` sind beide Quellen zufällig dieselbe, weshalb es niemand sieht.

**Fix:** Die Doppelablesung behalten (sie trägt die Abweisung der Halbkonfiguration), aber die Widersprüche abweisen statt still aufzulösen:

```python
if settings is not None:
    reread = chain.load_exchange_config(env)
    if (reread is None) != (resolved.exchange is None):
        raise ToolError(
            message=(
                "the exchange configuration of the handed-in settings and the one of "
                "this environment disagree about whether the path is armed."
            ),
            hint=_HINT,
        )
    exchange_config = reread
```

Und den Feld-Docstring auf die Wirklichkeit bringen: das Feld trägt die Antwort des `load_settings`-Weges, der Settings-Weg liest erneut und prüft Gleichheit. Ein Test mit bewaffneten Settings und leerem `env`-Mapping, der die ToolError erwartet.

### WR-03: Die Bearer-Leseweise existiert jetzt zweimal (Middleware privat, `chain._BEARER_PREFIX` als Kopie), und kein Test hält die beiden gegeneinander

**File:** `src/mcp_connector/oauth/chain.py:314-318`, `338-341`; Gegenstelle `src/mcp_connector/exapp/middleware.py:80`, `232-234`

**Issue:** Die Phase begründet `exchange_shaped_request` damit, dass die Formregel "genau einmal existieren darf" (Docstring Zeile 325-330), und hält das für `looks_like_jws` auch mit einem Test (`test_the_condition_of_the_throttle_is_the_switch_of_the_verifier_itself`). Für die andere Hälfte derselben Bedingung, die Extraktion des Tokens aus dem Header, gilt es nicht: `_BEARER_PREFIX` plus Präfixvergleich plus `strip()` stehen wortgleich in `middleware.py` (privat) und als eingestandene Kopie in `chain.py`. Heute sind sie zeichengleich (verglichen), aber nichts hält sie zusammen: die Ende-zu-Ende-Tests prüfen nur die Headerformen `Bearer/bearer/BEARER a.b.c`, `Basic`, leer und fehlend. Driftet die Middleware-Leseweise (etwa eine tolerantere Trennzeichenbehandlung), zählt die Drossel eine andere Menge als die, die die Grenze in den Exchange-Zweig schickt, und das ist wörtlich der Fall, den der eigene Docstring "schlechter als keine Drossel" nennt: entweder ungedrosselte vor-authentische Signaturarbeit oder gedrosselte eigene Tokens.

**Fix:** Ein Vertragstest, der beide Leseweisen über eine Header-Matrix (Tab statt Leerzeichen, Doppel-Leerzeichen, fehlendes Leerzeichen, `Bearer` ohne Rest, führender Weissraum, Nicht-ASCII-Rest) gegeneinander hält: für jede Form muss `exchange_shaped_request` genau dann `True` sagen, wenn die Grenze einen Token extrahiert, der `looks_like_jws` erfüllt. Da `middleware.py` ausserhalb des Phasen-Zauns liegt, ist der Test der zaunverträgliche Fix; die Konstante teilen kann eine spätere Phase.

### WR-04: `ChainedVerifier.invalidate` ohne `try/finally`: wirft die Store-Hälfte, erreicht der Widerruf den Schlüsselsatz nie

**File:** `src/mcp_connector/oauth/chain.py:430-440`

**Issue:** `invalidate` ruft `self._store.invalidate()` und danach `self._checker.forget_keys()`. Der konkrete `StoreTokenVerifier.invalidate` ist ein `dict.clear()` und kann nicht werfen (geprüft, `verifier.py:207-215`), aber der Zweig ist absichtlich ein Protokoll (`StoreBranch`), damit andere Implementierungen hereingereicht werden können, und die Testdatei selbst reicht Stellvertreter herein, deren `invalidate` wirft. Für jede solche Implementierung bleibt bei einem Fehler der ersten Hälfte ein rotierter Signaturschlüssel bis zu fünf Minuten benutzbar, und zwar genau in dem Moment, in dem jemand widerrufen hat, also die stillste Form des Versagens dieser Kette. Der Docstring verspricht "One call, both layers" ohne diese Einschränkung.

**Fix:**

```python
def invalidate(self) -> None:
    try:
        self._store.invalidate()
    finally:
        self._checker.forget_keys()
```

Ein Test mit einem Store, dessen `invalidate` wirft: `forget_keys` wurde trotzdem gerufen, die Ausnahme kommt an.

## Info

### IN-01: Der Bau des `AccessToken` steht ausserhalb des Fail-closed-Fangs von T-22-09

**File:** `src/mcp_connector/oauth/chain.py:399-415`

`except Exception` deckt nur den Aufruf `claims_of` ab. `str(claims["azp"])` und `int(claims["exp"])` danach werfen `KeyError`, wenn ein (per Protokoll austauschbarer) `ExchangeBranch` einen Claim-Satz ohne diese Schlüssel liefert, und das wird an der Grenze ein 500. Mit dem echten Checker unerreichbar (Phase 21 garantiert beide Claims), aber die Zusage "jede unerwartete Ausnahme dieses Zweigs ist eine Abweisung" endet vier Zeilen zu früh. Fix: die Konstruktion in denselben `try` ziehen oder die beiden Zugriffe mit `claims.get` plus Abweisung schreiben.

### IN-02: `retry_after` beschattet seinen eigenen Parameter `limit` in der Schleife

**File:** `src/mcp_connector/oauth/throttle.py:264-272`

`for key, limit in pairs:` überschreibt den Parameter `limit`. Funktional korrekt, weil `pairs` vorher gebaut ist, aber genau die Zeile, an der die nächste Hand beim Lesen stolpert. Vorbestand, nicht Phase 22; beim nächsten Anfassen der Datei umbenennen (`for key, bound in pairs:`).

### IN-03: Zwei Leerzeilen-Artefakte aus dem Phasen-Diff

**File:** `src/mcp_connector/oauth/jwks.py:213-214`, `src/mcp_connector/oauth/exchange.py:495-496`

`def _stale(...)` und `def _require_text(...)` haben durch diese Phase je eine leere Zeile zwischen Signatur und Rumpf bekommen (im Diff als eigene `+`-Zeile sichtbar). Kosmetik, aber es sind die einzigen zwei Funktionen des Repos in dieser Form. Entfernen.

### IN-04: Der 429-Pfad des ExApp-Einstiegspunkts ist nur strukturell belegt, nie Ende zu Ende

**File:** `tests/unit/test_exapp_entry.py:2397-2410`, Gegenstück `tests/unit/test_oauth_exchange_chain.py:872-921`

Die beiden gemessenen 429-Läufe (Limit, Retry-After, `call_count == 0`, unberührter Alt-Pfad) laufen ausschliesslich gegen `build_oauth_app`. Für `build_exapp_app` gibt es nur die zwei Strukturtests (Wrapper aussen, nichts im Aus-Zustand). Die Verdrahtung ist zeilengleich und der Wrapper geteilt, das Risiko ist klein; trotzdem ist die ExApp der Pfad, den F13 tatsächlich trifft, und ein einziger `TestClient`-Lauf gegen die gebaute ExApp-Anwendung (mit AppAPI-Attrappe oder direkt gegen die 401 der Grenze) würde die Lücke schliessen.

### IN-05: Widerruf plus gebasteltes Token ordnet je Zyklus einen ausgehenden JWKS-Abruf an; der Deckel ist die Drossel, und das steht nirgends

**File:** `src/mcp_connector/oauth/chain.py:430-440`, `src/mcp_connector/oauth/jwks.py:196-211`

`forget()` lässt die beiden Bremsen absichtlich stehen, aber der Expiry-Abruf ist von der Miss-Abkühlzeit ausgenommen (by design, `jwks.py:184`). Ein Client mit Widerrufsrecht kann also im Takt `POST /revoke` (200, ungezählt, weil die Klasse Ablehnungen zählt) plus ein JWS-förmiges Token mit passendem `iss` und erfundenem `kid` je Zyklus genau einen Abruf beim Provider anordnen. Begrenzt wird das heute allein durch `EXCHANGE_LIMIT`/`PATH_CEILING`, weil die gebastelten Tokens als Ablehnungen zählen; sobald Phase 23 gültigen Exchange-Tokens eine Identität gibt, werden deren 200er **vergeben** statt gezählt, und die Rechnung ändert sich. Kein Fix jetzt; ein Satz im Docstring von `forget` beziehungsweise in der Phase-24-Planung (AUDIT-07), damit die Grenze dort nachgemessen wird, statt wiederentdeckt.

---

_Reviewed: 2026-09-19_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: deep_
