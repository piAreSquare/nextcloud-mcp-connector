# Project Research Summary

**Project:** MCP Connector für Nextcloud
**Domain:** OAuth-Resource-Server einer ausgelieferten Nextcloud-ExApp erweitert um die Annahme eines fremden, nach RFC 8693 getauschten Keycloak-Tokens (F13-Orchestrator) und dessen Abbildung auf ein lokales Nextcloud-Konto
**Researched:** 2026-09-18
**Confidence:** HIGH für Stack, Architektur und Pitfalls (eigener Quelltext, installierte Abhängigkeiten und offizielle Doku direkt gelesen), MEDIUM für die Keycloak-Feldrealität und die Nextcloud-Kontoseite, solange das Beispiel-Token und der Realm-Export von F13 fehlen.

## Executive Summary

Milestone v1.6 baut keinen neuen Authorization Server und keine neue Bibliothek, sondern einen zweiten, klar getrennten Prüfpfad neben der bestehenden Standalone-OAuth-Maschinerie aus PR #6. Der Kern ist immer PyJWT gegen ein JWKS aus oauth/oidc.py, das für den Exchange-Pfad herausgelöst statt zweitgeschrieben wird; die einzige nötige Abhängigkeitsänderung ist eine Untergrenzenanhebung von PyJWT auf >=2.14,<3, weil diese Sicherheitsfreigabe vom 11.09.2026 exakt den JWKS-Pfad betrifft, den dieser Meilenstein baut. Drei Befunde ziehen sich unabhängig durch alle vier Recherchen und bestimmen die Reihenfolge des Baus: Erstens ist die Frage, woher ein über Exchange gemapptes Konto seine Nextcloud-Anmeldedaten bekommt (AppAPI-Impersonation über APP_SECRET gegen eine vorab vom Nutzer erteilte, gespeicherte Autorisierung), eine Vollmachtsentscheidung des Owners und keine technische Frage; sie gehört vor die erste Codezeile, nicht ans Ende. Zweitens ist die im Projekt bereits vorhandene RFC-8707-Prüfstelle (check_resource_allowed aus dem MCP-SDK) für fremde Audiences ungeeignet, weil sie eine hierarchische Pfad-Präfixprüfung ist und keine exakte Gleichheit; für den Exchange-Pfad braucht es einen eigenen exakten Vergleich, dazu strict_aud in PyJWT, weil Keycloak-Tokens häufig mehrere Audiences tragen. Drittens existiert die gesamte JWKS-Maschinerie (Cache mit Verfallszeit, Rotation, Algorithmen- und Schlüsseltyp-Allowlist, Gleich-Origin-Prüfung) bereits vollständig in oauth/oidc.py und muss für den neuen Bedrohungsfall nur um zwei Fähigkeiten ergänzt werden, die dort fehlen, weil der bestehende Code hinter einem browsergebundenen Consent-Fluss steht: eine Abkühlzeit gegen die Verstärkung durch ein unbekanntes kid und ein Single-Flight gegen gleichzeitige Abrufe.

Die empfohlene Bauform ist eine Prüferkette statt eines sechsten Modus: der bestehende StoreTokenVerifier bleibt unverändert und wird zuerst gefragt, ein neuer ExchangeVerifier kommt nur zum Zug, wenn der Store None liefert und der Pfad eingeschaltet ist. Die Auswahl fällt dabei nicht über ein Try/Except, sondern über die Tokenform selbst: eigene Access-Tokens sind punktlose secrets.token_urlsafe-Werte, ein kompaktes JWS hat exakt zwei Punkte. Diese Weiche ist strukturell und nicht geheim, und sie garantiert, dass ein heute gültiges Token den neuen Code nie erreicht. Damit sind die entscheidungsunabhängigen Teile (JWKS-Herauslösung, Claim-Prüfung, Audience-Vergleich, Mapping-Profile, Kette, Konfiguration, Audit-Anschluss) vollständig ohne F13s vier ausstehende Antworten baubar; nur der Credential-Weg und die Golden-Fixture aus einem echten Beispiel-Token hängen extern.

Das größte Risiko liegt nicht in der Kryptografie, sondern in der Übertragung bestehender Annahmen auf eine neue Bedrohungslage: die Toleranzen und Nachladeregeln aus oidc.py sind für einen browsergebundenen Consent-Fluss richtig kalibriert und werden im unauthentisierten heißen Pfad jedes Werkzeugaufrufs zu einem vor-authentischen Verstärker, wenn sie unverändert übernommen werden. Ebenso gefährlich ist die Verwechslung von Anmeldename und kanonischem Principal beim Konto-Mapping, weil davon der Pausenschalter und die Audit-Kette abhängen, ohne dass ein bestehender Test das bemerken würde.

## Key Findings

### Recommended Stack

Keine neue Laufzeitabhängigkeit. PyJWT bleibt die einzige Bibliothek für Header, Signatur und Standard-Claims, aber die Untergrenze muss von >=2.13,<3 auf >=2.14,<3 steigen (Lock von 2.13.0 auf 2.14.0), weil diese Sicherheitsfreigabe fünf Befunde im JWKS-Pfad schließt, von denen drei den geerbten Code in oauth/oidc.py unmittelbar betreffen (unbegrenzter Neuabruf bei unbekanntem kid, Umleitungen bei PyJWKClient, unbehandelte Ausnahmen bei kaputten JWK-Einträgen). jwt.PyJWKClient wird trotzdem nicht benutzt, weil es synchron auf urllib gebaut ist und im ASGI-Server den Event-Loop blockieren würde; die vorhandene asynchrone JWKS-Schicht aus oidc.py wird stattdessen in ein eigenständiges oauth/jwks.py herausgelöst und von beiden Prüfpfaden geteilt.

**Kerntechnologien:**
- pyjwt[crypto] >=2.14,<3: Signatur- und Claim-Prüfung, bereits direkte Abhängigkeit und bereits von mcp 2.0.0 verlangt, die Anhebung kollidiert mit nichts.
- cryptography >=50,<51: Verifikation unter PyJWT, reiner Wheel-Neubau ohne API-Wechsel, im selben Lock-Schritt mitgezogen.
- httpx >=0.28,<0.29: JWKS- und Discovery-Abruf, Projektregel bleibt bestehen (eigener Code spricht httpx, nicht das transitive httpx2).
- mcp >=2.0,<3: trägt bereits einen fertigen SEP-990-Assertion-Grant-Andockpunkt (identity_assertion_enabled, exchange_identity_assertion), der als dokumentierter Zweitweg (Weg B, Token-Endpunkt) neben der direkten Bearer-Annahme (Weg A, Transportgrenze) offengehalten wird.
- Python 3.13 Standardbibliothek: asyncio.Lock für Single-Flight, time.monotonic für die Abkühlzeit, hmac.compare_digest für Konstant-Zeit-Vergleiche.

### Expected Features

**Must have (Launch v1.6, entscheidungsunabhängig baubar):**
- Fünfter Prüfpfad mit eigenem Schalter (NC_MCP_EXCHANGE_*), ab Werk aus, kein sechster Modus in select_mode.
- Issuer-Allowlist, JWKS-Cache mit Rotation, fail-closed, Algorithmen- und Schlüsseltyp-Allowlist (Wiederverwendung aus oauth/oidc.py).
- Standard-Claims iss, exp, nbf, iat, aud mit Clock-Skew-Toleranz und options={"require": [...]}.
- typ-Prüfung als Payload-Claim (Keycloak: Bearer im Claim-Satz, JWT im Header), ID-Tokens werden abgewiesen.
- Exakte Audience-Prüfung mit strict_aud, nicht check_resource_allowed.
- azp-Allowlist als Ersatz für das fehlende act (Keycloak Standard Token Exchange V2 kennt keine Delegationssemantik).
- Konfigurierbares Claim-Mapping auf den Principal, mindestens ein sub-basiertes und ein LDAP-taugliches Profil.
- Abweisung statt stiller Kontoanlage, umgekehrte Asymmetrie gegenüber dem bestehenden nachsichtigen Sweep-Code.
- Anschluss an die bestehende Audit-Kette inklusive der handelnden Partei (azp), unter den bestehenden Inhaltsverboten.

**Should have (nach F13-Antwort):**
- Golden-Fixture aus echtem Beispiel-Token und Realm-Export.
- Festgeschriebene Audience-Konvention samt Mandantennachweis.
- Trockenlauf-Kommando für Administratoren, Zwei-Konten-Negativbeweis gemessen statt behauptet.

**Defer (v2+):**
- act-Auswertung, sobald Keycloak Delegation liefert.
- Identity Chaining über Domänengrenzen.
- Optionale Introspection als ausdrücklich gewählter Zusatz, nie als Default.

### Architecture Approach

Der Exchange-Pfad wird eine Prüferkette (ChainedVerifier) hinter der bestehenden, unveränderten Transportgrenze (exapp/middleware.py), nicht ein sechster Modus in config.select_mode. Der Store-Prüfer läuft immer zuerst; ein neuer ExchangeVerifier wird nur erreicht, wenn kein Store-Treffer vorliegt und der Pfad konfiguriert ist, und die Auswahl fällt strukturell über die Tokenform (punktlos gegen zwei Punkte), nicht über einen Fallback-Versuch. Die JWKS-Logik wandert aus oidc.py in ein geteiltes oauth/jwks.py. Die eigentliche Architekturentscheidung, die der Stack nicht abnimmt, ist der Credential-Weg: AppAPI-Impersonation über APP_SECRET (nur ExApp-Betrieb, keine Provisionierung, macht die IdP-Signatur zum funktionalen Äquivalent des Instanzgeheimnisses) gegen eine vorab vom Nutzer erteilte, gespeicherte Autorisierung (beide Betriebsarten, kostet einen einmaligen Browser-Schritt, fügt keine neue Vollmacht hinzu). Beide Wege teilen rund achtzig Prozent des Codes; nur die letzte Zeile, die das Credential wählt, unterscheidet sich.

**Wesentliche Komponenten:**
1. oauth/jwks.py (neu, aus oidc.py herausgelöst): Abruf, Cache, Rotation, Abkühlzeit, Single-Flight, fail-closed.
2. oauth/exchange.py (neu): Signatur- und Claim-Prüfung, Audience-Vergleich, Mapping-Strategien, reine testbare Funktionen ohne Server-Bindung.
3. Prüferkette (oauth/verifier.py Ergänzung oder oauth/chain.py): Reihenfolge Store vor Exchange, Weiche über Tokenform, gemeinsames invalidate().
4. Credential-Zweig in deps.py: je nach Owner-Entscheidung ein neuer Impersonation-Zweig oder ein Store-Lesezugriff auf eine vorab gebundene Autorisierung.
5. Audit-Anschluss (audit/record.py, oauth/principal.py): wirkt bei korrekt hinterlegter OAuthIdentity automatisch, die handelnde Partei (azp) braucht ein eigenes, dokumentiertes Feld.

### Critical Pitfalls

1. Der fremde Prüfer wird zur Rückfallebene des eigenen (verify_token bekommt einen Zweig, der ein unbekanntes Token als JWT probiert) - vermeiden durch eine formbasierte Weiche vor jeder Prüfung, kein Try/Except, kein zweiter Versuch nach einem Fehlschlag.
2. Die Audience wird mit check_resource_allowed geprüft - das ist eine hierarchische Pfad-Präfixprüfung des SDK und für Keycloak-Client-Ids als Audience ungeeignet; stattdessen exakte Zeichenkettengleichheit plus strict_aud in PyJWT.
3. Ein unbekanntes kid wird zum Verstärker, weil oidc.py._key heute hinter einem browsergebundenen, ratenbegrenzten Consent-Fluss steht und im Exchange-Pfad direkt im unauthentisierten heißen Pfad landet; dazu nimmt oauth/throttle.py die MCP-Route bewusst vom Limit aus, was ab dem Exchange-Pfad nicht mehr stimmt - vermeiden durch Negativ-Karenz (Abkühlzeit), Single-Flight und eine eigene Throttle-Pfadklasse für Ablehnungen.
4. Das getauschte Token beweist eine Identität, liefert aber kein Nextcloud-Geheimnis - die Credential-Frage muss als P0-Owner-Entscheidung vor dem ersten Code stehen, sonst landet der Bau automatisch bei Impersonation über ein Dienstkonto oder bei stiller Credential-Anlage.
5. Der Claim wird zum Anmeldenamen statt zum Principal - Pausenschalter und Audit-Kette hängen am kanonischen Principal (oauth/principal.py), nicht am Anmeldenamen; ein falsches Mapping bricht den Pausenschalter unbemerkt und spaltet die Audit-Kette.

## Implications for Roadmap

Basierend auf der Architekturempfehlung (Teil 8 der Architektur-Recherche) und dem Pitfall-zu-Phase-Mapping ergibt sich eine Reihenfolge mit einer vorgelagerten Owner-Entscheidung und sechs Bauphasen.

### Phase 0: Credential-Entscheidung
Rationale: Die Frage, womit ein gemapptes Konto gegenüber Nextcloud handelt (AppAPI-Impersonation gegen vorab gebundene Autorisierung), ist eine Vollmachtsfrage und keine technische Frage. Sie bestimmt die Form von deps.py und muss vor jeder Codezeile stehen, sonst entsteht automatisch der Dienstkonto-Durchgriff, den dieses Projekt in v1.5 für OpenProject bereits ausgeschlossen hat.
Delivers: Ein schriftlicher Owner-Entscheid, kein Code.
Avoids: Pitfall 8 (Credential-Herkunft).

### Phase 1: JWKS-Herauslösung
Rationale: Ohne diesen Schritt entstehen zwei JWKS-Implementierungen im selben Repo, und die zweite erbt die Härtungen der ersten nicht. Verhaltensgleiche Umstellung, durch bestehende Unit-Tests gedeckt, deshalb zuerst und risikoarm.
Delivers: oauth/jwks.py, OidcClient darauf umgestellt.
Uses: PyJWT >=2.14,<3, cryptography >=50,<51.

### Phase 2: Fremder Tokenprüfer
Rationale: Signatur- und Claim-Prüfung, Audience-Vergleich und Mapping-Profile lassen sich vollständig als freistehende, testbare Funktionen ohne F13-Antworten bauen.
Delivers: oauth/exchange.py mit Algorithmus-Allowlist, typ-Prüfung, exaktem Audience-Vergleich, azp-Allowlist, Mapping-Strategien.
Avoids: Pitfalls 2, 3, 4, 6, 9 (Audience-Präfix, Issuer/kid-Vermischung, Algorithmus-Confusion, Clock-Skew, ID-Token als Access-Token).

### Phase 3: Konfiguration und Schalter
Rationale: Eigener Namensraum NC_MCP_EXCHANGE_*, ab Werk aus, Startvalidierung statt stiller Halbkonfiguration.
Delivers: config.exchange_settings, Fail-Fast beim Start bei halber Konfiguration.
Avoids: Pitfall 11 (Ersteinschaltschutz nur im Text).

### Phase 4: Kette und Einbau
Rationale: Erst hier trifft der neue Pfad auf die Transportgrenze, an genau zwei Zeilen (entry_exapp.py, entry_oauth.py); middleware.py bleibt unangetastet.
Delivers: ChainedVerifier, Weiche über Tokenform, gemeinsames invalidate().
Avoids: Pitfall 1 (Rückfallebene), Pitfall 13 (fail-closed wird fail-everything), Pitfall 7 teilweise (Pausenschalter greift automatisch, weil derselbe Request-State-Mechanismus gilt).

### Phase 5: Credential-Weg
Rationale: Erst hier wird der Pfad betriebsfähig, abhängig vom Owner-Entscheid aus Phase 0.
Delivers: Je nach Entscheidung ein deps.py-Impersonation-Zweig oder ein Store-Lesezugriff plus Provisionierungsroute.
Avoids: Pitfall 7 vollständig (Anmeldename gegen Principal), Pitfall 8 wird umgesetzt statt nur entschieden.

### Phase 6: Audit-Anschluss, Härtung, Nachweis
Rationale: Audit-Zeile mit handelnder Partei, Lasttest gegen JWKS-Verstärkung, Log-Gate gegen Claim-Leaks, Doku und Trockenlauf-Kommando.
Delivers: Erweiterte Audit-Zeile, gemessene Karenz/Single-Flight, docs/token-exchange.md.
Avoids: Pitfall 12 (Delegationskette fehlt im Audit), Pitfall 10 (gesprächige Ablehnung als Orakel), Pitfall 5 (Last).

### Phase Ordering Rationale

- P0 steht vor allem anderen, weil sie die Form der deps.py-Änderung in P5 bestimmt, aber die Phasen P1 bis P4 sind davon unabhängig baubar (Zusage der Spec-Note, von der Architektur-Recherche bestätigt).
- P1 vor P2, weil eine zweite JWKS-Implementierung genau die Sorte Doppelpflege erzeugt, an der später eine Sicherheitslücke nur in einer der zwei Kopien geschlossen wird.
- P2 und P3 vor P4, weil die Kette die Feldnamen der Konfiguration und die Form des Prüfers bereits kennen muss.
- P5 zuletzt vor der Härtung, weil erst mit einem Credential-Weg ein Ende-zu-Ende-Test überhaupt einen echten Nextcloud-Aufruf auslöst.
- Vier der zwölf kritischen Pitfalls (1, 2, 3, 9) sind reine P1/P2-Fragen und lassen sich vollständig gegen selbst erzeugte Testschlüssel verifizieren, ohne auf F13 zu warten.

### Research Flags

Phasen, die während der Planung wahrscheinlich tiefere Recherche brauchen:
- Phase 5 (Credential-Weg): Die Provisionierung einer vorab gebundenen Autorisierung für viele Konten (occ user:auth-tokens:add) ist nur dokumentiert, nicht gemessen (MEDIUM confidence in ARCHITECTURE.md, Teil 3, Weg B).
- Phase 6 (Nachweis): Header-Größe eines echten Keycloak-Tokens über HaRP ist nicht gemessen; Keycloak-Feldrealität (preferred_username in getauschten Tokens, LDAP-Bindung der F13-Instanzen) bleibt offen, bis das Beispiel-Token vorliegt.

Phasen mit etabliertem Muster (research-phase überspringbar):
- Phase 1 (JWKS-Herauslösung): reine Umstellung ohne Verhaltensänderung, durch bestehende Tests gedeckt.
- Phase 2 (Fremder Tokenprüfer): RFC 8725, PyJWT-Quelltext und der bestehende oidc.py-Code liefern das vollständige Muster.
- Phase 3 (Konfiguration): folgt exakt dem Muster von config.oauth_configured.

## Confidence Assessment

| Area | Confidence | Notes |
|------|------------|-------|
| Stack | HIGH | PyPI-JSON-API, PyJWT-Changelog und -Sicherheitshinweise, installierter Quelltext von jwt/jwks_client.py (zwei Fassungen) und der eigene Quelltext direkt gelesen; MEDIUM nur für die Keycloak-Claim-Konventionen, bis das Beispiel-Token vorliegt |
| Features | HIGH für Keycloak- und MCP-Spec-Verhalten (offizielle Doku, GitHub-Issue-API), MEDIUM für die Marktpraxis vergleichbarer MCP-Gateways (Herstellerblogs) | Vier offene Punkte hängen ausdrücklich an F13-Antworten (aud-Wert, preferred_username-Verfügbarkeit, LDAP-Bindung, AppAPI-Vollständigkeit auf LDAP) |
| Architecture | HIGH für die eigene Codebasis (Datei und Zeile gelesen) und check_resource_allowed (SDK-Quellcode gelesen), HIGH für Keycloak Standard Token Exchange V2 (offizielle Doku über Context7), MEDIUM für occ user:auth-tokens:add ohne Nutzerpasswort (nicht gemessen) | Die Korrektur "cimd.py zu oidc.py" und die Aussage "resource-Parameter noch nicht unterstützt" sind belegte Korrekturen an der F13-Spec-Note |
| Pitfalls | HIGH für den Code-Stand dieses Repos und PyJWT/MCP-SDK-Verhalten (installierter Quelltext gelesen), MEDIUM-HIGH für Keycloak-Feldverhalten (offizielle Doku plus Blog, nicht gegen eine Instanz gemessen), LOW für alles, was von F13s vier Antworten abhängt | Bewusst als Entscheidungsfläche markiert, nicht als Befund |

**Overall confidence:** HIGH für die entscheidungsunabhängigen Teile (P1 bis P4), MEDIUM für alles, was an F13s vier Antworten und der Owner-Entscheidung aus P0 hängt.

### Gaps to Address

- Credential-Weg (P0): kein Recherche-Gap, sondern eine ausstehende Owner-Entscheidung; beide Wege sind mit Preis und Kosten in ARCHITECTURE.md Teil 3 tabellarisch gegenübergestellt und sollten vor Phase 5 entschieden werden.
- Beispiel-Token und Realm-Export (F13-Entscheidung 3): ohne sie wird gegen selbst gebaute Tokens getestet, die genau die erwartete Struktur haben; Gegenmaßnahme ist ein lokaler Keycloak im Testaufbau (nextcloud-docker-dev bringt einen mit) plus ein bewusst danebenliegender Testkorpus.
- Audience-Konvention (F13-Entscheidung 1): STACK.md und ARCHITECTURE.md liefern übereinstimmend eine Vorzugsantwort (Keycloak-Client-Id je Connector-Instanz, Default die eigene Resource-URL), die vor dem zweiten Treffen in die Spec-Note gehört, aber vom Owner/F13 noch bestätigt werden muss.
- Header-Größe über HaRP: nicht gemessen; ein Keycloak-Token ist typischerweise ein bis vier Kilobyte groß gegenüber den heutigen kurzen Tokens dieses Servers, vor dem ersten Durchstich messen.
- Abgewiesene Exchange-Versuche im Audit-Log: heute konstruktionsbedingt unsichtbar, weil der Recorder erst nach erfolgreicher Prüfung greift; eigener kleiner Roadmap-Punkt außerhalb dieses Meilensteins.

## Sources

### Primary (HIGH confidence)
- Eigener Quelltext, direkt gelesen: src/mcp_connector/oauth/oidc.py, verifier.py, principal.py, throttle.py, store.py, connect.py, config.py, deps.py, exapp/middleware.py, audit/record.py, audit/store.py, audit/accounts.py, entry_exapp.py, entry_oauth.py, server/__init__.py, pyproject.toml
- PyPI JSON-API (18.09.2026): pyjwt 2.14.0, cryptography 50.0.1, httpx 0.28.1, mcp 2.0.0 requires_dist
- PyJWT-Changelog und Sicherheitshinweise GHSA-2gx3-rcp4-g85q, GHSA-9v7f-9g4p-ffgj, GHSA-jq35-7prp-9v3f, GHSA-fhv5-28vv-h8m8, GHSA-8wjv-2p76-3863; installierter PyJWT-Quelltext jwt/api_jwt.py, jwt/algorithms.py, jwt/jwks_client.py
- MCP-SDK-Quelltext (installiert, 2.0.0): mcp/shared/auth_utils.py (check_resource_allowed), mcp/server/auth/handlers/token.py, mcp/server/auth/provider.py
- Keycloak offizielle Doku über Context7 (/keycloak/keycloak): docs/guides/securing-apps/token-exchange.adoc, Blog "Standard Token Exchange is now officially supported in Keycloak 26.2"
- RFC 8693, RFC 8707, RFC 8725, RFC 9068, OpenID Connect Core 1.0 Abschnitt 5.7, MCP-Spezifikation (Authorization, Security Considerations, Authorization Server Discovery)

### Secondary (MEDIUM confidence)
- keycloak/keycloak GitHub-Issues/PRs: #14355, #37367, #38279, #46763, #37573, #36696, Discussion #19419
- Community-Praxis vergleichbarer MCP-Gateways (agentgateway, Envoy AI Gateway, TrueFoundry, IBM mcp-context-forge), Herstellerblogs
- Nextcloud user_oidc-LDAP-Mapping: help.nextcloud.com, GitHub-Issues nextcloud/user_saml#406, nextcloud/server#55284
- Nextcloud occ-Handbuch zu user:auth-tokens:add

### Tertiary (LOW confidence)
- Alles, was von F13s vier ausstehenden Entscheidungen abhängt (Audience-Wert, Konto-Claim, Beispiel-Token, Exchange-Ziel-Eintrag): bewusst als Entscheidungsfläche markiert, nicht als Befund

---
*Research completed: 2026-09-18*
*Ready for roadmap: yes*
