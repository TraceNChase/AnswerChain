Kvalitet före hastighet. Leverera stabil kod med verifierade beteenden.

Minimala ändringar. Skriv inte mer kod än absolut nödvändigt.

Bevara funktionalitet. Existerande flöden får inte gå sönder.

Air-gapped antagande. Ingen nätverksåtkomst. Undvik beroenden som kräver internet.

Observabilitet först. Varje ändring ska öka spårbarheten i debug-loggarna.

2. Obligatorisk process per uppdatering

Föranalys av loggar

Läs senaste JSON-filerna i src\logs\debug_logs. Identifiera fel, varningar, timing, edge cases.

Extrahera aktiva feature-flaggor, konfiguration och senaste stacktraces.

Ändringsplan

Definiera mål, antaganden, påverkan på publika API:er och datakontrakt.

Specificera minsta möjliga ingrepp och rollback-strategi.

Koduppdatering

Implementera endast nödvändiga rader.

Synkron uppdatering av loggning: alla nya code paths loggar strukturerat (JSON Lines).

Om generated_security_hardening.py saknas: skapa den i src\modules med idempotenta hjälpfunktioner för härdning (se §4).

Verifiering

Kör lokala sanity-tester och simulera användarflöden som framgår av loggarna.

Kör regressioner mot berörda moduler.

Läs nya debug-loggar och bekräfta att fel och edge cases nu loggas tydligt.

Resultat

Bekräfta att inga existerande funktioner degraderats.

Säkerställ att nya problem skulle bli “synliga” i loggarna med klara fält.

3. Loggningsstandard (måste)

Format: JSON Lines (en rad per händelse).

Fält (minimikrav):

ts (ISO-8601 lokal tid), level (DEBUG|INFO|WARN|ERROR), event, module, func, line, corr_id (UUIDv4),
user_sim (true/false vid simulering), inputs_redacted (bool), elapsed_ms, status, details (objekt).

Krav:

Allt nytt loggas. Inga tysta paths.

Säker maskning: hemligheter och känsliga fält redigeras, men skriv tydligt att maskning har skett.

Fel loggas med stacktrace och kategoriserad error_kind samt stabil error_code.

Varje ändring ökar diagnosvärdet: tydligare orsaker, åtgärdsförslag i details.hint.

4. Säkerhetshärdning (modul generated_security_hardening.py)

Skapas endast om den inte finns. Innehållsansvar:

Validering & sanering: filvägar, miljövariabler, CLI-argument, JSON-inmatning. Whitelist för kataloger.

Rättigheter: kontroller av fil- och katalogtillstånd, försvar mot överskrivningar, atomiska skrivningar.

Konfiguration: säkra default-värden, strict mode, feature-flaggor, togglar för “dry-run” och “simulation”.

Determinism: frö-hantering för RNG vid tester.

Integritet: SHA-256 kontrollsummor för kritiska artefakter.

Logg-helpers: skapande av JSON-logger med fälten i §3 och corr_id-propagering.

Idempotens: alla operationer kan köras flera gånger utan sidoeffekter.

Offline-garanti: inga nätverksanrop; skydd mot oavsiktlig I/O utanför whitelists.

5. Testkrav