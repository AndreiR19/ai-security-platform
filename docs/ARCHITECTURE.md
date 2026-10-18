# Arhitectura proiectului

## 1. Ideea

Proiectul transformă **loguri brute** în **alerte justificate cu dovezi**. Într-o etapă ulterioară, un model AI ajută un analist să înțeleagă alertele. Un SOC real rezolvă aceeași problemă, la scară mare.

```
auth.log → [parser] → AuthEvent → [reguli] → Alert → [DB] → [API] → [AI analyst] → dashboard
 (haos)     curăță     (ordine)    detectează   dovezi   stocare   expune    explică
```

## 2. Principiul central: separarea responsabilităților

Fiecare componentă știe un singur lucru și comunică cu vecinii printr-un format fix.

| Componentă | Știe | Nu știe |
|---|---|---|
| Parser | cum arată un log SSH | ce este un atac |
| Reguli | ce este un atac | formatul logului brut, stocarea |
| Baza de date | cum se păstrează datele | ce înseamnă ele |
| AI analyst | cum se explică o alertă | cum a fost detectată |

Consecință: o sursă nouă de loguri (de exemplu un firewall) cere **doar un parser nou**. Regulile, baza de date și API-ul rămân neschimbate, pentru că toate lucrează cu `AuthEvent`, nu cu text brut.

## 3. Structura repo-ului

| Cale | Rol | Concepte |
|---|---|---|
| `src/ingestion/models.py` | clasa `AuthEvent` | schemă, validare la graniță, imutabilitate, timp cu fus orar |
| `src/ingestion/parser.py` | `parse_line`, `parse_lines`, `parse_file` | regex, normalizare, input ostil |
| `src/detection/models.py` | clasa `Alert` | auditabilitate, dovezi, separarea faptelor de concluzii |
| `src/detection/rules.py` | regulile de detecție | fereastră glisantă, praguri |
| `src/database/` | stocarea evenimentelor și alertelor | persistență (PostgreSQL) |
| `src/api/` | expunerea datelor | API REST (FastAPI) |
| `src/ai_analyst/` | rezumarea și explicarea alertelor | integrare LLM, prompt injection |
| `scripts/generate_logs.py` | generator de loguri sintetice etichetate | date de test, *ground truth*, determinism |
| `tests/unit/` | teste pe componente izolate | TDD, `parametrize`, testarea limitelor |
| `tests/integration/` | teste pe lanțul întreg | integrare, regresii |
| `data/samples/` | loguri de exemplu și etichetele lor | reproductibilitate |
| `.github/workflows/` | pipeline CI | automatizare, scanare de securitate |
| `Dockerfile`, `compose.yaml` | împachetarea aplicației | containere, izolare |
| `pyproject.toml` | configurația uneltelor (pytest, ruff) | reproductibilitate |
| `requirements.txt` | dependențele | medii izolate (`venv`) |

## 4. Fluxul de date, pas cu pas

1. **Ingestie.** Parserul primește o linie brută și un an (logurile syslog nu conțin anul). Dacă linia nu este o autentificare SSH recunoscută sau conține valori invalide, întoarce `None`.
2. **Normalizare.** Datele devin un `AuthEvent`: `timestamp` (UTC, cu fus orar), `source_ip` (adresă validată), `username` (lungime limitată), `outcome` (`success` sau `failure`) și `raw` (linia originală, păstrată ca dovadă).
3. **Detecție.** Regulile grupează evenimentele (după IP, după cont) și le analizează pe ferestre de timp. O regulă produce un `Alert` care conține identificatorul regulii, severitatea, entitatea afectată, evenimentele-dovadă și maparea MITRE ATT&CK.
4. **Persistență și acces.** Alertele și evenimentele se stochează și se expun printr-un API.
5. **Analiză AI.** Un model rezumă alertele și propune pași de investigare. Concluziile modelului sunt păstrate separat de faptele observate.

## 5. Conceptele-cheie

**Normalizare.** Aducerea datelor din surse diferite la o formă comună. `AuthEvent` este această formă.

**Validare la graniță.** Datele se verifică o singură dată, la intrare. Un `AuthEvent` existent este considerat corect de restul codului. Pydantic aplică regulile (tipuri, lungimi, adrese IP valide, fus orar obligatoriu).

**Input ostil.** Logurile conțin text controlat de atacator (nume de utilizator, adrese). Parserul limitează lungimile, validează adresele și respinge liniile nerecunoscute. Același principiu stă la baza riscului de *prompt injection*: un câmp din log poate conține instrucțiuni pentru un LLM.

**Parsare strictă.** Expresia regulată este ancorată (`^...$`): o linie fie se potrivește integral, fie este ignorată. Regex-ul verifică forma liniei, iar modelul Pydantic verifică valorile.

**Fereastră glisantă.** Baza detecției: „N evenimente în T minute". Evenimentele se grupează (de exemplu după IP), se ordonează în timp și se numără cele care încap într-un interval. De aceea toate timestamp-urile sunt UTC și cu fus orar explicit.

**Cele trei reguli de pornire:**

| Regulă | Tipar | Ce se numără | MITRE ATT&CK |
|---|---|---|---|
| Brute force | multe eșecuri, un IP, un cont | eșecuri per (IP, cont) | T1110.001 |
| Password spraying | puține încercări, un IP, multe conturi | conturi distincte per IP | T1110.003 |
| Succes după eșecuri | serie de eșecuri urmată de un succes | succes după o serie de eșecuri | T1110 |

**Auditabilitate.** O alertă fără dovezi este o părere. Fiecare alertă păstrează evenimentele care au declanșat-o, inclusiv linia originală (`raw`), astfel încât orice concluzie poate fi verificată.

**False positives și false negatives.** Un prag prea mic alertează pe utilizatori legitimi, unul prea mare ratează atacuri. Compromisul se măsoară:

- *precision*: din alertele generate, câte corespund unor atacuri reale
- *recall*: din atacurile reale, câte au fost detectate

Măsurarea cere date etichetate, pe care le produce generatorul sintetic.

**TDD.** Testele se scriu înaintea codului: testul pică, apoi se scrie implementarea până trece. Testele funcționează ca specificație.

## 6. Etapele dezvoltării

1. **Fundament:** parser, modele, reguli de detecție, teste unitare, date sintetice.
2. **CI:** GitHub Actions rulează testele, `ruff` și scanări de dependențe la fiecare push și pull request.
3. **Containere:** Docker și Compose pentru aplicație și baza de date, rulare pe Ubuntu Server.
4. **Integrare AI:** rezumarea alertelor, teste de prompt injection, comparația cu detecția pe reguli.
5. **Monitorizare și hardening:** metrici, threat modeling, securizarea containerelor.

Fiecare etapă se construiește peste cea anterioară, fără să o rescrie. Din acest motiv, fundamentul (formatul `AuthEvent` și separarea componentelor) este partea cea mai importantă.

## 7. Limite și reguli de siguranță

- Se folosesc exclusiv date sintetice sau loguri dintr-un laborator autorizat.
- Sistemul nu se conectează la infrastructură reală.
- Nu se automatizează blocarea adreselor IP înainte ca detecția să fie validată riguros pe metrici.
