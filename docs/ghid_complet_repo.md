# 🔐 Ghid Complet — AI Security Operations Platform

Acest document explică **fiecare concept** din repo, de la structura de foldere până la fiecare linie de cod. E scris ca să înțelegi nu doar *ce* face codul, ci și *de ce* e făcut așa.

---

## Cuprins

1. [Ce face proiectul](#1-ce-face-proiectul)
2. [Structura proiectului — de ce arată așa](#2-structura-proiectului)
3. [Fișierele de configurare](#3-fișierele-de-configurare)
4. [Modelul de date — `models.py`](#4-modelul-de-date)
5. [Parserul — `parser.py`](#5-parserul)
6. [Generatorul de loguri — `generate_logs.py`](#6-generatorul-de-loguri)
7. [Pachetul `__init__.py`](#7-pachetul-initpy)
8. [Testele unitare](#8-testele-unitare)
9. [Concepte de programare generală](#9-concepte-de-programare-generala)
10. [Concepte de securitate](#10-concepte-de-securitate)

---

## 1. Ce face proiectul

Proiectul este o **platformă de securitate cibernetică** (un mini-SOC — Security Operations Center). Scopul:

```
Loguri brute → Parsare → Evenimente structurate → Reguli de detecție → Alerte → Analiză AI
```

Imaginează-ți un server Linux care rulează SSH (un mod prin care te conectezi la distanță pe acel server). De fiecare dată când cineva încearcă să se logheze, serverul scrie o linie într-un fișier numit `auth.log`. Linia arată așa:

```
Oct  1 03:12:05 srv01 sshd[2211]: Failed password for root from 203.0.113.5 port 41022 ssh2
```

Un atacator care ghicește parole trimite **sute** de astfel de încercări. Proiectul tău:
1. **Citește** aceste loguri (ingestion/parser)
2. **Le transformă** în obiecte Python structurate (ingestion/models)
3. **Detectează** tipare de atac (detection — în plan)
4. **Alertează** analistul (alerting — în plan)

---

## 2. Structura proiectului

```
AISOP/
├── .gitignore              ← fișiere pe care Git le ignoră
├── .venv/                  ← mediul virtual Python (nu e în Git)
├── README.md               ← documentația principală
├── pyproject.toml          ← configurare pytest + ruff
├── requirements.txt        ← lista de librării necesare
│
├── src/                    ← CODUL SURSĂ
│   ├── ingestion/          ← modulul care „înghite" logurile
│   │   ├── __init__.py     ← face modulul importabil
│   │   ├── models.py       ← definește AuthEvent (structura datelor)
│   │   └── parser.py       ← transformă text brut în AuthEvent
│   └── detection/          ← modulul de detecție (gol deocamdată)
│
├── scripts/                ← scripturi utilitare
│   ├── __init__.py         ← face scripts importabil ca modul
│   └── generate_logs.py    ← generează loguri false pentru testare
│
├── tests/                  ← TESTE
│   └── unit/               ← teste pe componente individuale
│       ├── test_models.py  ← testează AuthEvent
│       ├── test_parser.py  ← testează parserul
│       └── test_generator.py ← testează generatorul de loguri
│
├── data/
│   └── samples/            ← loguri de exemplu (gol deocamdată)
│
└── docs/
    └── ARCHITECTURE.md     ← documentul de arhitectură
```

### De ce există foldere separate?

**Separarea responsabilităților** (Separation of Concerns) — cel mai important principiu în programare. Fiecare folder/modul știe un singur lucru:
- `ingestion` știe cum arată un log SSH → nu știe ce e un atac
- `detection` știe ce e un atac → nu știe cum arată logul brut
- `scripts` generează date de test → nu detectează nimic

**Beneficiul:** dacă vrei să adaugi loguri de la un firewall, scrii **doar** un parser nou. Restul codului rămâne neschimbat.

---

## 3. Fișierele de configurare

### [`.gitignore`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/.gitignore)

```gitignore
__pycache__
.pytest.cache
.venv
```

| Linie | Ce face |
|---|---|
| `__pycache__` | Python compilează fișierele `.py` în bytecode (`.pyc`) și le pune în `__pycache__/`. Sunt generate automat, nu trebuie versionate. |
| `.pytest.cache` | Pytest își salvează informații între rulări (ce test a picat ultima dată, etc.). Nu e cod, e cache temporar. |
| `.venv` | Mediul virtual Python. Conține copii locale ale librăriilor. E specific fiecărei mașini, nu se pune în Git. |

**Concept: `.gitignore`** — un fișier special citit de Git. Orice fișier/folder care se potrivește cu un pattern din `.gitignore` nu va fi urmărit de Git. E crucial ca să nu trimiți pe GitHub fișiere generate, secrete, sau dependențe voluminoase.

---

### [`requirements.txt`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/requirements.txt)

```
pydantic
pytest
ruff
```

| Librărie | Rol |
|---|---|
| **pydantic** | Validare de date. Verifică automat că un câmp are tipul corect (IP valid, string de maxim 64 de caractere, etc.) |
| **pytest** | Framework de testare. Rulezi `pytest` și el găsește toate fișierele `test_*.py`, le execută, și-ți arată ce a trecut și ce a picat. |
| **ruff** | Linter + formatter. Scanează codul pentru erori stilistice și potențiale bug-uri. E ca un „spell checker" pentru cod. |

**Concept: `requirements.txt`** — lista de dependențe ale proiectului. Când cineva clonează repo-ul, rulează `pip install -r requirements.txt` și primește exact librăriile necesare. E un fișier de convenție în ecosistemul Python.

**Concept: `pip`** — managerul de pachete Python. Descarcă librării de pe PyPI (Python Package Index), le instalează, și gestionează dependențele.

**Concept: Virtual Environment (`.venv`)** — un folder izolat unde se instalează librăriile. Fără el, toate proiectele tale ar folosi aceleași librării la nivel global, ceea ce creează conflicte de versiuni. Cu `.venv`, fiecare proiect are propriile versiuni.

---

### [`pyproject.toml`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/pyproject.toml)

```toml
[tool.pytest.ini_options]
pythonpath = ["."]
testpaths = ["tests"]
```

| Cheie | Ce face |
|---|---|
| `[tool.pytest.ini_options]` | Secțiune de configurare specifică pentru `pytest`. Formatul TOML folosește `[]` pentru a defini secțiuni (tabele). |
| `pythonpath = ["."]` | Spune pytest-ului: „adaugă directorul curent la calea de import Python". Fără asta, `from src.ingestion.models import AuthEvent` nu ar funcționa din teste, deoarece Python nu ar ști unde să caute `src`. |
| `testpaths = ["tests"]` | Spune pytest-ului: „caută teste doar în folderul `tests/`". Fără asta, pytest ar căuta în tot proiectul. |

**Concept: `pyproject.toml`** — fișierul standard modern (PEP 518/621) pentru configurarea proiectelor Python. Înlocuiește `setup.py`, `setup.cfg`, `pytest.ini`, etc. Toate uneltele (pytest, ruff, black, mypy) citesc din el.

**Concept: TOML** — un format de configurare (Tom's Obvious Minimal Language). E ușor de citit de oameni și de mașini. Folosește `[secțiuni]`, `chei = valori`, și liste cu `[„a", „b"]`.

**Concept: `pythonpath`** — Python caută module de importat într-o listă de directoare numită `sys.path`. `pythonpath = ["."]` adaugă rădăcina proiectului în această listă, ca importurile din teste să funcționeze.

---

## 4. Modelul de date

### [`src/ingestion/models.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/src/ingestion/models.py)

```python
from typing import Literal  # 1
from pydantic import AwareDatetime, BaseModel, ConfigDict, IPvAnyAddress, Field  # 2


class AuthEvent(BaseModel):  # 3
    model_config = ConfigDict(frozen=True)  # 4

    timestamp: AwareDatetime  # 5
    source_ip: IPvAnyAddress  # 6
    username: str = Field(min_length=1, max_length=64)  # 7
    outcome: Literal["success", "failure"]  # 8
    raw: str = Field(max_length=2048)  # 9
```

### Linie cu linie:

**Linia 1: `from typing import Literal`**
- `typing` e un modul standard Python care oferă tipuri avansate pentru *type hints*.
- `Literal["success", "failure"]` este un tip care acceptă **doar** valorile `"success"` sau `"failure"`. Orice alt string e o eroare de validare.
- **De ce:** Un câmp `outcome` de tip `str` ar permite orice text (`"maybe"`, `"dunno"`). Cu `Literal`, forțezi programul să accepte doar cele 2 valori posibile.

**Linia 2: `from pydantic import AwareDatetime, BaseModel, ConfigDict, IPvAnyAddress, Field`**
- **`BaseModel`** — clasa de bază Pydantic. Orice clasă care moștenește de la ea primește:
  - Validare automată la creare (constructorul verifică tipurile)
  - Serializare (`.model_dump()` → dict, `.model_dump_json()` → JSON)
  - Mesaje de eroare descriptive
- **`AwareDatetime`** — un `datetime` care **obligatoriu** conține informații despre fusul orar (timezone-aware). `datetime(2026, 10, 1, 3, 0, 0)` e **naiv** (fără fus orar) și e RESPINS. `datetime(2026, 10, 1, 3, 0, 0, tzinfo=timezone.utc)` e **aware** și e ACCEPTAT.
  - **De ce contează:** Dacă un server din Tokyo scrie `03:00` și altul din București scrie `03:00`, fără fus orar nu știi dacă e vorba de aceeași secundă. Într-un SOC, ordinea exactă a evenimentelor e critică.
- **`IPvAnyAddress`** — acceptă orice adresă IP validă (IPv4 sau IPv6). Respinge text arbitrar (`"not-an-ip"` → eroare).
- **`ConfigDict`** — un dicționar tipizat pentru configurarea comportamentului modelului.
- **`Field`** — permite adăugarea de constrângeri pe câmpuri (lungime minimă/maximă, valori implicite, descriere, etc.).

**Linia 3: `class AuthEvent(BaseModel):`**
- Definește o clasă numită `AuthEvent` care **moștenește** de la `BaseModel`.
- **Concept: Moștenire (Inheritance)** — `AuthEvent` primește automat tot ce știe `BaseModel` (validare, serializare, etc.) și adaugă câmpurile sale specifice.
- **Concept: Clasă (Class)** — un șablon care definește structura și comportamentul unui obiect. `AuthEvent` definește ce câmpuri are un eveniment de autentificare.

**Linia 4: `model_config = ConfigDict(frozen = True)`**
- **`frozen = True`** face obiectul **imutabil** (nu se poate modifica după creare).
- După creare, `event.username = "hacker"` aruncă o eroare `ValidationError`.
- **De ce:** Un eveniment de securitate e o **dovadă** — un fapt observat. Dacă altcineva poate modifica câmpurile, dovada e compromisă. Imutabilitatea garantează integritatea.
- **Concept: Imutabilitate (Immutability)** — un obiect care nu poate fi schimbat după ce a fost creat. Avantaje: e mai sigur, poate fi partajat între thread-uri fără probleme, și previne bug-uri subtile unde o funcție modifică un obiect fără să știi.

**Linia 5: `timestamp: AwareDatetime`**
- Declară câmpul `timestamp` de tip `AwareDatetime`.
- **Concept: Type Hints** — Python e un limbaj cu tipare dinamic (nu forțează tipuri la compilare). Type hints sunt adnotări opționale (`variabila: tip`) care documentează ce tip de date e așteptat. Pydantic le folosește activ pentru validare.

**Linia 6: `source_ip: IPvAnyAddress`**
- Adresa IP de la care vine încercarea de autentificare. Pydantic o validează automat.
- **De ce IPvAnyAddress și nu str:** Un `str` ar permite `"hello"`. `IPvAnyAddress` garantează matematic că valoarea e o adresă IP validă.

**Linia 7: `username: str = Field(min_length = 1, max_length = 64)`**
- Un string de minim 1 caracter și maxim 64.
- `Field(...)` e o funcție Pydantic care adaugă validări extra peste tipul de bază.
- **De ce max 64:** Un username rezonabil nu are 10.000 de caractere. Fără limită, un atacator ar putea trimite un username enorm care consumă memorie.
- **De ce min 1:** Un username gol (`""`) nu are sens — e o eroare de parsare care a scăpat.
- **Concept: Validare la graniță** — datele sunt verificate **o singură dată**, la intrare. Odată ce un `AuthEvent` e creat, restul codului poate avea **încredere** că datele sunt valide, fără verificări repetitive.

**Linia 8: `outcome: Literal["success", "failure"]`**
- Autentificarea a reușit sau a eșuat. Nu există altă opțiune.

**Linia 9: `raw: str = Field(max_length = 2048)`**
- Linia originală din log, păstrată ca **dovadă**.
- **De ce se păstrează:** Dacă o alertă spune „IP 203.0.113.5 a încercat 50 de ori", analistul poate verifica linia originală. Fără `raw`, n-ai cum să verifici dacă parserul a interpretat corect.
- **De ce max 2048:** O linie de log normală are ~200 de caractere. 2048 e generos, dar previne un atac de tip „un log cu un megabyte de text pe o singură linie".

---

## 5. Parserul

### [`src/ingestion/parser.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/src/ingestion/parser.py)

```python
from collections.abc import Iterable  # 1
import re  # 2
from src.ingestion.models import AuthEvent  # 3
from datetime import datetime, timezone  # 4
from pydantic import ValidationError  # 5

_PATTERN = re.compile(  # 7
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "  # 8
    r"\S+ "  # 9
    r"sshd\[\d+\]: "  # 10
    r"(?P<kind>Failed|Accepted) password for "  # 11
    r"(?:invalid user )?"  # 12
    r"(?P<user>\S+) "  # 13
    r"from (?P<ip>\S+) "  # 14
    r"port \d+ ssh2$"  # 15
)  # 16

_OUTCOMES = {"Failed": "failure", "Accepted": "success"}  # 18


def parse_line(line: str, year: int) -> AuthEvent | None:  # 20
    line = line.rstrip("\n")  # 21
    match = _PATTERN.match(line)  # 22
    if match is None:  # 23
        return None  # 24
    try:  # 25
        ts_text = " ".join(match["ts"].split())  # 26
        timestamp = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")  # 27
        timestamp = timestamp.replace(tzinfo=timezone.utc)  # 28
        return AuthEvent(  # 29
            timestamp=timestamp,  # 30
            source_ip=match["ip"],  # 31
            username=match["user"],  # 32
            outcome=_OUTCOMES[match["kind"]],  # 33
            raw=line,  # 34
        )  # 35
    except (ValueError, ValidationError):  # 36
        return None  # 37


def parse_lines(lines: Iterable[str], year: int) -> list[AuthEvent]:  # 39
    events = []  # 40
    for line in lines:  # 41
        event = parse_line(line, year)  # 42
        if event is not None:  # 43
            events.append(event)  # 44
    return events  # 45


def parse_file(path: str, year: int) -> list[AuthEvent]:  # 47
    with open(path, encoding="UTF-8", errors="replace") as f:  # 48
        return parse_lines(f, year)  # 49
```

### Linie cu linie:

#### Importuri (liniile 1-5)

**Linia 1: `from collections.abc import Iterable`**
- `Iterable` e un tip abstract care spune: „orice obiect peste care poți itera cu `for`". Include liste, tuple, fișiere deschise, generatoare, etc.
- **De ce:** `parse_lines` acceptă orice iterabil, nu doar liste. Asta o face mai flexibilă — poți trimite un fișier deschis direct, fără să citești totul în memorie.
- **Concept: Abstract Base Class (ABC)** — o clasă care definește un **contract** (ce metode trebuie să ai) fără implementare. `Iterable` spune: „trebuie să ai metoda `__iter__`".

**Linia 2: `import re`**
- Modulul standard Python pentru **expresii regulate** (regular expressions / regex).

**Linia 3: `from src.ingestion.models import AuthEvent`**
- Importă clasa `AuthEvent` definită mai devreme. Parserul produce obiecte `AuthEvent`.

**Linia 4: `from datetime import datetime, timezone`**
- `datetime` — clasa pentru lucrul cu date și ore.
- `timezone` — oferă `timezone.utc`, fusul orar UTC.

**Linia 5: `from pydantic import ValidationError`**
- Excepția pe care Pydantic o aruncă când datele nu trec validarea.

---

#### Regex-ul (liniile 7-16)

```python
_PATTERN = re.compile(
    r"^(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2}) "
    r"\S+ "
    r"sshd\[\d+\]: "
    r"(?P<kind>Failed|Accepted) password for "
    r"(?:invalid user )?"
    r"(?P<user>\S+) "
    r"from (?P<ip>\S+) "
    r"port \d+ ssh2$"
)
```

**Concept: Expresii Regulate (Regex)** — un mini-limbaj pentru descrierea tiparelor în text. E extrem de puternic dar greu de citit. Hai să-l disecăm:

**`re.compile(...)`** — compilează regex-ul o singură dată și-l stochează. E mai eficient decât `re.match(pattern, text)` apelat repetat, deoarece compilarea se face doar la importul modulului.

**`_PATTERN`** — prefixul `_` e o convenție Python care spune „această variabilă e privată — nu e destinată importului din exterior". Nu e impusă de limbaj, dar e un semnal pentru alți programatori.

**`r"..."`** — **raw string**. În Python normal, `\n` înseamnă newline. În raw string, `\n` rămâne literalmente `\n` (backslash + n). Esențial pentru regex, care folosește intens backslash.

Acum, fiecare fragment al regex-ului:

| Fragment | Ce se potrivește | Exemplu |
|---|---|---|
| `^` | Începutul liniei. Ancora. | — |
| `(?P<ts>\w{3}\s+\d{1,2} \d{2}:\d{2}:\d{2})` | Timestamp-ul, salvat în grupul numit `ts` | `Oct  1 03:12:05` |
| `\w{3}` | Exact 3 caractere alfanumerice (luna prescurtată) | `Oct` |
| `\s+` | Unul sau mai multe spații (ziua sub 10 are spațiu extra) | ` ` sau `  ` |
| `\d{1,2}` | 1 sau 2 cifre (ziua lunii) | `1` sau `15` |
| `\d{2}:\d{2}:\d{2}` | Ora HH:MM:SS | `03:12:05` |
| `\S+` | Unul+ caractere non-whitespace (hostname-ul serverului) | `srv01` |
| `sshd\[\d+\]:` | Literal `sshd[` + cifre + `]:` — procesul SSH cu PID-ul | `sshd[2211]:` |
| `\[` și `\]` | Parantezele pătrate sunt caractere speciale în regex (definesc clase de caractere). `\[` le scapă (escape) ca să fie literale. | `[` și `]` |
| `(?P<kind>Failed\|Accepted)` | Grupul `kind` — exact `Failed` sau `Accepted` | `Failed` |
| `password for ` | Text literal | `password for ` |
| `(?:invalid user )?` | Opțional (sufixul `?`), grup non-capturat (`?:`) | `invalid user ` sau nimic |
| `(?P<user>\S+)` | Grupul `user` — username-ul (orice non-whitespace) | `root` |
| `from (?P<ip>\S+)` | `from ` + grupul `ip` | `from 203.0.113.5` |
| `port \d+ ssh2` | `port` + cifre + `ssh2` | `port 41022 ssh2` |
| `$` | Sfârșitul liniei. Ancora. | — |

**Concept: Grupuri cu Nume (`(?P<name>...)`)** — regex-ul nu doar se potrivește, ci și **extrage** secțiuni. `(?P<ts>...)` salvează conținutul potrivit sub cheia `"ts"`, accesibil cu `match["ts"]`.

**Concept: Ancorare (`^` și `$`)** — obligă potrivirea pe **toată** linia. Fără ele, regex-ul ar putea găsi un fragment în mijlocul unei linii irelevante, ceea ce ar fi periculos (un atacator ar putea injecta text care arată ca un log SSH în altă parte a logului).

**Concept: Grup Non-Capturat (`(?:...)`)** — `(invalid user )?` ar fi creat un grup capturat care ocupă un index. `(?:...)` spune „grupează dar nu captura" — e o optimizare.

---

#### Dicționarul de Mapping (linia 18)

```python
_OUTCOMES = {"Failed": "failure", "Accepted": "success"}
```

Transformă cuvintele din log în valorile `Literal` din model. Logul spune `Failed`, dar modelul așteaptă `failure`. Acest dicționar face maparea.

**De ce un dicționar, nu un `if`?** E mai curat, mai extensibil, și mai ușor de testat. Dacă apare un al treilea outcome, adaugi o linie, nu un `elif`.

---

#### Funcția `parse_line` (liniile 20-37)

```python
def parse_line(line: str, year: int) -> AuthEvent | None:
```

- **Semnătura:** primește o linie de text și un an, returnează `AuthEvent` sau `None`.
- **`-> AuthEvent | None`** — type hint care spune: funcția returnează fie un `AuthEvent` valid, fie `None` (dacă linia nu e un log SSH recunoscut sau are date invalide).
- **`|` (pipe)** — din Python 3.10, poți scrie `X | Y` în loc de `Union[X, Y]` pentru tipuri uniune.
- **De ce `year` e parametru:** Logurile syslog (formatul standard Linux) **nu conțin anul**. `Oct  1 03:12:05` ar putea fi din orice an. De aceea anul e un parametru explicit.

**Linia 21: `line = line.rstrip("\n")`**
- Elimină newline-ul de la sfârșitul liniei (dacă există). Când citești dintr-un fișier, fiecare linie vine cu `\n` la final, care ar deranja potrivirea regex (`$` nu se potrivește cu `\n`).
- **`rstrip`** — „right strip" — elimină caractere doar de la dreapta string-ului.

**Linia 22: `match = _PATTERN.match(line)`**
- Încearcă să potrivească regex-ul pe linie.
- **`.match()`** se potrivește de la **începutul** string-ului (nu caută în interior — e echivalent cu ancora `^`).
- Returnează un obiect `Match` dacă se potrivește, sau `None` dacă nu.

**Liniile 23-24:**
```python
if match is None:
    return None
```
- Dacă linia nu se potrivește cu tiparul SSH, returnează `None`. Linia e ignorată — nu e un eveniment de autentificare.
- **`is None`** vs **`== None`**: `is` verifică **identitatea** (exact același obiect în memorie), nu egalitatea. Pentru `None`, e practica recomandată.

**Linia 25: `try:`**
- Începe un bloc `try-except`. Dacă orice cod din `try` aruncă o excepție din tipurile specificate în `except`, execuția sare la blocul `except`.

**Linia 26: `ts_text = " ".join(match["ts"].split())`**
- **`match["ts"]`** — extrage textul capturat de grupul `ts` (ex: `"Oct  1 03:12:05"`).
- **`.split()`** — fără argumente, împarte string-ul la orice secvență de whitespace și elimină spațiile extra. `"Oct  1 03:12:05".split()` → `["Oct", "1", "03:12:05"]`.
- **`" ".join(...)`** — reunește lista cu un singur spațiu: `"Oct 1 03:12:05"`.
- **Scopul:** Normalizează spațiile multiple într-un singur spațiu. Logul syslog pune 2 spații înainte de zile cu o singură cifră (`Oct  1`), dar `datetime.strptime` așteaptă un singur spațiu. Aceasta rezolvă diferența.

**Linia 27: `timestamp = datetime.strptime(f"{year} {ts_text}", "%Y %b %d %H:%M:%S")`**
- **`f"..."`** — f-string (formatted string literal). Inserează valorile variabilelor direct în string: `f"{2026} Oct 1 03:12:05"` → `"2026 Oct 1 03:12:05"`.
- **`datetime.strptime(text, format)`** — „string parse time" — parsează un string conform unui format:
  - `%Y` → anul pe 4 cifre (`2026`)
  - `%b` → luna prescurtată (`Oct`)
  - `%d` → ziua (`1`)
  - `%H:%M:%S` → ora, minutul, secunda (`03:12:05`)
- Returnează un obiect `datetime`.

**Linia 28: `timestamp = timestamp.replace(tzinfo=timezone.utc)`**
- `strptime` creează un datetime **naiv** (fără fus orar). `.replace(tzinfo=timezone.utc)` îl face **aware**, etichetându-l ca UTC.
- **De ce UTC:** Toate timpurile sunt convertite la UTC ca să fie comparabile. Dacă o regulă de detecție caută „5 eșecuri în 10 minute", trebuie să compari momente din același fus orar.

**Liniile 29-35: Crearea `AuthEvent`**
```python
return AuthEvent(
    timestamp=timestamp,
    source_ip=match["ip"],
    username=match["user"],
    outcome=_OUTCOMES[match["kind"]],
    raw=line,
)
```
- Creează un `AuthEvent` cu datele extrase.
- **`match["ip"]`**, **`match["user"]`** — extrage valorile din grupurile regex.
- **`_OUTCOMES[match["kind"]]`** — mapează `"Failed"` → `"failure"`, `"Accepted"` → `"success"`.
- **`raw = line`** — salvează linia originală ca dovadă.
- Pydantic validează totul la acest punct: IP-ul, lungimea username-ului, fusul orar, etc.

**Liniile 36-37:**
```python
except (ValueError, ValidationError):
    return None
```
- **`ValueError`** — aruncată de `strptime` dacă data nu se parsează (ex: luna invalidă).
- **`ValidationError`** — aruncată de Pydantic dacă IP-ul e invalid, username-ul e prea lung, etc.
- **În ambele cazuri, returnează `None`** — linia e silențios ignorată.
- **Concept: Fail Silently vs. Fail Loudly** — aici e intenționat să eșueze silențios. Un log care nu se parsează nu e o eroare a programului — e un log care nu ne interesează. Dar într-un produs real, ai vrea să numeri câte linii au fost ignorate (metrici).

---

#### Funcția `parse_lines` (liniile 39-45)

```python
def parse_lines(lines: Iterable[str], year: int) -> list[AuthEvent]:
    events = []
    for line in lines:
        event = parse_line(line, year)
        if event is not None:
            events.append(event)
    return events
```

- Iterează peste orice iterabil de linii, parsează fiecare, și colectează doar cele valide.
- **`Iterable[str]`** — tipul spune: orice obiect care produce stringuri la iterare.
- **Pattern: Filter-Map** — conceptual, asta e un filter: din N linii, păstrează doar cele care produc `AuthEvent` valide.
- Ar putea fi rescrisă cu o **list comprehension**: `[e for line in lines if (e := parse_line(line, year)) is not None]`, dar versiunea explicită e mai clară pentru începători.

---

#### Funcția `parse_file` (liniile 47-49)

```python
def parse_file(path: str, year: int) -> list[AuthEvent]:
    with open(path, encoding="UTF-8", errors="replace") as f:
        return parse_lines(f, year)
```

- **`with open(...) as f:`** — **context manager**. Deschide fișierul și garantează că îl închide automat, chiar dacă apare o excepție. Fără `with`, ai putea uita `f.close()` și ai scurge file handles.
- **`encoding = "UTF-8"`** — specifică encoding-ul (cum sunt reprezentați octeții ca text). UTF-8 e standardul modern.
- **`errors = "replace"`** — dacă fișierul conține octeți invalizi pentru UTF-8, **îi înlocuiește** cu `�` în loc să arunce o excepție. Important: logurile reale pot conține octeți corupți (binare amestecate, encoding-uri mixte). Fără `errors="replace"`, parserul ar crăpa pe un singur octet invalid.
- **`f` ca iterabil** — un fișier deschis în Python e un iterabil care produce o linie la fiecare iterație. `parse_lines` îl acceptă datorită tipului `Iterable[str]`. **Avantajul:** fișierul nu e citit tot în memorie — e citit linie cu linie (lazy).

---

## 6. Generatorul de loguri

### [`scripts/generate_logs.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/scripts/generate_logs.py)

```python
from asyncio import events  # 1
import random  # 2
from datetime import datetime, timedelta, timezone  # 3

HOST = "srv01"  # 5
USERS = ["alice", "bob", "carol", "dave", "erin"]  # 6


def format_line(ts, outcome, username, ip, rng):  # 8
    verb = "Accepted" if outcome == "success" else "Failed"  # 9
    known = username in USERS or username == "root"  # 10
    invalid = "invalid user " if outcome == "failure" and not known else ""  # 11
    stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"  # 12
    pid = rng.randint(1000, 60000)  # 13
    port = rng.randint(30000, 65000)  # 14
    return (
        f"{stamp} {HOST} sshd[{pid}]: {verb} password for "  # 15
        f"{invalid}{username} from {ip} port {port} ssh2"
    )  # 16


def brute_force(rng, start, ip):  # 18
    events = []  # 19
    t = start  # 20
    for _ in range(rng.randint(30, 60)):  # 21
        t += timedelta(seconds=rng.randint(2, 4))  # 22
        events.append((t, format_line(t, "failure", "root", ip, rng)))  # 23
    label = {  # 24
        "scenario": "brute_force",  # 25
        "source_ip": ip,  # 26
        "start": events[0][0].isoformat(),  # 27
        "end": events[-1][0].isoformat(),  # 28
    }  # 29
    return events, label  # 30
```

### Linie cu linie:

**Linia 1: `from asyncio import events`**
- ⚠️ Acesta e un **import neutilizat** — probabil a rămas din autocompletare. `events` din `asyncio` nu e folosit. `ruff` (linter-ul) ar trebui să-l semnaleze.

**Linia 2: `import random`**
- Modulul standard Python pentru generare de numere aleatoare.

**Linia 3: `from datetime import datetime, timedelta, timezone`**
- **`timedelta`** — reprezintă o durată de timp. `timedelta(seconds=3)` = 3 secunde. Poți aduna un `datetime` cu un `timedelta` ca să avansezi în timp.

**Linia 5: `HOST = "srv01"`**
- **Constantă** (prin convenție — scrisă cu MAJUSCULE). Python nu are constante reale — oricine ar putea face `HOST = "x"` — dar MAJUSCULELE comunică: „nu modifica asta".

**Linia 6: `USERS = ["alice", "bob", "carol", "dave", "erin"]`**
- Lista utilizatorilor „legitimi". Dacă un username nu e aici și nu e `root`, SSH-ul real ar marca încercarea ca „invalid user".

---

#### `format_line` (liniile 8-16) — construiește o linie de log sintetică

**Linia 9: `verb = "Accepted" if outcome == "success" else "Failed"`**
- **Ternary operator** (expresie condițională inline). Echivalent cu:
  ```python
  if outcome == "success":
      verb = "Accepted"
  else:
      verb = "Failed"
  ```

**Linia 10: `known = username in USERS or username == "root"`**
- **`in`** — operatorul de apartenență. Verifică dacă `username` e în lista `USERS`.
- **`or`** — operator logic. Dacă prima condiție e adevărată, a doua nu mai e evaluată (**short-circuit evaluation**).

**Linia 11: `invalid = "invalid user " if outcome == "failure" and not known else ""`**
- SSH-ul real scrie `invalid user` doar dacă login-ul a eșuat ȘI username-ul nu există pe server. Generatorul reproduce acest comportament ca logurile sintetice să fie realiste.

**Linia 12: `stamp = f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S}"`**
- Format string complex:
  - `{ts:%b}` — luna prescurtată (`Oct`), folosind format-ul `datetime` în f-string
  - `{ts.day:>2}` — ziua, aliniată la dreapta pe 2 caractere. Ziua `1` devine ` 1` (cu spațiu în față), exact cum face syslog-ul real
  - `{ts:%H:%M:%S}` — ora `03:12:05`
- **Concept: Format Specs** — în f-string-uri, `:` separă valoarea de specificația de formatare. `>2` = aliniere la dreapta pe 2 caractere.

**Liniile 13-14:**
```python
pid = rng.randint(1000, 60000)
port = rng.randint(30000, 65000)
```
- Generează PID-uri și porturi aleatoare realiste.
- **`rng`** nu e `random.randint()` global, ci un **obiect `Random` injectat**. Asta permite **determinism** — dacă dai același seed, primești aceleași numere aleatoare. Esențial pentru teste reproductibile.
- **Concept: Dependency Injection** — în loc să folosească `random.randint()` direct (dependență globală, necontrolabilă), funcția primește un obiect `rng` ca parametru. Cine apelează funcția decide ce generator folosește. La testare, folosești `random.Random(42)` cu un seed fix.

**Liniile 15-16:**
```python
return (
    f"{stamp} {HOST} sshd[{pid}]: {verb} password for "
    f"{invalid}{username} from {ip} port {port} ssh2"
)
```
- Construiește linia finală de log, exact în formatul pe care parserul îl așteaptă.
- **Concept: Round-Trip** — generatorul produce loguri → parserul le parsează → testul verifică că rezultatul e corect. Dacă generatorul sau parserul au un bug, testul pică.

---

#### `brute_force` (liniile 18-30) — simulează un atac brute force

**Linia 18: `def brute_force(rng, start, ip):`**
- Parametri:
  - `rng` — generatorul de numere aleatoare (deterministic la testare)
  - `start` — momentul de start al atacului
  - `ip` — IP-ul atacatorului

**Linia 21: `for _ in range(rng.randint(30, 60)):`**
- **`_`** — variabila „aruncată". Convenție Python: dacă nu-ți trebuie valoarea iteratorului, o numești `_`.
- Generează între 30 și 60 de încercări (specific unui brute force real).

**Linia 22: `t += timedelta(seconds = rng.randint(2, 4))`**
- Avansează timpul cu 2-4 secunde între încercări, simulând un atacator automat.

**Linia 23: `events.append((t, format_line(t, "failure", "root", ip, rng)))`**
- Adaugă un **tuplu** `(timestamp, linie_de_log)` în listă.
- **Concept: Tuplu** — o structură imutabilă și ordonată. `(t, line)` e un tuplu de 2 elemente. Diferența față de listă: tuplurile nu pot fi modificate, sunt mai ușoare în memorie, și comunică intenția „aceasta e o pereche fixă de valori".

**Liniile 24-29: Label-ul**
```python
label = {
    "scenario": "brute_force",
    "source_ip": ip,
    "start": events[0][0].isoformat(),
    "end": events[-1][0].isoformat(),
}
```
- **Label** = etichetă = **adevărul de bază** (ground truth). Știi exact ce scenariul e simulat, de la ce IP, și între ce momente.
- **`events[0][0]`** — primul eveniment (`events[0]`), timestamp-ul său (indexul `[0]` din tuplu).
- **`events[-1][0]`** — ultimul eveniment (indexul `-1` = ultimul element din listă).
- **`.isoformat()`** — convertește datetime-ul în format ISO 8601 (`"2026-10-01T03:00:02+00:00"`), un standard internațional.
- **De ce label-uri:** Când testezi detecția, ai nevoie să știi **răspunsul corect**. Dacă generatorul zice „e brute_force de la IP X", iar detectorul nu generează alertă, detectorul are un bug. Asta e baza pentru calculul *precision* și *recall*.

---

## 7. Pachetul `__init__.py`

### [`src/ingestion/__init__.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/src/ingestion/__init__.py)

```python
from src.ingestion.models import AuthEvent
from src.ingestion.parser import parse_line, parse_file

__all__ = ["AuthEvent", "parse_line", "parse_file"]
```

**Concept: `__init__.py`** — face un folder un **pachet Python**. Fără el, `from src.ingestion import AuthEvent` nu ar funcționa. Python tratează folderul ca pe un modul importabil.

**Re-exporturi:** Importurile din `__init__.py` permit un API simplificat:
```python
# Fără __init__.py — trebuie calea completă:
from src.ingestion.models import AuthEvent

# Cu __init__.py — importul e mai curat:
from src.ingestion import AuthEvent
```

**`__all__`** — o listă care definește ce e exportat când cineva face `from src.ingestion import *`. Fără ea, `import *` ar importa totul. Cu ea, doar `AuthEvent`, `parse_line`, și `parse_file` sunt expuse.

### [`scripts/__init__.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/scripts/__init__.py)

Fișierul e gol. Singura sa funcție e să permită importul `from scripts.generate_logs import ...` în teste.

---

## 8. Testele unitare

### Concepte generale de testare

**Concept: TDD (Test-Driven Development)** — scrii testul **înainte** de cod:
1. Scrii un test care descrie comportamentul dorit
2. Testul pică (codul nu există încă)
3. Scrii minimum de cod ca testul să treacă
4. Refactorizezi codul, testele rămân verzi

**Concept: Test Unitar** — testează o singură „unitate" (funcție, clasă) izolat de restul sistemului. Nu se conectează la baze de date, rețea, etc.

**Concept: `pytest`** — framework-ul de testare:
- Caută automat fișierele `test_*.py`
- Caută funcțiile `test_*` din aceste fișiere
- Execută fiecare funcție — dacă nu aruncă excepție, testul trece
- `assert` e suficient — nu trebuie `self.assertEqual` ca în `unittest`

---

### [`tests/unit/test_models.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/tests/unit/test_models.py)

```python
import pytest
from datetime import datetime, timezone
from src.ingestion.models import AuthEvent
from pydantic import ValidationError


def make_event(**overrides):  # 6
    data = {  # 7
        "timestamp": datetime(2026, 10, 1, 3, 0, 0, tzinfo=timezone.utc),
        "source_ip": "203.0.113.5",
        "username": "root",
        "outcome": "failure",
        "raw": "linie de test",
    }
    data.update(overrides)  # 14
    return AuthEvent(**data)  # 15
```

**`make_event(**overrides)`** — o **funcție ajutătoare** (helper/factory). Creează un `AuthEvent` valid cu valori implicite, dar permite suprascrierea oricărui câmp.

- **`**overrides`** — **kwargs** (keyword arguments). Colectează orice argumente cu nume într-un dicționar. Apel: `make_event(username="hacker")` → `overrides = {"username": "hacker"}`.
- **`data.update(overrides)`** — suprascrie cheile din `data` cu cele din `overrides`. Dacă `overrides = {"username": "hacker"}`, atunci `data["username"]` devine `"hacker"`.
- **`AuthEvent(**data)`** — **unpacking de dicționar**. `**data` transformă dicționarul în argumente cu nume: `AuthEvent(timestamp=..., source_ip=..., ...)`.
- **De ce un factory:** Fiecare test trebuie doar să specifice câmpul pe care-l testează. `make_event(source_ip="abc")` e mult mai clar decât să repeti toate cele 5 câmpuri în fiecare test.
- **`203.0.113.5`** — e o adresă din **blocul de documentare** (RFC 5737). E rezervată specific pentru exemple, nu aparține nimănui. E echivalentul `example.com` pentru IP-uri.

```python
def failed_fields(exc_info):
    return [error["loc"][0] for error in exc_info.value.errors()]
```

- Extrage **numele câmpurilor** care au cauzat eroarea de validare.
- **`exc_info.value`** — obiectul excepției capturat de `pytest.raises`.
- **`.errors()`** — returnează o listă de dicționare Pydantic. Fiecare are `"loc"` (locația erorii) și `"msg"` (mesajul).
- **`error["loc"][0]`** — primul element din locație, de ex. `"timestamp"`.
- **List comprehension** — `[expresie for element in lista]` — creează o listă nouă aplicând o expresie pe fiecare element.

---

#### Testele individuale:

```python
def test_valid_event_is_created():
    event = make_event()
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.outcome == "failure"
```
- **Happy path** — testează că un eveniment valid se creează corect.
- **`str(event.source_ip)`** — `source_ip` e un obiect `IPvAnyAddress`, nu un string. `str(...)` îl convertește pentru comparație.

```python
def test_invalid_ip_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(source_ip="abc")
    assert exc_info.value.errors()[0]["loc"] == ("source_ip",)
```
- **`pytest.raises(ValidationError)`** — context manager care **așteaptă** o excepție. Dacă excepția NU apare, testul pică.
- **Testează că `"abc"` nu e acceptat ca IP** — confirmă că validarea funcționează.
- **`("source_ip",)`** — un tuplu cu un singur element (virgula finală e importantă, fără ea ar fi doar un string între paranteze).

```python
def test_naive_timestamp_is_rejeected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(timestamp=datetime(2026, 10, 1, 3, 0, 0))
    assert failed_fields(exc_info) == ["timestamp"]
```
- Testează că un timestamp **naiv** (fără `tzinfo`) e respins.

```python
def test_username_at_limit_is_accepted():
    assert make_event(username="a" * 64).username == "a" * 64
```
- **Boundary testing** — testează exact limita de 64 de caractere. Trebuie să treacă.
- **`"a" * 64`** — creează un string de 64 de `a`. Multiplicarea stringurilor e o funcționalitate Python.

```python
def test_username_over_limit_is_rejected():
    with pytest.raises(ValidationError) as exc_info:
        make_event(username="a" * 65)
    assert failed_fields(exc_info) == ["username"]
```
- **Boundary testing** — testează peste limită (65 caractere). Trebuie respins.
- **Concept: Boundary Testing** — bug-urile se ascund la granițe. Dacă limita e 64, testezi 63 (sub limită), 64 (pe limită), și 65 (peste limită). Off-by-one errors sunt printre cele mai comune bug-uri.

```python
def test_event_is_immutable():
    event = make_event()
    with pytest.raises(ValidationError):
        event.username = "someone"
```
- Confirmă că `frozen = True` funcționează — nu poți modifica obiectul.

---

### [`tests/unit/test_parser.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/tests/unit/test_parser.py)

```python
from asyncio import events  # 1 — import neutilizat
import pytest
from random import paretovariate  # 3 — import neutilizat
from datetime import datetime, timezone
from src.ingestion.parser import parse_line, parse_file
```

- **Liniile 1 și 3:** importuri neutilizate (probabil din autocompletare). `ruff` ar trebui să le semnaleze.

#### Constantele de test:

```python
FAILED = "Oct  1 03:12:05 srv01 sshd[2211]: Failed password for root from 203.0.113.5 port 41022 ssh2"
INVALID_USER = "Oct  1 03:12:09 srv01 sshd[2213]: Failed password for invalid user admin from 203.0.113.5 port 41030 ssh2"
ACCEPTED = "Oct  1 09:00:00 srv01 sshd[2300]: Accepted password for alice from 10.0.0.12 port 50000 ssh2"
IRRELEVANT = "Oct  1 03:12:05 srv01 cron[1]: job started"
BAD_IP = "Oct  1 03:12:05 srv01 sshd[1]: Failed password for root from not-an-ip port 41022 ssh2"
LONG_USER = f"Oct  1 03:12:05 srv01 sshd[1]: Failed password for {'a' * 200} from 203.0.113.5 port 41022 ssh2"
```

Fiecare constantă e un **caz de test** clar:
- `FAILED` — login eșuat normal (user existent)
- `INVALID_USER` — login eșuat cu „invalid user" (user inexistent)
- `ACCEPTED` — login reușit
- `IRRELEVANT` — linie din alt proces (`cron`, nu `sshd`)
- `BAD_IP` — IP invalid (text, nu adresă)
- `LONG_USER` — username de 200 de caractere (peste limita de 64)

#### Testele:

```python
def test_failed_login():
    event = parse_line(FAILED, 2026)
    assert event.timestamp == datetime(2026, 10, 1, 3, 12, 5, tzinfo=timezone.utc)
    assert event.outcome == "failure"
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
```
- Verifică extracția corectă a tuturor câmpurilor dintr-un login eșuat.

```python
def test_invalid_user_login():
    event = parse_line(INVALID_USER, 2026)
    ...
    assert event.username == "admin"
```
- Verifică că parserul extrage corect username-ul chiar și când linia conține `invalid user`.

```python
@pytest.mark.parametrize("line", [BAD_IP, LONG_USER, "", "garbage"])
def test_hostile_or_malformed_input_returns_none(line):
    assert parse_line(line, 2026) is None
```
- **`@pytest.mark.parametrize`** — un **decorator** care rulează **același test de 4 ori**, cu inputuri diferite: IP invalid, username prea lung, linie goală, și text aleator.
- **Concept: Parametrize** — în loc de 4 funcții de test identice, un singur test parametrizat. DRY (Don't Repeat Yourself) aplicat la teste.
- **Concept: Decorator** — `@decorator` e un „ambalaj" pentru o funcție. Modifică comportamentul funcției fără să-i schimbe codul. `@parametrize` transformă o funcție în N funcții.

```python
def test_parse_file_skips_irrelevant_lines(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text("\n".join([FAILED, IRRELEVANT, ACCEPTED]) + "\n")
    events = parse_file(log, 2026)
    assert [e.outcome for e in events] == ["failure", "success"]
```
- **`tmp_path`** — **fixture pytest**. Pytest furnizează automat un director temporar unic pentru fiecare test. Nu trebuie creat sau șters manual.
- **`tmp_path / "auth.log"`** — operatorul `/` pe obiecte `Path` creează o cale (path joining). Echivalent cu `os.path.join(tmp_path, "auth.log")` dar mai elegant.
- **Concept: Fixture** — un mecanism pytest pentru a furniza date sau resurse testelor. Scrii parametrul în semnătura funcției, și pytest îl furnizează automat.
- **Verificarea:** din 3 linii (eșec, irelevant, succes), doar 2 produc evenimente (`failure`, `success`).

```python
def test_parse_file_survives_invalid_bytes(tmp_path):
    log = tmp_path / "auth.log"
    log.write_bytes(
        FAILED.encode() + b"\n\xff\xfe garbage\n" + ACCEPTED.encode() + b"\n"
    )
    assert len(parse_file(log, 2026)) == 2
```
- **Testează reziliența la octeți invalizi.** `\xff\xfe` nu sunt UTF-8 valid.
- **`write_bytes`** — scrie octeți bruti (bytes), nu text.
- **`.encode()`** — convertește string la bytes (UTF-8 implicit).
- **`b"..."`** — bytes literal. `b"\xff"` e octetul 255.
- Testul confirmă că `errors="replace"` din parser funcționează corect — octeții invalizi sunt înlocuiți, nu crash.

---

### [`tests/unit/test_generator.py`](file:///c:/Users/Marius%20Radulescu/OneDrive/Desktop/AISOP/tests/unit/test_generator.py)

```python
def test_format_line_round_trips_through_parser():
    rng = random.Random(1)
    ts = datetime(2026, 10, 1, 3, 12, 5, tzinfo=timezone.utc)
    line = format_line(ts, "failure", "root", "203.0.113.5", rng)
    event = parse_line(line, 2026)
    assert event is not None
    assert event.timestamp == ts
    assert event.username == "root"
    assert str(event.source_ip) == "203.0.113.5"
    assert event.outcome == "failure"
```
- **Round-trip test:** generatorul produce un log → parserul îl parsează → verifici că ai aceleași date. Dacă generatorul produce un format ușor diferit de ce așteaptă parserul, testul pică.
- **`random.Random(1)`** — creează un generator cu **seed** fix. Seed-ul 1 va produce mereu aceleași numere „aleatoare", ceea ce face testul **deterministic** (reproductibil).

```python
@pytest.mark.parametrize("seed", range(20))
def test_brute_force_event_count_is_in_range(seed):
    events, _ = brute_force(random.Random(seed), START, IP)
    assert 30 <= len(events) <= 60
```
- Testează cu **20 de seed-uri diferite** că numărul de evenimente e mereu între 30 și 60 (conform `rng.randint(30, 60)`).
- **`range(20)`** — generează `0, 1, 2, ..., 19`.
- **`events, _`** — tuple unpacking. `brute_force` returnează `(events, label)`. `_` ignoră label-ul.
- **`30 <= len(events) <= 60`** — Python permite chain comparisons (comparații înlănțuite). E echivalent cu `30 <= len(events) and len(events) <= 60`.

```python
def test_brute_force_label_matches_events():
    events, label = brute_force(random.Random(7), START, IP)
    assert label["scenario"] == "brute_force"
    assert label["source_ip"] == IP
    assert label["start"] == events[0][0].isoformat()
    assert label["end"] == events[-1][0].isoformat()
```
- Verifică **consistența** între label și evenimente — label-ul trebuie să descrie exact ce s-a generat.

---

## 9. Concepte de programare generală

### Type Hints
Python e **dinamic tipizat** — nu verifică tipuri la compilare. Type hints (`x: int`, `-> str`) sunt **adnotări opționale** care:
- Documentează codul (citești semnătura și știi ce primește/returnează)
- Sunt verificate de unelte statice (mypy, pyright)
- Sunt folosite de Pydantic pentru validare la runtime

### Moștenire (Inheritance)
`class AuthEvent(BaseModel)` — AuthEvent „moștenește" de la BaseModel. Primește tot ce știe BaseModel (validare, serializare) fără să rescrie nimic. E ca și cum ai extinde un șablon.

### Context Managers (`with`)
`with open(...) as f:` — garantează cleanup-ul (închiderea fișierului) chiar dacă apare o eroare. Orice obiect cu metode `__enter__` și `__exit__` poate fi folosit cu `with`.

### Excepții (Exception Handling)
```python
try:
    # cod care ar putea eșua
except (ValueError, ValidationError):
    return None
```
Când codul din `try` aruncă o excepție din tipurile specificate, execuția sare la `except`. E un mecanism de recuperare din erori.

### Iteratoare și Lazy Evaluation
Un fișier deschis e un **iterator** — produce câte o linie la cerere, nu le citește pe toate în memorie. `parse_lines` primește un `Iterable`, deci funcționează cu orice sursă de linii (fișier, listă, generator).

### Convenții Python
- `_PATTERN` — prefixul `_` = privat (nu e exportat)
- `HOST` — MAJUSCULE = constantă (nu modifica)
- `_` — variabilă ignorată (`for _ in range(10)`)
- `__all__` — controlează `import *`
- `__init__.py` — face un folder pachet Python

---

## 10. Concepte de securitate

### Validare la graniță (Boundary Validation)
Datele sunt verificate **o singură dată**, la intrare (când se creează `AuthEvent`). Tot codul din aval poate presupune că datele sunt valide. E mult mai sigur decât verificări ad-hoc împrăștiate prin cod.

### Input ostil (Hostile Input)
Un atacator controlează ce apare în loguri (username-ul pe care-l trimite, IP-ul sursă). Fără validare:
- Un username de 1 milion de caractere → memorie epuizată
- Un IP invalid → crash la prelucrare
- Text care arată ca un log valid dar nu e → alertă falsă

Parserul se apără: regex ancorat, lungimi limitate, validare Pydantic.

### Brute Force
Un atac în care un atacator încearcă mii de parole pe un cont. Tiparul: multe `failure` de la un IP, pe un cont, într-un interval scurt.

### Password Spraying
Un atac în care un atacator încearcă puține parole, dar pe **multe conturi**. Tiparul: un IP, multe username-uri distincte.

### MITRE ATT&CK
Un framework global care cataloghează tehnicile de atac. Fiecare tehnică are un ID:
- **T1110.001** — Brute Force: Password Guessing
- **T1110.003** — Brute Force: Password Spraying

Asocierea alertelor cu ID-uri MITRE permite standardizare și comunicare între echipe de securitate.

### False Positives / False Negatives
- **False Positive** — alertă când nu e atac (utilizator legitim care a greșit parola de 5 ori)
- **False Negative** — fără alertă când e atac real (pragul e prea mare)
- **Precision** — din alertele generate, câte sunt corecte
- **Recall** — din atacurile reale, câte au fost detectate

### Date sintetice și Ground Truth
Nu folosești date reale din motive legale și etice. Generatorul produce loguri false cu etichete (labels) care spun ce scenariul e simulat. Aceste etichete sunt **ground truth** — adevărul cunoscut contra căruia verifici detectorul.

---

> [!TIP]
> **Sfaturi pentru a deveni un programator mai bun:**
> 1. Citește codul **linie cu linie** — nu sări peste nimic
> 2. Pentru fiecare funcție, întreabă-te: ce primește, ce returnează, ce poate merge prost?
> 3. Scrie teste **înainte** de cod (TDD)
> 4. Folosește type hints — fac codul mai clar și previne bug-uri
> 5. Separă responsabilitățile — fiecare funcție/modul face un singur lucru
> 6. Validează datele la intrare, nu la fiecare utilizare
