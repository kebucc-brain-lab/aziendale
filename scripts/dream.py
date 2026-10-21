#!/usr/bin/env python3
"""dream.py -- revisione della memoria automatica del brain (Brain Builder v3.2, SPEC par. 2.6-2.7 e par. 12).

    python scripts/dream.py paths         [--root R] [--node N] [--json]
    python scripts/dream.py memory-report [--root R] [--node N] [--json] [--content]
    python scripts/dream.py new-proposal  [--root R] [--node N] [--sessions-read N]
    python scripts/dream.py apply         [--root R] [--node N] [--proposal FILE] [--dry-run]
    python scripts/dream.py schedule-cmd  [--root R] [--node N] [--day MON] [--time 09:00] [--platform auto|windows|posix]
    python scripts/dream.py recover       [--root R] [--node N]

Sostituisce la parte "a mano" delle skill dream dell'archivio (`cp -r`, `$(date)`, modifiche dirette della
memoria): la memoria cambia SOLO con `apply` e SOLO per le voci spuntate `[x]` della proposta.

- Nodo corrente: `--node` > nodo.md piu' vicino alla cwd > radice. Uno script installato in `<root>/scripts/`
  lavora solo sulla propria radice (`--root` fuori = exit 3, come sessions.py).
- Memory dir AUTOREVOLE: `autoMemoryDirectory` del `.claude/settings.json` del nodo. `settings.json` assente o
  corrotto, chiave assente, oppure `settings.local.json` che ne dichiara una diversa: `paths` lo segnala,
  `new-proposal` e `apply` si fermano (exit 2). Nessun fallback silenzioso in scrittura (i comandi di sola
  lettura ripiegano su `BRAIN_MEMORY_DIR`, poi `<nodo>/.memory`, e lo dicono).
- Proposte separate per nodo: `<root>/workspace/dream/<node-key>/<YYYY-MM-DD>-<HHMMSS>.md` (node-key: `root`
  oppure node_path con `/` -> `__`), gitignorate. La prima riga e' l'intestazione macchina
  `<!-- dream-meta {json} -->` (brain_id, node_path, memory_dir, review_id, sha256 di ogni file di memoria al
  momento della review), scritta da `new-proposal`: `apply` la verifica.
- Backup prima di qualunque scrittura: copia completa della memory dir in
  `<root>/.memory-backup/<node-key>/<YYYYMMDD-HHMMSS>/` (`shutil.copytree(symlinks=True)`); senza modifiche
  da fare, nessun backup. Link/junction nella memory dir o memory dir condivisa con un altro nodo = exit 2.
- Gruppi atomici: le voci con lo stesso prefisso (`m1` e `m1r`, `c1-tieni`/`c1-correggi`) si applicano tutte o
  nessuna; validazione completa prima di scrivere; registro (`Voce: <id>`) scritto dopo ogni gruppo.
- `schedule-cmd` STAMPA il comando per Task Scheduler / crontab che lancerebbe la review: non lo registra.
  `apply` non si schedula mai.

Exit di `apply`: 0 nessun errore, 1 almeno una voce in errore (le altre restano applicate), 2 proposta assente,
illeggibile o di un altro brain/nodo/memoria, oppure memoria non autorevole/insicura; 3 `--root` fuori dal brain.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import datetime as dt
import hashlib
import io
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kb_config as kc  # noqa: E402
from secrets_scan import find_secrets, mask_secrets  # noqa: E402
from sessions import RootOutside, bound_root, canon, is_within, norm_path, EXIT_ROOT_OUTSIDE  # noqa: E402

MAX_LINES = 200
MAX_BYTES = 25 * 1024
WARN_RATIO = 0.8
CONTENT_LIMIT = 200 * 1024
INDEX_NAME = "MEMORY.md"
ACTIONS = ("AGGIUNGI", "AGGIORNA", "RIMUOVI", "TIENI", "VAULT")
WRITE_ACTIONS = ("AGGIUNGI", "AGGIORNA", "RIMUOVI")
MEMORY_TYPES = ("user", "feedback", "project", "reference")
META_PREFIX = "<!-- dream-meta "
META_SUFFIX = " -->"

ITEM_RE = re.compile(r"^\s*- \[(?P<mark>[ xX])\] \{(?P<id>[A-Za-z0-9_-]+)\}\s+(?P<action>[A-Z]+)\b(?P<rest>.*)$")
FENCE_RE = re.compile(r"^(?P<indent>\s*)(?P<ticks>`{3,})memoria\s*$")
HEADING_RE = re.compile(r"^#{1,6}\s")
APPLIED_RE = re.compile(r"^##\s+(?:Applicato|Recuperato)\b")
VOCI_RE = re.compile(r"^Voc[ei]:\s*(?P<ids>.*)$")
ANNUL_RE = re.compile(r"^Annullat[ae]:\s*(?P<ids>.*)$")
FILE_RE = re.compile(r"`([^`]+)`")
NAME_RE = re.compile(r"^[A-Za-z0-9._-]+\.md$")
LINK_RE = re.compile(r"\]\(([^)\s]+)\)")
CONFLICT_RE = re.compile(r"^(?P<key>c\d+)-(?P<side>tieni|correggi)$")
GROUP_RE = re.compile(r"^([A-Za-z]+\d+)")
PROPOSAL_RE = re.compile(r"^\d{4}-\d{2}-\d{2}-\d{6}(?:-\d+)?\.md$")
DAYS = ("MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN")
DAY_NAME = {"MON": "Monday", "TUE": "Tuesday", "WED": "Wednesday", "THU": "Thursday", "FRI": "Friday",
            "SAT": "Saturday", "SUN": "Sunday"}
CRON_DAY = {"MON": 1, "TUE": 2, "WED": 3, "THU": 4, "FRI": 5, "SAT": 6, "SUN": 0}


class Stop(Exception):
    """Condizione che ferma il comando con exit 2 (messaggio pronto per l'utente)."""


# --------------------------------------------------------------------------- utilita'

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


is_link = kc.is_link            # v3.2.1: implementazione unica in kb_config (la usa anche brain_sync --ops)


def links_inside(d: Path) -> list[str]:
    found: list[str] = []
    if not d.is_dir():
        return found
    stack = [d]
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for e in entries:
            if is_link(e.path):
                found.append(Path(e.path).relative_to(d).as_posix())
            elif e.is_dir(follow_symlinks=False):
                stack.append(Path(e.path))
    return sorted(found)


def _write(p: Path, text: str) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)


def mask_obj(obj):
    """Maschera ogni stringa di una struttura (per l'output JSON: il JSON resta valido)."""
    if isinstance(obj, str):
        return mask_secrets(obj)[0]
    if isinstance(obj, list):
        return [mask_obj(x) for x in obj]
    if isinstance(obj, dict):
        return {k: mask_obj(v) for k, v in obj.items()}
    return obj


def _append(p: Path, text: str) -> None:
    with open(p, "a", encoding="utf-8", newline="\n") as f:
        f.write(text)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


# --------------------------------------------------------------------------- radice, nodo, memoria

def resolve(a) -> tuple[Path, kc.Node]:
    root = bound_root(a.root)
    node = kc.current_node(root, override=a.node)
    return root, node


@dataclass
class MemInfo:
    path: Path | None
    source: str
    problems: list[str] = field(default_factory=list)
    outside: bool = False          # giro 5: memoria fuori dalla radice del brain = sola lettura per dream

    @property
    def declared_ok(self) -> bool:
        return self.path is not None and self.source == "autoMemoryDirectory" and not self.problems

    @property
    def authoritative(self) -> bool:
        return self.declared_ok and not self.outside


def _declared(settings: Path) -> tuple[str | None, str]:
    """(autoMemoryDirectory dichiarato o None, problema o '')."""
    try:
        data = json.loads(kc.read_text(settings))
    except (OSError, ValueError) as e:
        return None, "%s corrotto o illeggibile (%s)" % (settings.name, e.__class__.__name__)
    if not isinstance(data, dict):
        return None, "%s non e' un oggetto JSON" % settings.name
    amd = data.get("autoMemoryDirectory")
    if isinstance(amd, str) and amd.strip():
        return os.path.expanduser(amd.strip()), ""
    return None, ""


def memory_info(node: kc.Node) -> MemInfo:
    problems: list[str] = []
    sp = node.dir / ".claude" / "settings.json"
    declared = None
    if not sp.is_file():
        problems.append("%s assente" % sp.as_posix())
    else:
        declared, prob = _declared(sp)
        if prob:
            problems.append(prob)
        elif declared is None:
            problems.append("autoMemoryDirectory assente in %s" % sp.as_posix())
    lp = node.dir / ".claude" / "settings.local.json"
    if lp.is_file():
        local, prob = _declared(lp)
        if prob:
            problems.append(prob)
        elif local is not None and (declared is None or canon(local) != canon(declared)):
            problems.append("settings.local.json dichiara un autoMemoryDirectory diverso (%s): Claude userebbe "
                            "quello, non %s" % (local, declared or "(nessuno)"))
    if declared:
        mp = Path(os.path.abspath(declared))
        # giro 4 (#5/#7/N3): nessun componente del percorso della memoria (antenati compresi) puo' essere un
        # link/junction/reparse point; vale per TUTTE le risoluzioni (paths, memory-report, new-proposal, apply, recover)
        bad = link_in_path(Path(mp.anchor), mp)
        if bad is not None:
            problems.append("la memory dir %s passa da un link/junction (%s): rifiutata" % (mp.as_posix(), bad.as_posix()))
        outside = not is_within(canon(mp), canon(node.root))
        return MemInfo(mp, "autoMemoryDirectory", problems, outside)
    # verifica di chiusura N3(a): nessun ripiego (ne' BRAIN_MEMORY_DIR ne' <nodo>/.memory): senza una
    # autoMemoryDirectory autorevole non c'e' memoria da leggere o scrivere.
    return MemInfo(None, "nessuna (autoMemoryDirectory non dichiarata)", problems)


link_in_path = kc.link_in_path  # v3.2.1: implementazione unica in kb_config


def foreign_brain_of(root: Path, mem: Path) -> Path | None:
    """Cartella di un ALTRO brain che contiene la memory dir (realpath), oppure None. Dentro la radice del brain
    e' sempre ammessa; fuori lo e' solo se nessun antenato ha `brain.yaml` o `nodo.md` (N3(b))."""
    real = Path(os.path.realpath(mem))
    if is_within(canon(real), canon(root)):
        return None
    for d in (real, *real.parents):
        if (d / "brain.yaml").is_file() or (d / "nodo.md").is_file():
            return d
    return None


def other_nodes_sharing(root: Path, node: kc.Node, mem: Path) -> list[str]:
    target = canon(mem)
    out = []
    for n in kc.iter_nodes(root):
        if n.path == node.path:
            continue
        sp = n.dir / ".claude" / "settings.json"
        if sp.is_file():
            d, _p = _declared(sp)
            if d and canon(d) == target:
                out.append(n.path)
    return out


OUTSIDE_MSG = "memoria fuori dal brain: dream la tratta in sola lettura"


def require_safe_memory(root: Path, node: kc.Node, write: bool = True) -> MemInfo:
    """Memoria dichiarata, non link, senza link dentro, non condivisa con altri nodi. Altrimenti Stop.
    Giro 5 (#5/#7/N3): con `write` (new-proposal, apply, recover) la memoria deve stare DENTRO la radice del brain;
    fuori e' ammessa solo in lettura (memory-report), cosi' due brain che dichiarano la stessa cartella esterna non
    possono scriversi a vicenda.
    Giro 7 (#5): il controllo "fuori dalla radice" e' il PRIMO, prima di qualunque enumerazione: una memoria esterna
    non si enumera, non se ne nominano file o link, e TUTTI i comandi che la userebbero (anche memory-report in
    lettura) escono con 2 "memoria fuori dal brain: <cartella>". `write` resta per compatibilita' della firma."""
    mi = memory_info(node)
    if mi.path is not None and mi.outside:
        other = foreign_brain_of(root, mi.path)          # solo stat sugli antenati: nessuna enumerazione
        raise Stop("memoria fuori dal brain: %s%s" % (mi.path.as_posix(),
                   (" (appartiene a un altro brain: %s)" % other.as_posix()) if other is not None else ""))
    if not mi.declared_ok:
        raise Stop("memory dir non autorevole per il nodo %s: %s" % (node.path, "; ".join(mi.problems) or mi.source))
    if is_link(mi.path):
        raise Stop("la memory dir %s e' un link/junction: rifiutata" % mi.path.as_posix())
    bad = links_inside(mi.path)                          # memoria DEL brain: i nomi si possono citare
    if bad:
        raise Stop("nella memory dir ci sono link/junction (%s): rifiutata" % ", ".join(bad[:5]))
    shared = other_nodes_sharing(root, node, mi.path)
    if shared:
        raise Stop("la memory dir %s e' dichiarata anche dai nodi %s: memoria condivisa, rifiutata"
                   % (mi.path.as_posix(), ", ".join(shared)))
    return mi


def node_key(node: kc.Node) -> str:
    return kc.node_key(node.path)


def proposals_dir(root: Path, node: kc.Node) -> Path:
    return root / "workspace" / "dream" / node_key(node)


def backups_dir(root: Path, node: kc.Node) -> Path:
    return root / ".memory-backup" / node_key(node)


def list_proposals(pdir: Path) -> list[Path]:
    if not pdir.is_dir():
        return []
    return sorted(p for p in pdir.iterdir() if p.is_file() and PROPOSAL_RE.match(p.name))


def latest_proposal(pdir: Path) -> Path | None:
    props = list_proposals(pdir)
    return props[-1] if props else None


def brain_id_of(root: Path) -> str:
    return kc.brain_id(root, strict=False) or root.name


def cmd_paths(a) -> int:
    root, node = resolve(a)
    mi = memory_info(node)
    pdir = proposals_dir(root, node)
    latest = latest_proposal(pdir)
    info = {
        "brain_id": brain_id_of(root),
        "root": root.as_posix(),
        "node_path": node.path,
        "node_key": node_key(node),
        "node_dir": node.dir.as_posix(),
        "memory_dir": mi.path.as_posix() if mi.path else None,
        "memory_source": mi.source,
        "memory_authoritative": mi.authoritative,
        "memory_problems": mi.problems + ([OUTSIDE_MSG] if mi.outside else []),
        "memory_read_only": mi.outside,
        "proposals_dir": pdir.as_posix(),
        "latest_proposal": latest.as_posix() if latest else None,
        "backup_dir": backups_dir(root, node).as_posix(),
    }
    if a.json:
        print(json.dumps(mask_obj(info), ensure_ascii=False, indent=2))
        return 0
    rows = [("brain", info["brain_id"]), ("radice", info["root"]), ("nodo rilevato", info["node_path"]),
            ("cartella del nodo", info["node_dir"]),
            ("memoria", info["memory_dir"] or "(nessuna autorevole)"), ("origine memoria", info["memory_source"]),
            ("memoria autorevole", "si" if mi.authoritative else "NO (apply si fermerebbe)"),
            ("cartella proposte", info["proposals_dir"]),
            ("ultima proposta", info["latest_proposal"] or "(nessuna)"), ("backup", info["backup_dir"])]
    for k, v in rows:
        print("%s: %s" % (k, v))
    for p in mi.problems + ([OUTSIDE_MSG] if mi.outside else []):
        print("PROBLEMA: " + p)
    return 0


# --------------------------------------------------------------------------- memory-report

def index_targets(line: str) -> list[str]:
    """Basename dei file a cui punta una riga d'indice (`[testo](file.md)`)."""
    out = []
    for t in LINK_RE.findall(line):
        t = t.split("#", 1)[0].replace("\\", "/")
        if t:
            out.append(t.rsplit("/", 1)[-1])
    return out


def size_status(lines: int, size: int) -> str:
    if lines > MAX_LINES or size > MAX_BYTES:
        return "over"
    if lines > MAX_LINES * WARN_RATIO or size > MAX_BYTES * WARN_RATIO:
        return "warn"
    return "ok"


STATUS_IT = {"ok": "ok", "warn": "ATTENZIONE: oltre l'80% della soglia",
             "over": "OLTRE LA SOGLIA: la parte in eccesso non si carica", "absent": "assente (memoria nuova)"}


def memory_type(fm: dict) -> str:
    """`type` al livello principale (formato canonico); in lettura accetta anche `metadata.type`."""
    meta = fm.get("metadata") if isinstance(fm.get("metadata"), dict) else {}
    return kc.fm_str(fm.get("type") or meta.get("type"))


def memory_report(mem: Path, with_content: bool = False) -> dict:
    rep: dict = {"memory_dir": mem.as_posix(), "exists": mem.is_dir(), "files": [], "index_missing": [],
                 "not_indexed": [], "content_truncated": False, "secrets_masked": 0,
                 "memory_md": {"exists": False, "path": (mem / INDEX_NAME).as_posix(), "lines": 0, "bytes": 0,
                               "kb": 0.0, "max_lines": MAX_LINES, "max_kb": MAX_BYTES // 1024, "status": "absent"}}
    if not mem.is_dir():
        return rep
    budget = [CONTENT_LIMIT]

    def take(text: str) -> str | None:
        masked, n = mask_secrets(text)
        rep["secrets_masked"] += n
        size = len(masked.encode("utf-8"))
        if size > budget[0]:
            rep["content_truncated"] = True
            return None
        budget[0] -= size
        return masked

    names = sorted(p.name for p in mem.iterdir()
                   if p.is_file() and p.suffix.lower() == ".md" and p.name != INDEX_NAME)
    idx = mem / INDEX_NAME
    indexed: set[str] = set()
    if idx.is_file():
        raw = idx.read_bytes()
        text = raw.decode("utf-8", errors="replace")
        n_lines = len(text.splitlines())
        rep["memory_md"].update({"exists": True, "lines": n_lines, "bytes": len(raw), "kb": round(len(raw) / 1024, 1),
                                 "status": size_status(n_lines, len(raw)), "sha256": sha256_file(idx)})
        if with_content:
            rep["memory_md"]["content"] = take(text)
        for line in text.splitlines():
            for t in index_targets(line):
                indexed.add(t)
                if not (mem / t).is_file() and t not in rep["index_missing"]:
                    rep["index_missing"].append(t)
    for name in names:
        p = mem / name
        text = kc.read_text(p)
        entry = {"name": name, "path": p.as_posix(), "type": "", "description": "", "lines": len(text.splitlines()),
                 "sha256": sha256_file(p), "frontmatter_error": "", "type_location": ""}
        try:
            fm, _ = kc.read_frontmatter(text)
            entry["type"] = mask_secrets(memory_type(fm))[0]
            entry["type_location"] = "type" if fm.get("type") else ("metadata.type" if entry["type"] else "")
            entry["description"] = mask_secrets(kc.fm_str(fm.get("description")))[0]   # N2: anche i metadati
        except kc.FrontmatterError as e:
            entry["frontmatter_error"] = mask_secrets(str(e))[0]
        if with_content:
            entry["content"] = take(text)
        rep["files"].append(entry)
    rep["not_indexed"] = [n for n in names if n not in indexed]
    return rep


def cmd_memory_report(a) -> int:
    root, node = resolve(a)
    mi = require_safe_memory(root, node, write=False)   # N3(a): stessa risoluzione sicura di apply (in lettura)
    # giro 7 (#5): una memoria esterna non arriva qui (require_safe_memory esce prima, senza enumerarla)
    rep = memory_report(mi.path, with_content=a.content)
    rep["memory_source"] = mi.source
    rep["memory_problems"] = mi.problems + ([OUTSIDE_MSG] if mi.outside else [])
    rep["memory_read_only"] = mi.outside
    if a.json:
        print(json.dumps(mask_obj(rep), ensure_ascii=False, indent=2))
        return 0
    print("Nodo rilevato: %s (%s)" % (node.path, node.dir.as_posix()))
    print("Memoria: %s (da %s)" % (rep["memory_dir"], mi.source))
    if mi.outside:
        print("NOTA: " + OUTSIDE_MSG + " (non autorevole: niente proposte ne' apply)")
    for p in mi.problems:
        print("PROBLEMA: " + p)
    if not rep["exists"]:
        print("La cartella non esiste ancora: memoria nuova, niente da confrontare (e' normale all'inizio).")
        return 0
    mm = rep["memory_md"]
    if mm["exists"]:
        print("MEMORY.md: %d righe / %.1f KB (si caricano fino a %d righe / %d KB) - %s"
              % (mm["lines"], mm["kb"], MAX_LINES, MAX_BYTES // 1024, STATUS_IT[mm["status"]]))
    else:
        print("MEMORY.md: " + STATUS_IT["absent"])
    print("File di memoria: %d" % len(rep["files"]))
    for f in rep["files"]:
        extra = (" [frontmatter non valido: %s]" % f["frontmatter_error"]) if f["frontmatter_error"] else ""
        if f["type_location"] == "metadata.type":
            extra += " [type sotto metadata: il formato canonico lo vuole al livello principale]"
        print("- %s  [%s]  %d righe  - %s%s" % (f["name"], f["type"] or "?", f["lines"],
                                                 f["description"] or "(senza description)", extra))
    print("Voci d'indice senza file: " + (", ".join(rep["index_missing"]) or "(nessuna)"))
    print("File non indicizzati in MEMORY.md: " + (", ".join(rep["not_indexed"]) or "(nessuno)"))
    if a.content:
        print("\n# Contenuto (mascherato; limite %d KB; provenienza = path)" % (CONTENT_LIMIT // 1024))
        blocks = ([(mm["path"], mm.get("content"))] if mm["exists"] else []) + [(f["path"], f.get("content")) for f in rep["files"]]
        for path, content in blocks:
            print("\n=== %s ===" % path)
            print(content.rstrip("\n") if content is not None else "(omesso: limite di contenuto raggiunto)")
        print("\n%d segreti mascherati%s" % (rep["secrets_masked"], "; contenuto TRONCATO al limite" if rep["content_truncated"] else ""))
    return 0


# --------------------------------------------------------------------------- new-proposal

def snapshot_hashes(mem: Path) -> dict[str, str]:
    if not mem.is_dir():
        return {}
    return {p.name: sha256_file(p) for p in sorted(mem.iterdir()) if p.is_file() and p.suffix.lower() == ".md"}


def cmd_new_proposal(a) -> int:
    root, node = resolve(a)
    mi = require_safe_memory(root, node)
    if pending_intents(backups_dir(root, node)):
        raise Stop("un apply precedente si e' interrotto a meta' gruppo: prima `dream.py recover`")
    pdir = proposals_dir(root, node)
    bad = link_in_path(root, pdir)                 # N3(c): ogni componente (workspace, dream, cartella del nodo)
    if bad is not None:
        raise Stop("%s e' un link/junction: proposta rifiutata" % bad.as_posix())
    pdir.mkdir(parents=True, exist_ok=True)
    if not is_within(canon(pdir), canon(root)):
        raise Stop("la cartella delle proposte %s esce dalla radice del brain: rifiutata" % pdir.as_posix())
    now = dt.datetime.now()
    review_id = now.strftime("%Y%m%d-%H%M%S")
    path = pdir / (now.strftime("%Y-%m-%d-%H%M%S") + ".md")
    n = 2
    while path.exists():
        path = pdir / ("%s-%d.md" % (now.strftime("%Y-%m-%d-%H%M%S"), n))
        n += 1
    bid = brain_id_of(root)
    meta = {"brain_id": bid, "node_path": node.path, "memory_dir": mi.path.as_posix(), "review_id": review_id,
            "created": now.isoformat(timespec="seconds"), "hashes": snapshot_hashes(mi.path)}
    rep = memory_report(mi.path)
    mm = rep["memory_md"]
    salute = ("MEMORY.md: %d righe / %.1f KB (si caricano fino a %d righe / %d KB) · File di memoria: %d"
              % (mm["lines"], mm["kb"], MAX_LINES, MAX_BYTES // 1024, len(rep["files"]))) if mm["exists"] else \
        ("MEMORY.md: assente (memoria nuova) · File di memoria: %d" % len(rep["files"]))
    sessions = str(a.sessions_read) if a.sessions_read is not None else "?"
    nodo = "" if node.is_root else " (nodo %s)" % node.path
    text = (META_PREFIX + json.dumps(meta, ensure_ascii=False, sort_keys=True) + META_SUFFIX + "\n"
            "# Dream — %s — brain %s%s\n" % (now.date().isoformat(), bid, nodo) +
            "Sessioni lette: %s · Memoria: %s\n\n" % (sessions, mi.path.as_posix()) +
            "## Da aggiungere (mai scritto)\n\n"
            "## Doppioni\n\n"
            "## Contraddizioni (decidi tu)\n\n"
            "## Probabilmente morto\n\n"
            "## Per il vault (via %s-feed)\n\n" % bid +
            "## Salute\n" + salute + "\n")
    _write(path, text)
    print(path.as_posix())
    return 0


# --------------------------------------------------------------------------- proposta: parsing

@dataclass
class Item:
    id: str
    action: str
    checked: bool
    rest: str
    line_no: int
    filename: str = ""
    block: str | None = None
    index_line: str | None = None
    error: str = ""

    @property
    def label(self) -> str:
        return "{" + self.id + "} " + self.action + ((" " + self.filename) if self.filename else "")

    @property
    def group(self) -> str:
        m = GROUP_RE.match(self.id)
        return m.group(1) if m else self.id


def parse_meta(text: str) -> dict | None:
    first = text.lstrip("\ufeff").split("\n", 1)[0].strip()
    if not (first.startswith(META_PREFIX) and first.endswith(META_SUFFIX)):
        return None
    try:
        data = json.loads(first[len(META_PREFIX):-len(META_SUFFIX)])
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def parse_proposal(text: str) -> tuple[list[Item], set[str]]:
    """Voci (righe `- [ ] {id} AZIONE ...` con il loro blocco ```memoria e la riga `Indice:`) e id gia' applicati
    (righe `Voce:`/`Voci:` delle sezioni `## Applicato`)."""
    lines = text.splitlines()
    items: list[Item] = []
    applied: set[str] = set()
    cur: Item | None = None
    in_applied = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if HEADING_RE.match(line):
            cur = None
            in_applied = bool(APPLIED_RE.match(line))
            i += 1
            continue
        if in_applied:                    # registro letto IN ORDINE: `Voce:` applica, `Annullata:` (recover) annulla
            m = VOCI_RE.match(line.strip())
            ma = ANNUL_RE.match(line.strip())
            if m:
                applied |= {x.strip() for x in m.group("ids").split(",") if x.strip() and not x.strip().startswith("(")}
            elif ma:
                applied -= {x.strip() for x in ma.group("ids").split(",") if x.strip()}
            i += 1
            continue
        m = ITEM_RE.match(line)
        if m:
            fm = FILE_RE.search(m.group("rest"))
            cur = Item(id=m.group("id"), action=m.group("action"), checked=m.group("mark") in "xX",
                       rest=m.group("rest").strip(), line_no=i + 1, filename=fm.group(1).strip() if fm else "")
            if cur.action not in ACTIONS:
                cur.error = "azione sconosciuta %r (ammesse: %s)" % (cur.action, ", ".join(ACTIONS))
            items.append(cur)
            i += 1
            continue
        fence = FENCE_RE.match(line)
        if fence and cur is not None:
            ticks, ind = fence.group("ticks"), len(fence.group("indent"))
            body: list[str] = []
            closed = False
            i += 1
            while i < len(lines):
                cl = lines[i]
                if cl.strip() == ticks:
                    closed = True
                    i += 1
                    break
                body.append(cl[ind:] if cl[:ind].strip() == "" else cl.lstrip())
                i += 1
            if cur.block is not None:
                cur.error = cur.error or "due blocchi memoria nella stessa voce"
            cur.block = "\n".join(body).strip("\n") + "\n"
            if not closed:
                cur.error = cur.error or "blocco memoria non chiuso"
            continue
        if cur is not None:
            s = line.strip()
            if s.startswith("Indice:"):
                v = s[len("Indice:"):].strip()
                if len(v) >= 2 and v[0] == "`" and v[-1] == "`":
                    v = v[1:-1].strip()
                cur.index_line = v
        i += 1
    return items, applied


def valid_name(name: str) -> str:
    """'' se il nome file e' un basename ammesso dentro la memory dir, altrimenti il motivo."""
    if not name:
        return "nome file assente (atteso fra backtick)"
    if "/" in name or "\\" in name or ":" in name or ".." in name or name.startswith("."):
        return "nome file non ammesso %r: solo basename, niente separatori, '..' o path assoluti" % name
    if not NAME_RE.match(name):
        return "nome file non ammesso %r: atteso [A-Za-z0-9._-]+.md" % name
    if name == INDEX_NAME:
        return "MEMORY.md non si modifica con una voce: si aggiorna solo tramite le righe Indice"
    return ""


def validate_block(block: str) -> str:
    """'' se il blocco e' una memoria valida: frontmatter con name, description e type (livello principale)."""
    try:
        fm, body = kc.read_frontmatter(block)
    except kc.FrontmatterError as e:
        return "frontmatter del blocco non valido: %s" % e
    if not fm:
        return "il blocco non ha frontmatter (--- name/description/type ---)"
    missing = [k for k in ("name", "description") if not kc.fm_str(fm.get(k))]
    if missing:
        return "frontmatter del blocco senza %s" % ", ".join(missing)
    t = kc.fm_str(fm.get("type"))
    if not t:
        return "frontmatter del blocco senza `type:` al livello principale"
    if t not in MEMORY_TYPES:
        return "type %r non ammesso (ammessi: %s)" % (t, ", ".join(MEMORY_TYPES))
    if find_secrets(block):
        return "il blocco contiene un segreto non mascherato"
    return ""


def target_ok(mem: Path, name: str) -> str:
    p = mem / name
    if is_link(p):
        return "%s e' un link/junction: rifiutato" % name
    if not is_within(canon(p), canon(mem)) or canon(p) == canon(mem):
        return "%s uscirebbe dalla memory dir" % name
    return ""


def set_index_line(lines: list[str], filename: str, new_line: str) -> list[str]:
    out: list[str] = []
    replaced = False
    for line in lines:
        if filename in index_targets(line):
            if not replaced:
                out.append(new_line)
                replaced = True
            continue
        out.append(line)
    if not replaced:
        out.append(new_line)
    return out


def drop_index_line(lines: list[str], filename: str) -> list[str]:
    return [line for line in lines if filename not in index_targets(line)]


def make_backup(mem: Path, bdir: Path) -> Path:
    stamp = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    dest = bdir / stamp
    n = 2
    while dest.exists():
        dest = bdir / ("%s-%d" % (stamp, n))
        n += 1
    bdir.mkdir(parents=True, exist_ok=True)
    if mem.is_dir():
        shutil.copytree(mem, dest, symlinks=True)
    else:
        dest.mkdir(parents=True)
    return dest


# --------------------------------------------------------------------------- apply

INTENT_NAME = "IN-CORSO.json"


def pending_intents(bdir: Path) -> list[Path]:
    """Registri di intento lasciati da un apply interrotto (`<backup>/IN-CORSO.json`)."""
    return sorted(bdir.glob("*/" + INTENT_NAME)) if bdir.is_dir() else []


def _write_bytes(p: Path, data: bytes) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "wb") as f:
        f.write(data)
        f.flush()
        try:
            os.fsync(f.fileno())
        except OSError:
            pass


def _snapshot_entry(mem: Path, name: str) -> dict:
    """Stato di un file PRIMA del gruppo (contenuto esatto in base64), per il ripristino."""
    p = mem / name
    if p.is_file():
        return {"name": name, "existed": True, "b64": base64.b64encode(p.read_bytes()).decode("ascii")}
    return {"name": name, "existed": False, "b64": None}


def _restore_entry(mem: Path, entry: dict) -> None:
    """Riporta un file allo stato registrato nel registro di intento. Solleva OSError se non riesce."""
    name = str(entry.get("name") or "")
    if name != INDEX_NAME and valid_name(name):
        raise OSError("nome non ammesso nel registro di intento: %r" % name)
    p = mem / name
    if is_link(p):
        raise OSError("%s e' un link: non ripristinato" % name)
    if entry.get("existed"):
        _write_bytes(p, base64.b64decode(entry.get("b64") or ""))
    elif p.exists():
        p.unlink()


def resolve_proposal(given: str | None, pdir: Path, root: Path, bid: str) -> Path:
    """Proposta da applicare: SOLO dentro `workspace/dream/<node-key>/` del nodo corrente. Con `--proposal` i
    link/junction si cercano sul path COSI' COME DATO (ogni componente) prima di qualunque risoluzione (N3(d))."""
    bad = link_in_path(root, pdir)
    if bad is not None:
        raise Stop("%s e' un link/junction: proposte rifiutate" % bad.as_posix())
    if given:
        raw = Path(os.path.abspath(given))
        bad = link_in_path(Path(raw.anchor), raw)
        if bad is not None:
            raise Stop("il percorso della proposta passa da un link/junction (%s): rifiutata" % bad.as_posix())
        if norm_path(raw.parent) != norm_path(pdir):
            raise Stop("la proposta deve stare dentro %s (workspace/dream/<node-key>/ del nodo corrente): %s"
                       % (pdir.as_posix(), raw.as_posix()))
        prop = raw
    else:
        prop = latest_proposal(pdir)
    if prop is None or not prop.is_file():
        raise Stop("nessuna proposta da applicare (%s). Prima una review: /%s-dream review"
                   % (given or pdir.as_posix(), bid))
    if is_link(prop) or not is_within(canon(prop), canon(pdir)):
        raise Stop("la proposta %s e' un link o esce da %s: rifiutata" % (prop.as_posix(), pdir.as_posix()))
    return prop


def intent_identity_problem(data: dict, bid: str, node: kc.Node, mem: Path) -> str:
    """'' se l'intento appartiene a questa transazione (brain, nodo, memoria realpath), altrimenti il motivo (N8)."""
    missing = [k for k in ("brain_id", "node_path", "memory_dir", "review_id") if not data.get(k)]
    if missing:
        return "registro di intento senza identita' della transazione (%s)" % ", ".join(missing)
    if data["brain_id"] != bid:
        return "brain %r invece di %r" % (data["brain_id"], bid)
    if data["node_path"] != node.path:
        return "nodo %r invece di %r" % (data["node_path"], node.path)
    if canon(data["memory_dir"]) != canon(os.path.realpath(mem)):
        return ("memoria della transazione %s diversa da quella configurata ora %s"
                % (data["memory_dir"], Path(os.path.realpath(mem)).as_posix()))
    return ""


NOTE_NAME = "ANNULLAMENTO-DA-REGISTRARE.txt"


def proposal_problem(prop: Path, pdir: Path) -> str:
    """'' se `recover` puo' scrivere l'annullamento nella proposta registrata: file vero, nessun link/junction in
    NESSUN componente del percorso, dentro `workspace/dream/<node-key>/` del nodo registrato (giro 5, N10)."""
    if not str(prop) or str(prop) == ".":
        return "proposta non registrata nell'intento"
    raw = Path(os.path.abspath(str(prop)))
    bad = link_in_path(Path(raw.anchor), raw)
    if bad is not None:
        return "il percorso della proposta passa da un link/junction (%s)" % bad.as_posix()
    if norm_path(raw.parent) != norm_path(pdir):
        return "la proposta non sta in %s" % pdir.as_posix()
    if not raw.is_file():
        return "proposta assente (%s)" % raw.as_posix()
    if not is_within(canon(raw), canon(pdir)):
        return "la proposta esce da %s" % pdir.as_posix()
    return ""


def cmd_recover(a) -> int:
    """Ripristina i file dei gruppi interrotti dallo stato registrato in `<backup>/IN-CORSO.json`.
    Giro 4: (N8) l'intento deve essere di QUESTA transazione (brain, nodo, memoria realpath, review): altrimenti exit 2
    senza scrivere nulla; (#8) il gruppo ripristinato viene annullato nel registro della proposta (`Annullata: <id>`)
    PRIMA di rimuovere l'intento, cosi' apply lo considera non applicato e lo puo' riapplicare."""
    root, node = resolve(a)
    mi = require_safe_memory(root, node)
    bid = brain_id_of(root)
    bdir = backups_dir(root, node)
    bad = link_in_path(root, bdir)
    if bad is not None:
        raise Stop("%s e' un link/junction: recover rifiutato" % bad.as_posix())
    intents = pending_intents(bdir)
    if not intents:
        print("niente da recuperare: nessun apply interrotto per il nodo %s" % node.path)
        return 0
    loaded: list[tuple[Path, dict]] = []
    linked = 0
    for ip in intents:                                   # tutte le verifiche PRIMA di qualunque scrittura
        bad = link_in_path(root, ip)                     # giro 6 (N11): cartella temporale del backup compresa
        if bad is not None:
            linked += 1
            print(mask_secrets("ANNULLAMENTO-DA-REGISTRARE (non scritto: %s e' un link/junction): il registro di "
                               "intento %s sta fuori dal brain; nessun ripristino e nessuna scrittura. Riporta la "
                               "cartella del backup dentro %s (cartella vera, non link) e rilancia `dream.py recover`."
                               % (bad.as_posix(), ip.as_posix(), bdir.as_posix()))[0])
            continue
        try:
            data = json.loads(ip.read_text(encoding="utf-8"))
        except (OSError, ValueError) as e:
            raise Stop("registro di intento illeggibile %s: %s" % (ip.as_posix(), e)) from e
        why = intent_identity_problem(data, bid, node, mi.path)
        if why:
            raise Stop("recover rifiutato, nessuna scrittura: %s (%s)" % (why, ip.as_posix()))
        loaded.append((ip, data))
    errors = 0
    pending = 0
    pdir = proposals_dir(root, node)
    for ip, data in loaded:
        failed = []
        for entry in data.get("files", []):
            try:
                _restore_entry(mi.path, entry)
            except OSError as e:
                failed.append("%s: %s" % (entry.get("name"), e))
        names = ", ".join(str(e.get("name")) for e in data.get("files", []))
        if failed:
            errors += 1
            print("gruppo %s: ripristino FALLITO (%s); registro lasciato in %s"
                  % (data.get("group"), "; ".join(failed), ip.as_posix()))
            continue
        prop = Path(str(data.get("proposal") or ""))
        ids = [str(x) for x in data.get("items", [])]
        why = proposal_problem(prop, pdir)
        if not why:
            try:
                _append(prop, "\n## Recuperato %s\nGruppo: %s ripristinato allo stato precedente; non applicato\nAnnullata: %s\n"
                        % (dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), data.get("group"), ", ".join(ids)))
            except OSError as e:
                why = "scrittura dell'annullamento fallita: %s" % e
        note = ip.parent / NOTE_NAME
        if why:                                          # intento conservato: apply resta bloccato (giro 5, #8/N10)
            pending += 1
            note_text = ("Gruppo %s (voci %s) RIPRISTINATO in memoria, ma l'annullamento NON e' registrato\n"
                         "nella proposta %s: %s.\nRimetti la proposta in %s e rilancia `dream.py recover`.\n"
                         % (data.get("group"), ", ".join(ids), prop.as_posix(), why, pdir.as_posix()))
            bad_note = link_in_path(root, note)          # giro 6 (N11): mai scrivere la nota attraverso un link
            if bad_note is not None or is_link(note):
                print(mask_secrets("ANNULLAMENTO-DA-REGISTRARE (nota non scritta: %s e' un link):\n%s"
                                   % ((bad_note or note).as_posix(), note_text))[0])
            else:
                try:
                    _write_bytes(note, note_text.encode("utf-8"))
                except OSError as e:
                    print(mask_secrets("ANNULLAMENTO-DA-REGISTRARE (nota non scritta: %s):\n%s" % (e, note_text))[0])
            print("gruppo %s ripristinato in memoria (file: %s), ma l'annullamento NON e' registrato (%s): intento "
                  "conservato, vedi %s; rimetti la proposta in %s e rilancia `dream.py recover`"
                  % (data.get("group"), names, why, note.as_posix(), pdir.as_posix()))
            continue
        ip.unlink()                                      # solo DOPO il ripristino e l'annullamento nel registro
        if note.exists():
            note.unlink()
        print("gruppo %s ripristinato allo stato precedente (file: %s); voci annullate: %s"
              % (data.get("group"), names, ", ".join(ids)))
    if pending or linked:
        return 2
    return 1 if errors else 0


def cmd_apply(a) -> int:
    root, node = resolve(a)
    mi = require_safe_memory(root, node)
    mem = mi.path
    bid = brain_id_of(root)
    pdir = proposals_dir(root, node)
    bdir = backups_dir(root, node)
    bad = link_in_path(root, bdir)
    if bad is not None:
        raise Stop("%s e' un link/junction: backup rifiutato" % bad.as_posix())
    pending = pending_intents(bdir)
    if pending:
        raise Stop("un apply precedente si e' interrotto a meta' gruppo (%s): prima ripristina con "
                   "`dream.py recover`, poi rilancia apply" % pending[0].as_posix())
    prop = resolve_proposal(a.proposal, pdir, root, bid)
    try:
        text = prop.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as e:
        raise Stop("proposta illeggibile %s: %s" % (prop, e)) from e
    meta = parse_meta(text)
    if meta is None:
        raise Stop("proposta senza intestazione dream-meta valida (prima riga): rigenerala con /%s-dream review" % bid)
    mism = []
    if meta.get("brain_id") != bid:
        mism.append("brain %r invece di %r" % (meta.get("brain_id"), bid))
    if meta.get("node_path") != node.path:
        mism.append("nodo %r invece di %r" % (meta.get("node_path"), node.path))
    if not isinstance(meta.get("memory_dir"), str) or canon(meta["memory_dir"]) != canon(mem):
        mism.append("memoria %r invece di %r" % (meta.get("memory_dir"), mem.as_posix()))
    if mism:
        raise Stop("la proposta non e' di questo brain/nodo/memoria: " + "; ".join(mism))
    hashes = meta.get("hashes") if isinstance(meta.get("hashes"), dict) else {}
    items, applied = parse_proposal(text)

    # ---- validazione completa, prima di qualunque scrittura
    seen: dict[str, int] = {}
    for it in items:
        seen[it.id] = seen.get(it.id, 0) + 1
    sides: dict[str, set[str]] = {}
    for it in items:
        m = CONFLICT_RE.match(it.id)
        if m and it.checked and it.id not in applied:
            sides.setdefault(m.group("key"), set()).add(m.group("side"))
    conflicts = {k for k, s in sides.items() if s == {"tieni", "correggi"}}
    existing = {p.name for p in mem.iterdir() if p.is_file()} if mem.is_dir() else set()
    status: dict[int, str] = {}
    todo: list[Item] = []
    for it in items:
        k = id(it)
        if not it.checked:
            status[k] = "saltata (non spuntata)"
            continue
        if it.id in applied:
            status[k] = "saltata (gia' applicata)"
            continue
        err = it.error
        cm = CONFLICT_RE.match(it.id)
        if not err and seen[it.id] > 1:
            err = "id duplicato nella proposta"
        if not err and cm and cm.group("key") in conflicts:
            err = ("{%s-tieni} e {%s-correggi} entrambe spuntate: nessuna modifica per %s"
                   % (cm.group("key"), cm.group("key"), cm.group("key")))
        if not err and it.action in WRITE_ACTIONS:
            err = valid_name(it.filename) or target_ok(mem, it.filename)
        if not err and it.action in ("AGGIUNGI", "AGGIORNA"):
            err = "manca il blocco ```memoria con il contenuto completo" if it.block is None else validate_block(it.block)
        if not err and it.action == "AGGIUNGI" and it.filename in existing:
            err = "%s esiste gia': AGGIUNGI non sovrascrive (usa AGGIORNA)" % it.filename
        if not err and it.action in ("AGGIORNA", "RIMUOVI"):
            if it.filename not in existing:
                err = "%s non esiste nella memoria" % it.filename
            elif hashes.get(it.filename) != sha256_file(mem / it.filename):
                err = "%s cambiato dopo la review (hash diverso): rifai la review" % it.filename
        if not err and it.index_line is not None and it.action in ("AGGIUNGI", "AGGIORNA"):
            if it.filename not in index_targets(it.index_line):
                err = "la riga Indice non punta a %s" % it.filename
        if err:
            status[k] = "errore: " + err
            continue
        if it.action == "VAULT":
            status[k] = "da passare a %s-feed (apply non tocca il vault)" % bid
            continue
        todo.append(it)
        if it.action == "AGGIUNGI":
            existing.add(it.filename)
        elif it.action == "RIMUOVI":
            existing.discard(it.filename)
    # gruppi atomici: un errore in una voce spuntata blocca tutte le voci spuntate dello stesso gruppo
    failed_groups: dict[str, str] = {}
    for it in items:
        if status.get(id(it), "").startswith("errore") and it.checked and it.id not in applied:
            failed_groups.setdefault(it.group, it.id)
    for it in list(todo):
        if it.group in failed_groups:
            status[id(it)] = "errore: gruppo %s non applicato (errore in {%s})" % (it.group, failed_groups[it.group])
            todo.remove(it)
    for it in todo:
        status[id(it)] = "da applicare (dry-run)" if a.dry_run else "in corso"

    writes = [it for it in todo if it.action in WRITE_ACTIONS]
    backup: Path | None = None
    if todo and not a.dry_run:
        if writes:
            try:
                backup = make_backup(mem, bdir)
            except OSError as e:
                raise Stop("backup fallito (%s): nessuna modifica applicata" % e) from e
        stamp = dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        _append(prop, ("" if text.endswith("\n") else "\n") + "\n## Applicato %s\nBackup: %s\n"
                % (stamp, backup.as_posix() if backup else "nessuno (nessuna modifica)"))
        idx = mem / INDEX_NAME
        idx_lines = kc.read_text(idx).splitlines() if idx.is_file() else []
        groups: list[str] = []
        for it in todo:
            if it.group not in groups:
                groups.append(it.group)
        halted = False
        for g in groups:
            members = [it for it in todo if it.group == g]
            if halted:
                for it in members:
                    status[id(it)] = "errore: non applicata (apply fermato: serve `dream.py recover`)"
                continue
            # indice calcolato PRIMA di scrivere; registro di intento PRIMA delle scritture (#8)
            new_lines = list(idx_lines)
            names: list[str] = []
            for it in members:
                if it.action == "RIMUOVI":
                    new_lines = drop_index_line(new_lines, it.filename)
                elif it.action in WRITE_ACTIONS and it.index_line:
                    new_lines = set_index_line(new_lines, it.filename, it.index_line)
                if it.action in WRITE_ACTIONS and it.filename not in names:
                    names.append(it.filename)
            if new_lines != idx_lines:
                names.append(INDEX_NAME)
            intent_p = backup / INTENT_NAME if backup else None
            if names and intent_p is not None:
                _write_bytes(intent_p, json.dumps({
                    # identita' della transazione (giro 4, N8): recover la verifica prima di scrivere
                    "brain_id": bid, "node_path": node.path, "memory_dir": Path(os.path.realpath(mem)).as_posix(),
                    "review_id": str(meta.get("review_id") or ""),
                    "proposal": prop.as_posix(), "group": g, "items": [it.id for it in members],
                    "started": dt.datetime.now().isoformat(timespec="seconds"),
                    "files": [_snapshot_entry(mem, n) for n in names]}, ensure_ascii=False, indent=2).encode("utf-8"))
            try:
                for it in members:
                    if it.action not in WRITE_ACTIONS:
                        continue
                    why = target_ok(mem, it.filename)
                    if why:
                        raise OSError(why)
                    target = mem / it.filename
                    if it.action == "RIMUOVI":
                        target.unlink()
                    else:
                        _write(target, it.block or "")
                if new_lines != idx_lines:
                    if is_link(idx):
                        raise OSError("MEMORY.md e' un link: rifiutato")
                    _write(idx, "\n".join(new_lines) + "\n")
            except OSError as e:
                rb_errors = []
                intent = json.loads(intent_p.read_text(encoding="utf-8")) if intent_p and intent_p.is_file() else {"files": []}
                for entry in intent.get("files", []):
                    try:
                        _restore_entry(mem, entry)
                    except OSError as re_:
                        rb_errors.append("%s: %s" % (entry.get("name"), re_))
                if rb_errors:
                    halted = True
                    msg = ("errore: gruppo %s non applicato (%s); ripristino FALLITO (%s): lancia `dream.py recover`"
                           % (g, e, "; ".join(rb_errors)))
                else:
                    if intent_p is not None and intent_p.exists():
                        intent_p.unlink()
                    msg = "errore: gruppo %s non applicato (%s); file del gruppo ripristinati" % (g, e)
                for it in members:
                    status[id(it)] = msg
                continue
            _append(prop, "".join("Voce: %s\n" % it.id for it in members))   # registro dopo ogni gruppo
            if intent_p is not None and intent_p.exists():
                intent_p.unlink()                                             # gruppo completo
            idx_lines = new_lines
            for it in members:
                status[id(it)] = "applicata"

    errors = 0
    for it in items:
        s = status[id(it)]
        if s.startswith("errore"):
            errors += 1
        print(it.label + ": " + s)
    if not items:
        print("(nessuna voce nella proposta)")
    if a.dry_run:
        print("dry-run: nessuna modifica, nessun backup")
    elif backup is not None:
        print("backup: " + backup.as_posix())
    else:
        print("backup: nessuno (nessuna modifica da fare)")
    print("proposta: " + prop.as_posix())
    return 1 if errors else 0


# --------------------------------------------------------------------------- schedule-cmd

def _ps_quote(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def _sh_quote(s: str) -> str:
    return "'" + s.replace("'", "'\\''") + "'"


def _fwd(p: Path) -> str:
    s = str(p).replace("\\", "/")
    if re.match(r"^[a-zA-Z]:", s):
        s = s[0].upper() + s[1:]
    return s


def _rule_path(p: Path) -> str:
    """Forma dei path assoluti nelle regole dei permessi di Claude: `D:/x` -> `//d/x`; `/home/x` -> `//home/x`."""
    s = _fwd(p)
    m = re.match(r"^([A-Za-z]):/?(.*)$", s)
    if m:
        return "//" + m.group(1).lower() + "/" + m.group(2).strip("/")
    return "/" + s


def skill_command_prefix(root: Path) -> tuple[str, str]:
    """(PYTHON, BRAIN_ROOT) esattamente come resi nei comandi delle skill: dal contesto del manifest dello
    scaffolder; in mancanza, l'interprete corrente e la radice con slash in avanti."""
    try:
        ctx = json.loads(kc.read_text(root / ".template-manifest.json")).get("context") or {}
    except (OSError, ValueError, AttributeError):
        ctx = {}
    py = ctx.get("PYTHON") if isinstance(ctx.get("PYTHON"), str) else _fwd(Path(sys.executable))
    br = ctx.get("BRAIN_ROOT") if isinstance(ctx.get("BRAIN_ROOT"), str) else _fwd(root)
    return py, br


def cmd_schedule(a) -> int:
    root, node = resolve(a)
    bid = brain_id_of(root)
    day = a.day.upper()
    if day not in DAYS:
        raise Stop("--day ammette %s" % ", ".join(DAYS))
    if not re.match(r"^([01]\d|2[0-3]):[0-5]\d$", a.time):
        raise Stop("--time nel formato HH:MM (24 ore)")
    plat = a.platform if a.platform != "auto" else ("windows" if os.name == "nt" else "posix")
    prompt = "/%s-dream review" % bid
    py, br = skill_command_prefix(root)
    sess = '"%s" "%s/scripts/sessions.py"' % (py, br)
    drm = '"%s" "%s/scripts/dream.py"' % (py, br)
    # #28: un permesso per OGNI sottocomando usato dalla review (stessa forma dei comandi delle skill); mai apply
    rules = ["Skill", "Read",
             "Bash(%s *)" % sess,
             "Bash(%s paths)" % drm,
             "Bash(%s memory-report)" % drm, "Bash(%s memory-report --content)" % drm,
             "Bash(%s new-proposal)" % drm, "Bash(%s new-proposal --sessions-read *)" % drm,
             "Write(%s/workspace/dream/**)" % _rule_path(root), "Edit(%s/workspace/dream/**)" % _rule_path(root)]
    print("# dream.py NON registra nulla: copia e lancia tu i comandi qui sotto se vuoi la review periodica.")
    print("# Solo la review si schedula: apply resta sempre manuale (/%s-dream apply). Log: .tmp/dream-schedule.log" % bid)
    print("# Strumenti ammessi (minimi): Skill, Read, Bash solo per sessions.py e per i sottocomandi paths, memory-report,")
    print("# new-proposal di dream.py (MAI il sottocomando che modifica la memoria), Write/Edit solo in workspace/dream.")
    if plat == "windows":
        cwd = str(node.dir).replace("/", "\\")
        tools = " ".join(r if r in ("Skill", "Read") else '"%s"' % r.replace('"', '\\"') for r in rules)
        arg = ('/c cd /d "%s" && (if not exist .tmp mkdir .tmp) && claude -p "%s" --setting-sources project '
               '--output-format stream-json --verbose --allowedTools %s > .tmp\\dream-schedule.log 2>&1'
               % (cwd, prompt, tools))
        print("$azione = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument %s -WorkingDirectory %s"
              % (_ps_quote(arg), _ps_quote(cwd)))
        print("$quando = New-ScheduledTaskTrigger -Weekly -DaysOfWeek %s -At %s" % (DAY_NAME[day], _ps_quote(a.time)))
        print("Register-ScheduledTask -TaskName %s -Action $azione -Trigger $quando -Description %s"
              % (_ps_quote("brain-%s-dream" % bid), _ps_quote("Dream review settimanale del brain %s (solo proposta)" % bid)))
    else:
        hh, mm = a.time.split(":")
        tools = " ".join(r if r in ("Skill", "Read") else _sh_quote(r) for r in rules)
        print("%d %d * * %d cd %s && mkdir -p .tmp && claude -p %s --setting-sources project --output-format stream-json "
              "--verbose --allowedTools %s >> .tmp/dream-schedule.log 2>&1"
              % (int(mm), int(hh), CRON_DAY[day], _sh_quote(node.dir.as_posix()), _sh_quote(prompt), tools))
    return 0


# --------------------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    kc.utf8_stdout()
    ap = argparse.ArgumentParser(description="Dream: percorsi, stato della memoria, proposta, applicazione.")
    sub = ap.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("paths", help="memory dir (e se e' autorevole), cartella proposte, ultima proposta, backup")
    kc.add_common_args(p)
    p.add_argument("--json", action="store_true")
    p = sub.add_parser("memory-report", help="stato della memoria (solo lettura)")
    kc.add_common_args(p)
    p.add_argument("--json", action="store_true")
    p.add_argument("--content", action="store_true", help="anche il contenuto dei file (mascherato, max 200 KB)")
    p = sub.add_parser("new-proposal", help="crea la proposta vuota con l'intestazione macchina e ne stampa il path")
    kc.add_common_args(p)
    p.add_argument("--sessions-read", type=int, default=None, help="numero di sessioni lette da look-back")
    p = sub.add_parser("apply", help="applica SOLO le voci spuntate [x] della proposta")
    kc.add_common_args(p)
    p.add_argument("--proposal", default=None, help="file della proposta (default: la piu' recente del nodo)")
    p.add_argument("--dry-run", action="store_true", help="mostra cosa farebbe, senza scrivere ne' fare backup")
    p = sub.add_parser("schedule-cmd", help="STAMPA i comandi per schedulare la review (non li registra)")
    kc.add_common_args(p)
    p.add_argument("--day", default="MON", help="giorno della settimana: " + ", ".join(DAYS))
    p.add_argument("--time", default="09:00", help="ora HH:MM")
    p.add_argument("--platform", choices=["auto", "windows", "posix"], default="auto")
    p = sub.add_parser("recover", help="ripristina dal registro di intento i file di un gruppo interrotto")
    kc.add_common_args(p)
    a = ap.parse_args(argv)
    handlers = {"paths": cmd_paths, "memory-report": cmd_memory_report, "new-proposal": cmd_new_proposal,
                "apply": cmd_apply, "schedule-cmd": cmd_schedule, "recover": cmd_recover}
    # N2 (difesa in profondita'): TUTTO lo stdout passa da mask_secrets prima di essere stampato
    buf = io.StringIO()
    rc = 2
    try:
        with contextlib.redirect_stdout(buf):
            rc = handlers[a.cmd](a)
    except RootOutside as e:
        print(mask_secrets("ERRORE: %s" % e)[0], file=sys.stderr)
        rc = EXIT_ROOT_OUTSIDE
    except (kc.ConfigError, Stop) as e:
        print(mask_secrets("ERRORE: %s" % e)[0], file=sys.stderr)
        rc = 2
    finally:
        out = buf.getvalue()
        masked = mask_secrets(out)[0]
        if getattr(a, "json", False) and masked != out:
            try:
                json.loads(masked)
            except ValueError:
                masked = out                     # i campi sono gia' mascherati uno per uno (mask_obj)
        sys.stdout.write(masked)
        sys.stdout.flush()
    return rc


if __name__ == "__main__":
    sys.exit(main())
