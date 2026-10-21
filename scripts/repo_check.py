"""repo_check -- controllo applicativo di cio' che finisce su GitHub (Brain Builder v3.2).

SPEC v3.2 par. 4, par. 12 (G9, G14, G15) e par. 13.1 (v3.2.1). Un controllo applicativo forte, non una garanzia: formati
sconosciuti di segreti possono sfuggire; il modello di minaccia sono gli errori, non un avversario.

Cosa rifiuta (un problema per commit + path + tipo; MAI il valore di un segreto):
  - path vietati: `workspace/dream/` (proposte dream), ogni segmento che inizia con `.memory` (`.memory/`,
    `.memory-backup/`, `.memory-*`), memory dir personalizzate dei nodi (passate dal chiamante), `.secrets/`,
    `.env` e `.env.*` TRANNE `.env.example`;
  - politica dei file (par. 13.1, costanti in `kb_config`): `BLOCKED_EXTENSIONS` (video, audio, archivi, eseguibili)
    sempre, a qualunque dimensione; `SMALL_BINARY_EXTENSIONS` (pdf, immagini, Office) oltre `MAX_BINARY_MB` (5 MB);
    ogni blob oltre `MAX_FILE_MB` (10 MB). Il messaggio dice la regola;
  - contenuti con segreti (`secrets_scan.find_secrets`, cantiere D) in OGNI blob ammesso (fino al limite di
    dimensione): tutti i tipi a prefisso noto ovunque; le "assegnazioni" (chiave sensibile + valore) sono esenti
    SOLO quando il valore e' un riferimento: nome di variabile d'ambiente (`QDRANT_API_KEY`), `<segnaposto>`,
    `${VAR}`; nei file di codice anche un'espressione non quotata (`os.environ["X"]`, `secrets.token_hex(8)`,
    `{self.key}`). Un letterale (quotato, numerico, alfanumerico) non e' esente; unica eccezione dichiarata: nel
    codice un letterale quotato di 1-3 caratteri (esempi di documentazione come "a b"). I binari ammessi
    (`SMALL_BINARY_EXTENSIONS`) NON si scansionano come testo (limite dichiarato: un segreto dentro un pdf/docx sfugge).

Insiemi controllati:
  outgoing  -> tutti gli oggetti nuovi per QUELLA destinazione: `git rev-list --objects <ref> --not
               --remotes=<remote>` (tutta la storia se il remote non ha ref), piu' `diff-tree -m` per commit
               per dire in quale commit compare il blob: coperti i merge (anche cio' che la risoluzione aggiunge)
               e i commit gia' su ALTRI remote ma nuovi per questo; un file aggiunto e poi cancellato resta;
  staged    -> i blob nello staging (prima del commit di brain_sync);
  tracked   -> i blob dell'albero di HEAD (workflow `brain-check` in CI).

Uso:
    python scripts/repo_check.py [--root R] --tracked          # CI: albero di HEAD
    python scripts/repo_check.py [--root R] --outgoing [--ref B] # commit non ancora su nessun remote
Exit: 0 nessun problema, 8 problemi trovati, 3 errore di configurazione/git.
"""
from __future__ import annotations

import argparse
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kb_config as kc  # noqa: E402

try:
    from secrets_scan import find_secrets  # noqa: E402  (cantiere D, API stabile)
except ImportError:  # pragma: no cover - il motore installato lo contiene sempre
    find_secrets = None

ALLOWED_ENV_FILES = {".env.example"}
CODE_EXTENSIONS = {".py", ".pyw", ".mjs", ".cjs", ".js", ".ts", ".ps1", ".psm1", ".sh", ".bat", ".cmd"}
FORBIDDEN_SEQUENCES = (("workspace", "dream"),)
FORBIDDEN_SEGMENTS = {".secrets"}
FORBIDDEN_PREFIX = ".memory"          # .memory/, .memory-backup/, .memory-<qualunque>/
MAX_SCAN_BYTES = kc.MAX_FILE_MB * 1024 * 1024   # ogni blob ammesso si legge tutto (oltre il limite e' gia' rifiutato)
# Riferimenti (MAI re.I: una password alfanumerica non e' un nome di variabile): nome di variabile d'ambiente con
# almeno un "_" (QDRANT_API_KEY), <segnaposto>, ${VAR} / $VAR, %VAR%, mascherature evidenti, valori nulli.
_REFERENCE_VALUE = re.compile(r"^(?:[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+|<[^>]*>?|\$\{[A-Za-z_]\w*\}?|\$[A-Za-z_]\w*|%[A-Za-z_]\w*%|"
                              r"\*+|x{3,}|X{3,}|\.{3}|null|None|none|true|false|True|False|\[SEGRETO-MASCHERATO:.*)$")
# Nel codice: un'espressione NON quotata (nome, attributo, chiamata, indice, segnaposto di format `{self.key}`,
# inizio di una struttura `{`/`[`, sequenza di escape), mai un letterale.
_CODE_REFERENCE = re.compile(r"^(?:[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*(?:[\[(].*)?|\{[A-Za-z_][\w.]*\}.*|[{\[].*|\\.*)$")
# Nel codice, un letterale quotato di 1-3 caratteri (`"a b"`, `'x'`) e' un esempio di documentazione, non una
# credenziale: limite dichiarato (README del motore, sez. 10).
CODE_MIN_LITERAL = 4


@dataclass(frozen=True)
class Problem:
    commit: str      # sha corto, "staging" o "HEAD"
    path: str
    kind: str        # descrizione del tipo, mai il valore

    def line(self) -> str:
        return f"  {self.commit:8}  {self.path}  ->  {self.kind}"


class RepoCheckError(RuntimeError):
    pass


def _git(root: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=True, input=input_bytes,
                          stdin=None if input_bytes is not None else subprocess.DEVNULL)


def path_reason(path: str, extra_prefixes: tuple[str, ...] = ()) -> str | None:
    """Motivo per cui `path` (relativo alla radice del repo, separatore /) non puo' andare su GitHub."""
    p = PurePosixPath(path.replace("\\", "/"))
    parts = p.parts
    low = [x.lower() for x in parts]
    for seg in low:
        if seg in FORBIDDEN_SEGMENTS or seg.startswith(FORBIDDEN_PREFIX):
            return f"percorso vietato ({seg}/)"
    for i in range(len(low) - 1):
        for seq in FORBIDDEN_SEQUENCES:
            if tuple(low[i:i + len(seq)]) == seq:
                return "percorso vietato (" + "/".join(seq) + "/: proposte dream)"
    for seg in low:
        if seg.startswith(".env") and seg not in ALLOWED_ENV_FILES:
            return "percorso vietato (.env*: solo .env.example e' ammesso)"
    norm = "/".join(low)                      # #9: confronto case-insensitive (Windows) con separatori normalizzati
    for pre in extra_prefixes:
        pre = pre.replace("\\", "/").strip("/").lower()
        if pre and (norm == pre or norm.startswith(pre + "/")):
            return f"percorso vietato (memoria del nodo: {pre}/)"
    cat = kc.blocked_category(p.suffix)
    if cat:
        return f"{cat} ({p.suffix.lower()}): sempre fuori da git, a qualunque dimensione"
    return None


def is_small_binary(path: str) -> bool:
    return PurePosixPath(path.replace("\\", "/")).suffix.lower() in kc.SMALL_BINARY_EXTENSIONS


def size_reason(path: str, size: int) -> str | None:
    """Motivo per cui un blob ammesso per path e' troppo grande: > MAX_FILE_MB per ogni file, > MAX_BINARY_MB per i
    binari piccoli (par. 13.1). MiB, come il controllo di GitHub."""
    if size > kc.MAX_FILE_MB * 1024 * 1024:
        return f"file di {size / 1048576:.1f} MB (> {kc.MAX_FILE_MB} MB)"
    if is_small_binary(path) and size > kc.MAX_BINARY_MB * 1024 * 1024:
        ext = PurePosixPath(path.replace("\\", "/")).suffix.lower().lstrip(".")
        return f"{ext} di {size / 1048576:.1f} MB: oltre {kc.MAX_BINARY_MB} MB per i binari (l'originale sta fuori dal repo)"
    return None


def _assignment_is_reference(text: str, s: int, e: int, code: bool) -> bool:
    """Il valore text[s:e] di un'assegnazione e' un riferimento (esente) e non un letterale?"""
    v = text[s:e].strip()                     # #14: nessun rstrip/lstrip che svuoti il valore (`))))` e' un valore)
    v = v.strip("`") or v                     # solo i delimitatori di codice Markdown, e mai fino a svuotarlo
    if not v or re.fullmatch(r"[|>][-+]?", v):    # indicatori di blocco YAML (pipe o maggiore dopo la chiave): il valore e' sotto
        return True
    quoted = s > 0 and text[s - 1] in "\"'"
    if _REFERENCE_VALUE.match(v.strip("\"'")):
        return True
    if not code:
        return False
    if quoted:
        return len(v) < CODE_MIN_LITERAL
    return bool(_CODE_REFERENCE.match(v)) and not v.replace(".", "").isdigit()


def decode_text(data: bytes) -> str | None:
    """Testo del blob: UTF-8, oppure UTF-16/UTF-32 riconosciuti dal BOM o dal pattern dei NUL alternati (#14).
    None = binario vero (nessuna scansione dei contenuti)."""
    boms = ((b"\xff\xfe\x00\x00", "utf-32-le"), (b"\x00\x00\xfe\xff", "utf-32-be"),
            (b"\xff\xfe", "utf-16-le"), (b"\xfe\xff", "utf-16-be"))
    for bom, enc in boms:
        if data.startswith(bom):
            return data[len(bom):].decode(enc, errors="replace")
    head = data[:8192]
    if b"\0" not in head:
        return data.decode("utf-8", errors="replace")
    n = len(head) - len(head) % 4
    if n >= 8:
        q = [head[i::4] for i in range(4)]
        if not any(q[1]) and not any(q[2]) and not any(q[3]) and any(q[0]):
            return data.decode("utf-32-le", errors="replace")
        if not any(q[0]) and not any(q[1]) and not any(q[2]) and any(q[3]):
            return data.decode("utf-32-be", errors="replace")
    even, odd = head[0::2], head[1::2]
    if len(head) >= 4 and odd.count(0) >= 0.9 * len(odd) and even.count(0) < 0.1 * len(even):
        return data.decode("utf-16-le", errors="replace")
    if len(head) >= 4 and even.count(0) >= 0.9 * len(even) and odd.count(0) < 0.1 * len(odd):
        return data.decode("utf-16-be", errors="replace")
    return None


def secret_kinds(path: str, data: bytes) -> list[str]:
    """Tipi di segreto trovati nel contenuto (mai i valori). Binari veri saltati; UTF-16/32 decodificati."""
    if find_secrets is None:
        return ["scansione dei segreti non eseguibile: secrets_scan.py assente accanto a repo_check.py"]
    text = decode_text(data)
    if text is None:
        return []
    code = PurePosixPath(path).suffix.lower() in CODE_EXTENSIONS
    kinds: list[str] = []
    for kind, s, e in find_secrets(text):
        if kind == "assegnazione" and _assignment_is_reference(text, s, e, code):
            continue
        if kind not in kinds:
            kinds.append(kind)
    return kinds


def _parse_raw(out: bytes) -> list[tuple[str, str, str]]:
    """Output `-z` di diff-tree/diff --raw -> [(status, blob nuovo, path)] per A/M/T (le cancellazioni no)."""
    items: list[tuple[str, str, str]] = []
    toks = out.split(b"\0")
    i = 0
    while i < len(toks):
        meta = toks[i].decode("utf-8", "replace")
        if not meta.startswith(":"):
            i += 1
            continue
        fields = meta[1:].split()
        status = fields[4][:1] if len(fields) >= 5 else "?"
        newsha = fields[3] if len(fields) >= 4 else ""
        path = toks[i + 1].decode("utf-8", "replace") if i + 1 < len(toks) else ""
        i += 2
        if status in ("C", "R"):          # con -M/-C ci sarebbero due path: non li chiediamo mai
            path = toks[i].decode("utf-8", "replace") if i < len(toks) else path
            i += 1
        if status in ("A", "M", "T", "C", "R") and set(newsha) != {"0"}:
            items.append((status, newsha, path))
    return items


def _object_info(root: Path, shas: list[str]) -> dict[str, tuple[str, int]]:
    """sha -> (tipo, dimensione) con una sola chiamata `cat-file --batch-check`."""
    if not shas:
        return {}
    r = _git(root, "cat-file", "--batch-check", input_bytes=("\n".join(shas) + "\n").encode())
    out: dict[str, tuple[str, int]] = {}
    for ln in r.stdout.decode("utf-8", "replace").splitlines():
        f = ln.split()
        if len(f) == 3 and f[2].isdigit():
            out[f[0]] = (f[1], int(f[2]))
    return out


def _blob_sizes(root: Path, shas: list[str]) -> dict[str, int]:
    return {k: v[1] for k, v in _object_info(root, shas).items()}


def _blob_contents(root: Path, shas: list[str]) -> dict[str, bytes]:
    if not shas:
        return {}
    r = _git(root, "cat-file", "--batch", input_bytes=("\n".join(shas) + "\n").encode())
    data, out, pos = r.stdout, {}, 0
    while pos < len(data):
        nl = data.find(b"\n", pos)
        if nl < 0:
            break
        head = data[pos:nl].decode("utf-8", "replace").split()
        pos = nl + 1
        if len(head) != 3 or not head[2].isdigit():
            continue
        size = int(head[2])
        out[head[0]] = data[pos:pos + size]
        pos += size + 1
    return out


def scan_note(stats: dict | None) -> str:
    """Esito della scansione dei contenuti (revisione Astra v3.2.1, rilievo 3): mai "senza segreti" in assoluto, e i
    binari ammessi (che non si scansionano come testo) contati a parte."""
    n = int((stats or {}).get("unscanned", 0))
    note = "nessun segreto rilevato nei contenuti scansionati"
    if n:
        note += f"; {n} binari ammessi non scansionati: pdf/immagini/Office \u2264 {kc.MAX_BINARY_MB} MB"
    return note


def check_blobs(root: Path, entries: list[tuple[str, str, str]], extra_prefixes: tuple[str, ...] = (),
                stats: dict | None = None) -> list[Problem]:
    """entries = [(commit-etichetta, blob sha, path)]. Ogni blob letto una volta sola. `stats["unscanned"]` = path dei
    binari ammessi (SMALL_BINARY_EXTENSIONS entro i limiti), che non si scansionano come testo."""
    problems: list[Problem] = []
    unscanned: set[str] = set()
    shas = sorted({sha for _c, sha, _p in entries})
    sizes = _blob_sizes(root, shas)
    to_scan = sorted({sha for _c, sha, p in entries
                      if path_reason(p, extra_prefixes) is None and not is_small_binary(p)
                      and sizes.get(sha, 0) <= MAX_SCAN_BYTES})
    contents = _blob_contents(root, to_scan)
    found_cache: dict[tuple[str, str], list[str]] = {}
    for commit, sha, path in entries:
        why = path_reason(path, extra_prefixes)
        if why:
            problems.append(Problem(commit, path, why))
            continue
        big = size_reason(path, sizes.get(sha, 0))
        if big:
            problems.append(Problem(commit, path, big))
            continue
        if is_small_binary(path):
            unscanned.add(path)
        if sha in contents:
            key = (sha, PurePosixPath(path).suffix.lower())
            if key not in found_cache:
                found_cache[key] = secret_kinds(path, contents[sha])
            for k in found_cache[key]:
                problems.append(Problem(commit, path, f"possibile segreto nel contenuto ({k})"))
    if stats is not None:
        stats["unscanned"] = len(unscanned)
    return problems


def outgoing_commits(root: Path, ref: str = "HEAD", remote: str = "origin") -> list[str]:
    """Commit raggiungibili da `ref` e non dai ref di `remote` (refs/remotes/<remote>/*): nuovi per QUELLA destinazione."""
    r = _git(root, "rev-list", "--reverse", ref, "--not", f"--remotes={remote}")
    if r.returncode != 0:
        raise RepoCheckError(f"git rev-list fallito: {r.stderr.decode('utf-8', 'replace').strip()[:200]}")
    return [x for x in r.stdout.decode().split() if x]


def outgoing_problems(root: Path, ref: str = "HEAD", extra_prefixes: tuple[str, ...] = (),
                      remote: str = "origin", stats: dict | None = None) -> tuple[list[str], list[Problem]]:
    """(commit in uscita, problemi). Insieme = TUTTI gli oggetti nuovi per `remote` (`rev-list --objects`), quindi
    anche i blob dei merge e di ogni genitore; `diff-tree -m` per commit serve solo a dire in quale commit compare."""
    commits = outgoing_commits(root, ref, remote)
    entries: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for c in commits:
        r = _git(root, "diff-tree", "-m", "-r", "--no-commit-id", "--root", "--no-renames", "-z", c)
        if r.returncode != 0:
            raise RepoCheckError(f"git diff-tree {c[:8]} fallito")
        for _st, sha, p in _parse_raw(r.stdout):
            if (sha, p) not in seen:
                seen.add((sha, p))
                entries.append((c[:8], sha, p))
    r = _git(root, "rev-list", "--objects", ref, "--not", f"--remotes={remote}")
    if r.returncode != 0:
        raise RepoCheckError(f"git rev-list --objects fallito: {r.stderr.decode('utf-8', 'replace').strip()[:200]}")
    objs: list[tuple[str, str]] = []
    for ln in r.stdout.decode("utf-8", "replace").splitlines():
        sha, _, path = ln.partition(" ")
        if path:
            objs.append((sha, path))
    info = _object_info(root, sorted({s for s, _p in objs}))
    covered = {sha for _c, sha, _p in entries}
    for sha, path in objs:
        if info.get(sha, ("?", 0))[0] == "blob" and sha not in covered:
            covered.add(sha)
            entries.append(("oggetto", sha, path))
    return commits, check_blobs(root, entries, extra_prefixes, stats)


def staged_problems(root: Path, extra_prefixes: tuple[str, ...] = (), stats: dict | None = None) -> list[Problem]:
    has_head = _git(root, "rev-parse", "--verify", "--quiet", "HEAD").returncode == 0
    args = ["diff", "--cached", "--raw", "--no-renames", "-z", "--abbrev=40"]
    if not has_head:
        args.append("4b825dc642cb6eb9a060e54bf8d69288fbee4904")   # albero vuoto
    r = _git(root, *args)
    return check_blobs(root, [("staging", sha, p) for _st, sha, p in _parse_raw(r.stdout)], extra_prefixes, stats)


def tracked_problems(root: Path, ref: str = "HEAD", extra_prefixes: tuple[str, ...] = (),
                     stats: dict | None = None) -> list[Problem]:
    r = _git(root, "ls-tree", "-r", "-z", ref)
    if r.returncode != 0:
        raise RepoCheckError(f"git ls-tree {ref} fallito: {r.stderr.decode('utf-8', 'replace').strip()[:200]}")
    entries = []
    for rec in r.stdout.split(b"\0"):
        if not rec:
            continue
        meta, _, path = rec.partition(b"\t")
        f = meta.decode().split()
        if len(f) == 3 and f[1] == "blob":
            entries.append((ref, f[2], path.decode("utf-8", "replace")))
    return check_blobs(root, entries, extra_prefixes, stats)


def memory_prefixes(root: Path) -> tuple[str, ...]:
    """Memory dir dei nodi che cadono dentro la radice: path relativi vietati. Fonte UNICA: `autoMemoryDirectory` dei
    `.claude/settings.json` di radice e nodi (#9: MAI `BRAIN_MEMORY_DIR` dell'ambiente, che toglierebbe l'esclusione);
    i default `.memory*` sono gia' vietati da `path_reason`."""
    import json as _json
    out: list[str] = []
    try:
        nodes = kc.iter_nodes(root)
    except kc.ConfigError:
        nodes = []
    dirs = [Path(root)] + [n.dir for n in nodes]
    for d in dirs:
        sp = d / ".claude" / "settings.json"
        try:
            amd = _json.loads(sp.read_text(encoding="utf-8-sig")).get("autoMemoryDirectory")
        except (OSError, ValueError, AttributeError):
            continue
        if not isinstance(amd, str) or not amd.strip():
            continue
        try:
            rel = Path(amd).resolve().relative_to(Path(root).resolve()).as_posix()
        except (ValueError, OSError):
            continue
        if rel and rel != "." and rel not in out:
            out.append(rel)
    return tuple(out)


def report(problems: list[Problem], header: str) -> None:
    print(header)
    for p in problems:
        print(p.line())


def main(argv: list[str] | None = None) -> int:
    kc.utf8_stdout()
    ap = argparse.ArgumentParser(description="Controllo applicativo dei file destinati a GitHub (exit 8 se trova problemi).")
    ap.add_argument("--root", default=".", help="radice del repository (default: cwd)")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--tracked", action="store_true", help="blob dell'albero di --ref (default HEAD): usato dal workflow brain-check")
    g.add_argument("--outgoing", action="store_true", help="blob di ogni commit non ancora su un remote")
    ap.add_argument("--ref", default="HEAD")
    a = ap.parse_args(argv)
    root = Path(a.root).resolve()
    stats: dict = {}
    try:
        prefixes = memory_prefixes(root)
        if a.tracked:
            probs = tracked_problems(root, a.ref, prefixes, stats)
            what = f"file tracciati in {a.ref}"
        else:
            commits, probs = outgoing_problems(root, a.ref, prefixes, stats=stats)
            what = f"{len(commits)} commit in uscita"
    except RepoCheckError as e:
        print(f"ERRORE: {e}")
        return 3
    if probs:
        report(probs, f"RIFIUTATO: {len(probs)} problemi nei {what} (commit, path, tipo):")
        return 8
    print(f"OK: nessun file vietato o pesante nei {what}; {scan_note(stats)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
