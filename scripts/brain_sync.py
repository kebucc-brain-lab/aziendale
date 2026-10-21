"""brain_sync -- il comando unico che porta il brain allo stato consistente.

Forkato da `scripts/brain_sync.py` di VMR Brain (HEAD 0efa9254). Cosa cambia:
  - LOCK file (`<root>/.tmp/brain_sync.lock`): due sync concorrenti non si pestano; un
    lock piu' vecchio di 2 ore e' considerato morto e viene sostituito (lo si dice);
  - tolto `build_catalog.py` (catalogo type/asset di VMR: non generico);
  - catena: bump `updated:` (giorno LOGICO) -> lint -> llms.txt -> ingest incrementale
    (saltato se nessun .md e' cambiato per mtime; ABORT su Qdrant non affidabile, exit 2,
    niente commit) -> commit SOLO con pathspec (cartelle del profilo + zone grezze +
    llms.txt + governance GitHub alla radice + stati condivisi dell'indice; MAI `git add -A`,
    mai .env/.secrets; `workspace/dream/` e `.memory-backup/` esclusi esplicitamente);
  - staging NON vuoto prima del sync = stop (non si committano file altrui per sbaglio);
  - v3.2: destinazione validata da `github:` di brain.yaml (none | personal | org) contro origin;
    push per PERMESSO (`gh api repos/<o>/<r> --jq .permissions.push`), mai login == owner;
    `personal` = commit + push sul ramo corrente; `org` = MAI su main: branch `sync/<giorno>-<login>`,
    push del branch, `gh pr create --repo <o>/<r>`, poi si ferma (merge squash di un'altra persona);
  - v3.2: prima del commit e prima di OGNI push, controllo applicativo (repo_check.py) dello staging e
    di tutti i commit in uscita: path vietati, video/audio/archivi (sempre), binari > 5 MB, file > 10 MB, segreti -> exit 8
    (politica dei file: SPEC v3.2 par. 13.1, costanti in kb_config);
  - per nodo (cwd/--node) o `--all-nodes` per tutto l'albero;
  - v3.2.1 (SPEC v3.2 par. 13.3): `--ops <path...>` committa A PARTE il lavoro operativo (`ops/`, che il sync del
    vault non committa mai): niente bump/lint/llms/ingest, solo i path dati (dentro una `ops_dirs` di un nodo,
    altrimenti exit 3), commit `ops: <msg>` (default `ops <giorno> <path principale>`), poi lo STESSO push del sync
    (validazione della destinazione, repo_check sui commit in uscita, personal -> main per permesso, org -> branch + PR).

Uso:
    python scripts/brain_sync.py [--node P | --all-nodes] [--no-ingest] [--no-commit] [--no-push]
                                 [--dry-run-git] [-m "msg"]
    python scripts/brain_sync.py --ops <path> [<path> ...] [-m "msg"] [--no-push] [--dry-run-git]

Exit: 0 ok; 1 lint; 2 store non affidabile; 3 config (anche: path di --ops fuori dalle ops_dirs); 4 lock; 5 staging non vuoto; 6 commit fallito;
      7 stop in modalita' org (branch non gestito, PR chiusa, gh in errore, main con commit propri);
      8 file vietati/pesanti/segreti; 9 destinazione GitHub non valida.

Primo sync di un brain appena generato (senza Qdrant ne' remote ancora configurati):
    python scripts/brain_sync.py --no-ingest --no-commit      # solo i gate: lint + llms.txt
    python scripts/brain_sync.py --no-ingest --no-push        # + commit locale, nessun push
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kb_config as kc  # noqa: E402
import repo_check  # noqa: E402

SCRIPTS = Path(__file__).resolve().parent
LOCK_MAX_AGE = 2 * 3600


class SyncAbort(SystemExit):
    pass


def run(label: str, cmd: list[str], cwd: Path) -> None:
    print(f"\n== {label} ==", flush=True)
    r = subprocess.run(cmd, cwd=str(cwd))
    if r.returncode != 0:
        print(f"FALLITO: {label} (exit {r.returncode}). Sync interrotto.")
        raise SyncAbort(r.returncode)


def git(root: Path, *args: str, check: bool = False, capture: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(root), *args], capture_output=capture, text=True,
                          encoding="utf-8", errors="replace", check=check, stdin=subprocess.DEVNULL)


# ----------------------------------------------------------------------------
# Lock
# ----------------------------------------------------------------------------
class Lock:
    def __init__(self, root: Path):
        self.path = root / ".tmp" / "brain_sync.lock"
        self.fd = None

    def __enter__(self):
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                self.fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self.fd, f"{os.getpid()} {time.time():.0f}\n".encode())
                return self
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                    owner = self.path.read_text(encoding="utf-8", errors="replace").strip()
                except OSError:
                    age, owner = 0, "?"
                if age > LOCK_MAX_AGE:
                    print(f"[sync] lock vecchio di {age / 3600:.1f} h ({owner}): lo considero morto e lo sostituisco")
                    self.path.unlink(missing_ok=True)
                    continue
                print(f"[sync] un altro brain_sync e' in corso (lock {self.path}, pid/ts {owner}). Riprova piu' tardi.")
                raise SyncAbort(4)
        raise SyncAbort(4)

    def __exit__(self, *exc):
        if self.fd is not None:
            os.close(self.fd)
        self.path.unlink(missing_ok=True)


# ----------------------------------------------------------------------------
# Passi
# ----------------------------------------------------------------------------
def vault_hash(root: Path, targets: list[kc.Node], nodes: list[kc.Node]) -> str:
    """Hash di path+mtime delle note compilate + sessioni dei nodi scelti: se non cambia,
    l'ingest si salta senza nemmeno aprire Qdrant."""
    h = hashlib.sha256()
    for n in targets:
        extra = kc.iter_travaso_files(root) if n.is_root else []       # v3.3: la zona travaso entra nell'ingest
        for p in [*kc.iter_notes(n, nodes), *kc.iter_sessions(n), *extra]:
            h.update(n.rel_root(p).encode())
            h.update(str(p.stat().st_mtime_ns).encode())
    return h.hexdigest()


def bump_updated(root: Path, targets: list[kc.Node]) -> None:
    """`updated:` = giorno logico di oggi sulle note del vault MODIFICATE rispetto a HEAD
    (solo file tracciati e cambiati: i nuovi hanno gia' la loro data). Best-effort."""
    today = kc.logical_today().isoformat()
    folders = []
    for n in targets:
        folders += [n.rel_root(n.dir / f) for f in n.profile.folders if (n.dir / f).is_dir()]
    if not folders:
        return
    try:
        r = git(root, "diff", "--name-only", "HEAD", "--", *folders)
        changed = [ln.strip() for ln in r.stdout.splitlines() if ln.strip().endswith(".md")]
    except Exception:  # noqa: BLE001
        return
    cnt = 0
    for rel in changed:
        p = root / rel
        if not p.is_file():
            continue
        txt = kc.read_text(p)
        m = re.match(r"^(---\s*\n)(.*?)(\n---\s*\n)", txt, re.S)
        if not m:
            continue
        fm = m.group(2)
        um = re.search(r"^updated:\s*(\S+)\s*$", fm, re.M)
        if not um or um.group(1).strip("\"'") == today:
            continue
        fm2 = fm[:um.start(1)] + today + fm[um.end(1):]
        kc.write_text(p, m.group(1) + fm2 + m.group(3) + txt[m.end():])
        cnt += 1
    if cnt:
        print(f"\n== updated == {cnt} note modificate portate a {today}")


# ----------------------------------------------------------------------------
# Git e GitHub (v3.2): destinazione validata, push per PERMESSO, modalita' org con branch + PR
# ----------------------------------------------------------------------------
GH_TIMEOUT = 20
ORG_BASE = "main"
EXIT_STOP = 7        # branch non gestito, PR chiusa, gh in errore, main locale con commit propri
EXIT_REFUSED = 8     # file vietati/pesanti/segreti nello staging o nei commit in uscita
EXIT_DEST = 9        # destinazione GitHub non valida: modalita', origin vs owner/repo, tipo di owner
GOVERNANCE_ROOT = (".github", "INDICE.md", "TEAM.md", "SECURITY.md", "decisioni", "docs", "travaso.yaml")   # v3.3: travaso.yaml (par. 14.20)
EXCLUDE_ALWAYS = ("workspace/dream", ".memory-backup")
EXIT_TRAVASO = 10    # v3.3: il travaso (post-passo) e' fallito; il sync resta buono
EXIT_VERIFY = 13     # v3.3: travaso "da verificare": l'agente deve eseguire `<id>-travaso verifica` e rilanciare con --verdetto
TRAVASO_SUBS = ("send", "verifica", "stato", "decisioni", "check")


def _q(a: str) -> str:
    return f'"{a}"' if (" " in a or not a) else a


class Runner:
    """git e gh per brain_sync. Con --dry-run-git le operazioni di sola lettura girano davvero, quelle che
    cambiano qualcosa (repo locale, remote, GitHub) vengono SOLO stampate con il prefisso [dry-run-git]."""

    def __init__(self, root: Path, dry: bool = False):
        self.root = root
        self.dry = dry
        self.gh_exe = shutil.which("gh")
        self.ops_nodes: list[kc.Node] | None = None   # --ops: dopo `git add` lo staging reale deve stare nelle ops_dirs
        self.coerenza = False                         # v3.3: brain `merge: coerenza` -> check --staged prima del commit, check --pr dopo la PR
        self.travaso_rc = 0                           # v3.3: esito peggiore dei check del travaso (0 ok, 12 rinviato, altro = fallito)
        self.pr_number: int | None = None

    def git(self, *args: str, write: bool = False, input_text: str | None = None) -> subprocess.CompletedProcess:
        if write and self.dry:
            print("[dry-run-git] git " + " ".join(_q(a) for a in args))
            return subprocess.CompletedProcess(list(args), 0, "", "")
        kw = {"input": input_text} if input_text is not None else {"stdin": subprocess.DEVNULL}
        return subprocess.run(["git", "-C", str(self.root), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", **kw)

    def gh(self, *args: str, write: bool = False, input_text: str | None = None) -> subprocess.CompletedProcess | None:
        """None = gh assente, timeout o non eseguibile."""
        if self.gh_exe is None:
            return None
        if write and self.dry:
            print("[dry-run-git] gh " + " ".join(_q(a) for a in args) + (" (corpo da stdin)" if input_text else ""))
            return subprocess.CompletedProcess(list(args), 0, "", "")
        kw = {"input": input_text} if input_text is not None else {"stdin": subprocess.DEVNULL}
        try:
            return subprocess.run([self.gh_exe, *args], capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=GH_TIMEOUT, cwd=str(self.root), **kw)
        except (OSError, subprocess.TimeoutExpired):
            return None

    # --- letture git di comodo
    def has_ref(self, ref: str) -> bool:
        return self.git("rev-parse", "--verify", "--quiet", ref).returncode == 0

    def count(self, rng: str) -> int:
        out = self.git("rev-list", "--count", rng).stdout.strip()
        return int(out) if out.isdigit() else 0

    def is_ancestor(self, a: str, b: str) -> bool:
        return self.git("merge-base", "--is-ancestor", a, b).returncode == 0

    def current_branch(self) -> str | None:
        r = self.git("symbolic-ref", "--short", "-q", "HEAD")
        return r.stdout.strip() or None if r.returncode == 0 else None


def parse_github(url: str | None) -> tuple[str, str] | None:
    """(owner, repo) di un URL GitHub https o ssh; None altrimenti."""
    m = re.search(r"github\.com[:/]+([^/\s]+)/([^/\s]+?)(?:\.git)?/?$", url or "")
    return (m.group(1), m.group(2)) if m else None


def remote_owner(root: Path) -> tuple[str | None, str | None]:
    """(owner, url) del remote `origin` com'e' scritto in config (senza riscritture insteadOf)."""
    r = git(root, "config", "--get", "remote.origin.url")
    url = r.stdout.strip() if r.returncode == 0 else ""
    if not url:
        return None, None
    gh = parse_github(url)
    return (gh[0] if gh else None), url


@dataclass
class Dest:
    mode: str
    owner: str = ""
    repo: str = ""
    url: str | None = None
    problem: str = ""    # non vuoto: destinazione non valida -> nessun push (exit 9)
    note: str = ""       # non vuoto: nessun push previsto (none, remote assente o non GitHub), non e' un errore
    merge: str = "review"   # v3.3: review | coerenza (github.merge)


def destination(root: Path) -> Dest:
    """Validazione BLOCCANTE della destinazione (SPEC v3.2 par. 12 G10): sezione `github:` di brain.yaml contro
    `remote.origin.url`. Il controllo del tipo di owner (personal -> mai un'organizzazione) e del permesso
    richiede gh e si fa al momento del push."""
    cfg = kc.github_config(root)
    mode = cfg.get("mode", "")
    _owner, url = remote_owner(root)
    gh = parse_github(url)
    d = Dest(mode=mode or "", owner=cfg.get("owner", ""), repo=cfg.get("repo", ""), url=url, merge=cfg.get("merge") or "review")
    if url is None:
        if mode in ("personal", "org"):
            d.problem = (f"github.mode {mode} ma nessun remote `origin`: "
                         f"git remote add origin https://github.com/{d.owner or '<owner>'}/{d.repo or '<repo>'}.git")
        else:
            d.note = "nessun remote `origin`: push saltato"
    elif gh is None:
        if mode in ("personal", "org"):
            d.problem = f"origin ({url}) non e' un repository GitHub ma github.mode e' {mode}"
        else:
            d.note = f"remote non GitHub ({url}): push manuale -> git push"
    elif not mode:
        d.problem = ("origin e' su GitHub ma brain.yaml non dichiara `github.mode` (none|personal|org): nessun push. "
                     "Aggiungi la sezione github: (SPEC v3.2 par. 3) o usa --no-push")
    elif mode == "none":
        d.note = "github.mode none: push saltato (brain solo locale)"
    elif not d.owner or not d.repo:
        d.problem = "github.owner / github.repo mancanti in brain.yaml: nessun push"
    elif (d.owner.lower(), d.repo.lower()) != (gh[0].lower(), gh[1].lower()):
        d.problem = (f"origin punta a {gh[0]}/{gh[1]} ma brain.yaml dichiara {d.owner}/{d.repo}: nessun push "
                     "(correggi origin o la sezione github:)")
    return d


def gh_login(run: Runner | None = None) -> str | None:
    run = run or Runner(Path.cwd())
    r = run.gh("api", "user", "-q", ".login")
    if r is None or r.returncode != 0:
        return None
    return r.stdout.strip() or None


def repo_permission(owner: str, repo: str, run: Runner | None = None) -> bool | None:
    """`gh api repos/<owner>/<repo> --jq .permissions.push`: True/False; None = gh assente, non loggato,
    repo non visibile (404) o risposta illeggibile. E' il permesso della CREDENZIALE gh: il push usa il
    credential helper di gh via HTTPS (origin https impostato dallo scaffolder); SSH o altri helper sono fuori
    garanzia (README)."""
    run = run or Runner(Path.cwd())
    r = run.gh("api", f"repos/{owner}/{repo}", "--jq", ".permissions.push")
    if r is None or r.returncode != 0:
        return None
    v = r.stdout.strip().lower()
    return True if v == "true" else False if v == "false" else None


def owner_type(owner: str, run: Runner) -> str | None:
    r = run.gh("api", f"users/{owner}", "--jq", ".type")
    if r is None or r.returncode != 0:
        return None
    return r.stdout.strip() or None


def pr_view(run: Runner, owner: str, repo: str, branch: str) -> dict | None:
    """{} = nessuna PR per il branch; dict con state/url/headRefOid/number; None = gh in errore (stop, G11)."""
    r = run.gh("pr", "view", branch, "--repo", f"{owner}/{repo}", "--json", "state,url,headRefOid,number")
    if r is None:
        return None
    if r.returncode != 0:
        if "no pull requests found" in (r.stderr or "").lower():
            return {}
        return None
    try:
        data = json.loads(r.stdout)
    except ValueError:
        return None
    return data if isinstance(data, dict) else None


def commit_pathspec(root: Path, targets: list[kc.Node]) -> tuple[list[str], list[str]]:
    """(path da aggiungere, pathspec di esclusione). Cartelle del profilo + zone grezze + llms.txt/README/
    CONVENTIONS per nodo; alla radice anche la governance GitHub (G27) quando esiste; stati condivisi
    dell'indice. `workspace/dream/` e `.memory-backup/` esclusi ESPLICITAMENTE (oltre al .gitignore)."""
    paths: list[str] = []
    excludes: list[str] = []
    for n in targets:
        for d in [*n.profile.folders, *n.profile.raw_dirs]:
            p = n.dir / d
            if p.exists():
                paths.append(n.rel_root(p))
        for f in ("llms.txt", "README.md", "CONVENTIONS.md"):
            if (n.dir / f).is_file():
                paths.append(n.rel_root(n.dir / f))
        if n.is_root:
            for f in GOVERNANCE_ROOT:
                if (n.dir / f).exists():
                    paths.append(f)
        prefix = "" if n.is_root else n.path + "/"
        excludes += [f":(exclude){prefix}{x}" for x in EXCLUDE_ALWAYS]
    idx = kc.index_dir(root)
    if idx.is_dir():
        # stati incrementali del RAG: viaggiano CON le note, nello stesso commit
        paths += [str(p.relative_to(root)).replace("\\", "/") for p in sorted(idx.glob("vault_state*.json"))]
        paths += [str(p.relative_to(root)).replace("\\", "/") for p in sorted(idx.glob("corpus_state*.json"))]
    return sorted(set(paths)), sorted(set(excludes))


def _require_clean_staging(run: Runner) -> None:
    if run.git("diff", "--cached", "--quiet").returncode != 0:
        print("STAGING NON VUOTO: brain_sync committa solo i path del vault e non vuole trascinarsi file "
              "altrui. Svuota lo staging (`git restore --staged .`) o committa a mano, poi rilancia.")
        raise SyncAbort(5)


def _stage(run: Runner, paths: list[str], excludes: list[str]) -> bool:
    """git add con pathspec; True se c'e' qualcosa da committare (in dry-run: modifiche pendenti nel pathspec)."""
    if not paths:
        return False
    if run.dry:
        st = run.git("status", "--porcelain", "--untracked-files=all", "--", *paths, *excludes)
        run.git("add", "--", *paths, *excludes, write=True)
        return bool(st.stdout.strip())
    ga = run.git("add", "--", *paths, *excludes)
    if ga.returncode != 0:
        print(f"WARN: git add fallito (rc={ga.returncode}): {ga.stderr.strip()[:200]}")
    return run.git("diff", "--cached", "--quiet").returncode != 0


def _refuse(problems, what: str) -> None:
    repo_check.report(problems, f"RIFIUTATO (exit {EXIT_REFUSED}): {len(problems)} problemi {what} (commit, path, tipo). "
                                "Nessun push. Togli i file (l'originale pesante sta fuori dal repo; i segreti in .env/.secrets):")


def _check_staged(run: Runner, root: Path) -> None:
    if run.dry:
        return
    if run.ops_nodes is not None:
        verify_ops_staged(run, root, run.ops_nodes)
    probs = repo_check.staged_problems(root, repo_check.memory_prefixes(root))
    if probs:
        run.git("reset", "-q")            # lo staging era vuoto prima del sync: torna com'era
        _refuse(probs, "nello staging (niente commit)")
        raise SyncAbort(EXIT_REFUSED)


def _check_outgoing(run: Runner, root: Path) -> tuple[int, str]:
    """(commit in uscita, esito della scansione dei contenuti per console e PR: revisione Astra v3.2.1, rilievo 3)."""
    stats: dict = {}
    try:
        commits, probs = repo_check.outgoing_problems(root, "HEAD", repo_check.memory_prefixes(root), stats=stats)
    except repo_check.RepoCheckError as e:
        print(f"controllo dei commit in uscita non eseguibile ({e}): push NON eseguito")
        raise SyncAbort(EXIT_REFUSED) from e
    if probs:
        _refuse(probs, f"nei {len(commits)} commit in uscita")
        raise SyncAbort(EXIT_REFUSED)
    note = repo_check.scan_note(stats)
    print(f"controllo applicativo: {len(commits)} commit in uscita senza file vietati o pesanti; {note}")
    return len(commits), note


def _commit(run: Runner, message: str) -> None:
    msg = message or f"brain-sync {kc.logical_today().isoformat()}"
    c = run.git("commit", "-m", msg, write=True)
    if c.returncode != 0:
        print(f"commit fallito: {c.stderr.strip()[:300]}")
        raise SyncAbort(6)
    print(f"commit: {msg}")


def redact_url(u: str) -> str:
    """URL stampabile: niente userinfo (`user:pass@`) e niente segreti riconoscibili (N9)."""
    u = re.sub(r"(://)[^/@\s]+@", r"\1***@", u)
    u = re.sub(r"^[^/@\s:]+@", "***@", u)
    try:
        from secrets_scan import mask_secrets  # noqa: PLC0415 (cantiere D, API stabile)
        u = mask_secrets(u)[0]
    except ImportError:  # pragma: no cover
        pass
    return u


def _is_local_path(base: str) -> bool:
    """Path del filesystem locale (repo bare di laboratorio/test)? URL di rete, scp-like e share UNC: no."""
    b = base.strip()
    if b.lower().startswith("file://"):
        return not b.lower().startswith("file:////")
    if b.startswith(("\\\\", "//")) or "://" in b:
        return False
    if re.match(r"^[A-Za-z]:[\\/]", b):
        return True
    if re.match(r"^[^/\\]*@[^/\\]+:", b) or re.match(r"^[A-Za-z0-9.-]{2,}:", b):
        return False                                   # git@host:repo, host:path
    return True                                        # path assoluto POSIX o relativo


def check_rewrites(run: Runner, owner: str, repo: str) -> None:
    """N5/N9: una regola `url.<base>.insteadOf`/`pushInsteadOf` che riscrive l'URL canonico
    https://github.com/<owner>/<repo>.git e' ammessa SOLO verso un path locale (repo bare di prova, con AVVISO);
    verso un altro host di rete -> nessun push (exit 9). L'URL non si stampa mai in chiaro."""
    url = f"https://github.com/{owner}/{repo}.git".lower()
    r = run.git("config", "--get-regexp", r"^url\..*\.(insteadof|pushinsteadof)$")
    for ln in r.stdout.splitlines():
        key, _, val = ln.partition(" ")
        val = val.strip()
        if not val or not url.startswith(val.lower()):
            continue
        base = key[4:].rsplit(".", 1)[0]
        shown = redact_url(base)
        if _is_local_path(base):
            print(f"AVVISO: una regola git url.<base>.insteadOf/pushInsteadOf riscrive {val} verso il path locale {shown}: "
                  "ammesso solo per prove con un repo bare locale")
            continue
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): una regola git url.<base>.insteadOf/pushInsteadOf riscrive "
              f"{val} verso un altro host ({shown}): nessun push. Togli la regola (git config --global --unset ...)")
        raise SyncAbort(EXIT_DEST)


def push_canonical(run: Runner, owner: str, repo: str, branch: str) -> subprocess.CompletedProcess:
    """Push SEMPRE verso l'URL canonico https://github.com/<owner>/<repo>.git (mai `origin` ne' il suo pushurl), con il
    credential helper di gh: l'identita' del trasporto e' la credenziale gh di cui si e' verificato il permesso (#13).
    Poi aggiorna il ref di tracciamento origin/<branch> e l'upstream."""
    check_rewrites(run, owner, repo)
    url = f"https://github.com/{owner}/{repo}.git"
    p = run.git("-c", "credential.helper=", "-c", "credential.helper=!gh auth git-credential",
                "push", url, f"HEAD:refs/heads/{branch}", write=True)
    if p.returncode == 0 and not run.dry:
        run.git("update-ref", f"refs/remotes/origin/{branch}", "HEAD")
        run.git("branch", f"--set-upstream-to=origin/{branch}")
    return p


def _perm_message(perm: bool | None, login: str | None, owner: str, repo: str) -> None:
    if perm is False:
        print(f"l'account `{login or '?'}` non ha scrittura su `{owner}/{repo}`: push NON eseguito. "
              "A mano: gh auth switch --user <account con accesso>; poi rilancia brain_sync")
    else:
        print(f"`gh` assente, non loggato o `{owner}/{repo}` non visibile (404) per l'account attivo: push NON "
              "eseguito. Controlla `gh auth status` e il permesso sul repo, poi rilancia brain_sync")


# ---------------------------------------------------------------- personal (e brain v3.1 senza GitHub)
def sync_personal(run: Runner, root: Path, dest: Dest, paths: list[str], excludes: list[str], message: str,
                  push: bool) -> None:
    _require_clean_staging(run)
    if push and dest.problem:
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): {dest.problem}")
        raise SyncAbort(EXIT_DEST)
    if _stage(run, paths, excludes):
        _check_staged(run, root)
        _commit(run, message)
    else:
        print("niente da committare")
    if not push:
        print("push saltato (--no-push)")
        return
    if dest.note:
        print(dest.note)
        return
    up = run.git("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{u}")
    if up.returncode == 0:
        run.git("fetch", "--quiet", write=True)
        behind = run.count("HEAD..@{u}")
        if behind > 0:
            p = run.git("pull", "--rebase", "--autostash", write=True)
            if p.returncode != 0:
                run.git("rebase", "--abort", write=True)
                print("WARNING: pull --rebase fallito (conflitto?); push saltato, riallinea a mano")
                return
            print(f"pull --rebase: {behind} commit integrati da upstream")
        if run.count("@{u}..HEAD") == 0:
            print("niente da pushare: il ramo e' allineato a upstream")
            return
    otype = owner_type(dest.owner, run)
    login = gh_login(run)
    if otype is None:
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): tipo dell'owner `{dest.owner}` non verificabile "
              f"(`gh api users/{dest.owner}` in errore o gh assente): nessun push")
        raise SyncAbort(EXIT_DEST)
    if otype == "Organization":
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): {dest.owner} e' un'organizzazione ma github.mode e' "
              "personal: in un'organizzazione si usa github.mode org (branch + PR, mai su main)")
        raise SyncAbort(EXIT_DEST)
    perm = repo_permission(dest.owner, dest.repo, run)
    if perm is not True:
        _perm_message(perm, login, dest.owner, dest.repo)
        return
    _check_outgoing(run, root)
    cur = run.current_branch()
    if cur is None:
        print("HEAD staccato: push NON eseguito (torna su un branch)")
        return
    pu = push_canonical(run, dest.owner, dest.repo, cur)
    if pu.returncode != 0:
        print(f"WARNING: push fallito (offline?): {pu.stderr.strip()[:200]} -- il commit resta locale")
    else:
        print(f"push su origin ok (account {login or '?'}, permesso di scrittura su {dest.owner}/{dest.repo})")


# ---------------------------------------------------------------- org: branch sync/* + PR, mai main
def _sanitize_login(login: str | None) -> str:
    s = re.sub(r"[^a-z0-9-]+", "-", (login or "").lower()).strip("-")
    return s or "locale"


def _new_branch_name(run: Runner, login: str | None) -> str:
    base = f"sync/{kc.logical_today().isoformat()}-{_sanitize_login(login)}"
    name, i = base, 1
    while run.has_ref(f"refs/heads/{name}") or run.has_ref(f"refs/remotes/origin/{name}"):
        i += 1
        name = f"{base}-{i}"
    return name


def _after_merge(run: Runner, branch: str, pr: dict, login: str | None) -> str:
    """PR MERGED (G12, N7): si cancella il branch locale SOLO se il suo HEAD e' la head integrata (`headRefOid`).
    Commit locali in piu': prima di tutto un ref di sicurezza `refs/brain-sync/salvataggio/<ts>` sul vecchio HEAD;
    se fra quei commit c'e' un merge (storia non lineare) stop senza rebase (exit 7); altrimenti rebase --onto
    origin/main su un nuovo branch sync (conflitto = rebase --abort, exit 7). Ritorna il branch su cui proseguire."""
    head = run.git("rev-parse", "HEAD").stdout.strip()
    oid = str(pr.get("headRefOid") or "")
    if not oid:
        print(f"PR di {branch} MERGED ma headRefOid non disponibile: non cancello nulla. Verifica a mano (exit {EXIT_STOP})")
        raise SyncAbort(EXIT_STOP)
    if head == oid:
        dirty = bool(run.git("status", "--porcelain", "--untracked-files=all").stdout.strip())
        if dirty and run.git("stash", "push", "--include-untracked", "-m", "brain_sync: modifiche in corso", write=True).returncode != 0:
            print(f"PR MERGED: impossibile mettere da parte le modifiche locali (git stash): mi fermo (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        if run.git("switch", ORG_BASE, write=True).returncode != 0:
            print(f"PR MERGED: `git switch {ORG_BASE}` fallito: mi fermo; modifiche locali in `git stash list` (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        if run.has_ref(f"refs/remotes/origin/{ORG_BASE}"):
            m = run.git("merge", "--ff-only", f"origin/{ORG_BASE}", write=True)
            if m.returncode != 0:
                print(f"PR MERGED ma {ORG_BASE} locale non avanza in fast-forward: riallinea a mano (exit {EXIT_STOP})")
                raise SyncAbort(EXIT_STOP)
        run.git("branch", "-D", branch, write=True)
        if dirty and run.git("stash", "pop", write=True).returncode != 0:
            print(f"PR MERGED, {ORG_BASE} aggiornato, ma le modifiche locali non si riapplicano senza conflitti: restano in "
                  f"`git stash list` e nei marcatori di conflitto; risolvi a mano (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        print(f"PR di {branch} MERGED: {ORG_BASE} aggiornato, branch locale cancellato (HEAD == head della PR)")
        return ORG_BASE
    if run.is_ancestor(oid, head):
        extra = run.count(f"{oid}..{head}")
        safety = f"refs/brain-sync/salvataggio/{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}"
        if run.git("update-ref", safety, head, write=True).returncode != 0:
            print(f"PR MERGED: impossibile creare il ref di sicurezza {safety}: mi fermo (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        merges = int(run.git("rev-list", "--merges", "--count", f"{oid}..{head}").stdout.strip() or 0)
        if merges:
            print(f"PR di {branch} MERGED; {extra} commit locali in piu' con {merges} merge (storia non lineare): nessun "
                  f"rebase automatico, branch {branch} intatto, copia di sicurezza in {safety}. A mano: crea un branch da "
                  f"origin/{ORG_BASE} e porta le modifiche (`git switch -c sync/... origin/{ORG_BASE}` + "
                  f"`git cherry-pick -m 1 <merge>` o `git checkout {safety} -- <file>`), poi rilancia (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        new = _new_branch_name(run, login)
        r = run.git("rebase", "--autostash", "--onto", f"origin/{ORG_BASE}", oid, branch, write=True)
        if r.returncode != 0:
            run.git("rebase", "--abort", write=True)
            print(f"PR MERGED; {extra} commit locali in piu' NON spostabili senza conflitti: branch {branch} lasciato "
                  f"com'era, copia di sicurezza in {safety}; risolvi a mano (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        run.git("branch", "-m", branch, new, write=True)
        if run.has_ref(ORG_BASE) and run.is_ancestor(ORG_BASE, f"origin/{ORG_BASE}"):
            run.git("branch", "-f", ORG_BASE, f"origin/{ORG_BASE}", write=True)
        print(f"PR di {branch} MERGED; {extra} commit locali in piu' spostati sul nuovo branch {new} "
              f"(storia di prima in {safety})")
        return new
    print(f"PR di {branch} MERGED ma il branch locale non contiene la head della PR: non cancello nulla, "
          f"verifica a mano (exit {EXIT_STOP})")
    raise SyncAbort(EXIT_STOP)


def _pr_body(run: Runner, branch: str, login: str | None, summary: dict, n_commits: int, scan: str = "") -> str:
    rng = f"origin/{ORG_BASE}...{branch}" if run.has_ref(f"refs/remotes/origin/{ORG_BASE}") else branch
    files = [f for f in run.git("diff", "--name-only", rng).stdout.splitlines() if f.strip()]
    lines = [f"Sincronizzazione di `brain_sync` (giorno logico {kc.logical_today().isoformat()}, account `{login or '?'}`).",
             "", f"## File ({len(files)})"]
    lines += [f"- `{f}`" for f in files[:40]] + ([f"- ... altri {len(files) - 40}"] if len(files) > 40 else [])
    if summary.get("ops"):     # par. 13.3: commit di ops/ separato dal rito del vault
        lines += ["", "## Controlli", "- commit di ops/ (`brain_sync --ops`): lint, llms.txt e ingest non eseguiti "
                  "(il vault non e' toccato)", "- path: " + ", ".join(f"`{x}`" for x in summary["ops"][:10])]
    else:
        lines += ["", "## Controlli", "- lint: 0 errori", "- llms.txt: rigenerato", f"- ingest: {summary.get('ingest', '?')}"]
    lines += [f"- controllo applicativo: {n_commits} commit in uscita senza file vietati o pesanti; "
              f"{scan or repo_check.scan_note(None)}",
              "", "Il merge (squash) lo fa un'altra persona dopo la review."]
    return "\n".join(lines) + "\n"


def sync_org(run: Runner, root: Path, dest: Dest, paths: list[str], excludes: list[str], message: str,
             push: bool, summary: dict) -> None:
    """Macchina a stati della modalita' org (README del motore, sezione "brain_sync in modalita' org")."""
    _require_clean_staging(run)
    if push and dest.problem:
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): {dest.problem}")
        raise SyncAbort(EXIT_DEST)
    branch = run.current_branch()
    if branch is None or (branch != ORG_BASE and not branch.startswith("sync/")):
        print(f"branch corrente `{branch or 'HEAD staccato'}`: in modalita' org brain_sync lavora solo da `{ORG_BASE}` o da un "
              f"branch `sync/*` (i branch di lavoro altrui non si toccano). Exit {EXIT_STOP}")
        raise SyncAbort(EXIT_STOP)
    owner, repo = dest.owner, dest.repo
    login = gh_login(run) if push else None
    online = False
    if push:
        f = run.git("fetch", "origin", "--quiet", write=True)
        online = f.returncode == 0
        if not online:
            print(f"git fetch origin fallito (offline?): si lavora in locale, push rimandato ({f.stderr.strip()[:120]})")
    pr: dict = {}
    if branch.startswith("sync/") and online:
        got = pr_view(run, owner, repo, branch)
        if got is None:
            print(f"`gh pr view {branch} --repo {owner}/{repo}` in errore: mi fermo senza toccare nulla (exit {EXIT_STOP})")
            raise SyncAbort(EXIT_STOP)
        pr = got
        state = str(pr.get("state") or "").upper()
        if state == "CLOSED":
            print(f"la PR di {branch} e' CHIUSA senza merge ({pr.get('url', '')}): nessun commit. Decidi tu: riapri la PR "
                  f"o torna su {ORG_BASE} (`git switch {ORG_BASE}`). Exit {EXIT_STOP}")
            raise SyncAbort(EXIT_STOP)
        if state == "MERGED":
            branch = _after_merge(run, branch, pr, login)
            pr = {}
    if branch == ORG_BASE and online:
        if not run.has_ref(f"refs/remotes/origin/{ORG_BASE}"):
            print(f"origin/{ORG_BASE} non esiste ancora: il primo push di {ORG_BASE} lo fa `github_org.py apply` "
                  f"(prima del ruleset). Exit {EXIT_STOP}")
            raise SyncAbort(EXIT_STOP)
        ahead = run.count(f"origin/{ORG_BASE}..HEAD")
        if ahead > 0:
            print(f"{ORG_BASE} locale ha {ahead} commit che non sono su origin/{ORG_BASE}: in modalita' org su {ORG_BASE} "
                  f"non si scrive. Spostali su un branch (`git switch -c sync/...`) e rilancia. Exit {EXIT_STOP}")
            raise SyncAbort(EXIT_STOP)
        if run.count(f"HEAD..origin/{ORG_BASE}") > 0:
            m = run.git("merge", "--ff-only", "--autostash", f"origin/{ORG_BASE}", write=True)
            if m.returncode != 0:
                print(f"{ORG_BASE} non avanza in fast-forward: riallinea a mano (exit {EXIT_STOP})")
                raise SyncAbort(EXIT_STOP)
            print(f"{ORG_BASE} aggiornato da origin (fast-forward)")
    staged = _stage(run, paths, excludes)
    if staged:
        _check_staged(run, root)
        if run.coerenza and not run.dry and run.ops_nodes is None:
            # v3.3 (par. 14.11): i file incongruenti escono dallo staging e vanno su travaso/attesa/<persona> con issue;
            # un controllo FALLITO (exit != 0/12) = nessun commit (giro 2, #11)
            rc = run_travaso(root, "check", ["--staged", *_persona_args(root)], quiet=True)
            if rc not in (0, 12):
                run.git("reset", "-q")
                print(f"controllo di coerenza dello staging fallito (exit {rc} di travaso.py check --staged): staging svuotato, "
                      f"nessun commit (exit {EXIT_TRAVASO})")
                raise SyncAbort(EXIT_TRAVASO)
            run.travaso_rc = _worst_rc(run.travaso_rc, rc)
            if run.git("diff", "--cached", "--quiet").returncode == 0:
                staged = False
                print("niente da committare: tutti i file in staging sono fermi (in attesa di decisione)")
    if staged:
        if branch == ORG_BASE:
            branch = _new_branch_name(run, login)
            if run.git("switch", "-c", branch, write=True).returncode != 0:
                print(f"creazione del branch {branch} fallita (exit {EXIT_STOP})")
                raise SyncAbort(EXIT_STOP)
            print(f"branch nuovo: {branch} (su {ORG_BASE} non si committa)")
        _commit(run, message)
    elif branch == ORG_BASE:
        print(f"niente da committare: {ORG_BASE} allineato, nessun branch sync creato")
        return
    else:
        print(f"niente da committare sul branch {branch}")
    if not push:
        print(f"push saltato (--no-push): commit locale sul branch {branch}")
        return
    if not online:
        print(f"offline: commit locale sul branch {branch}; push e PR al prossimo brain_sync")
        return
    remote_has = run.has_ref(f"refs/remotes/origin/{branch}")
    to_push = run.count(f"origin/{branch}..HEAD") if remote_has else run.count(f"origin/{ORG_BASE}..HEAD")
    if run.dry and staged:
        to_push = max(to_push, 1)          # in dry-run il commit e' solo stampato
    state = str(pr.get("state") or "").upper()
    if to_push == 0 and state == "OPEN":
        print(f"niente da pushare: la PR e' gia' aggiornata ({pr.get('url', '')})")
        return
    if to_push == 0 and not remote_has:
        print(f"niente da pushare: il branch {branch} non ha commit rispetto a origin/{ORG_BASE}")
        return
    if owner_type(owner, run) is None:
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): tipo dell'owner `{owner}` non verificabile "
              f"(`gh api users/{owner}` in errore o gh assente): commit locale sul branch {branch}, nessun push")
        raise SyncAbort(EXIT_DEST)
    perm = repo_permission(owner, repo, run)
    if perm is not True:
        _perm_message(perm, login, owner, repo)
        print(f"commit locale sul branch {branch}: nessun push")
        return
    n_commits, scan = 0, ""
    if to_push > 0:
        n_commits, scan = _check_outgoing(run, root)
        pu = push_canonical(run, owner, repo, branch)
        if pu.returncode != 0:
            print(f"WARNING: push di {branch} fallito: {pu.stderr.strip()[:200]} -- il commit resta locale")
            return
        print(f"push del branch {branch} su origin ok (account {login or '?'}, permesso di scrittura su {owner}/{repo})")
    if state == "OPEN":
        print(f"PR aggiornata: {pr.get('url', '')}")
        run.pr_number = int(pr.get("number") or 0) or None
        _after_pr(run, root)
        return
    title = f"brain-sync {kc.logical_today().isoformat()} ({login or '?'})"
    body = _pr_body(run, branch, login, summary, n_commits, scan)
    r = run.gh("pr", "create", "--repo", f"{owner}/{repo}", "--base", ORG_BASE, "--head", branch,
               "--title", title, "--body-file", "-", write=True, input_text=body)
    if r is None or r.returncode != 0:
        err = (r.stderr.strip()[:200] if r is not None else "gh assente o timeout")
        print(f"AVVISO: push riuscito ma PR NON creata ({err}): il prossimo brain_sync la crea")
        return
    url = (r.stdout.strip().splitlines() or [""])[-1]
    print(f"PR aperta: {url}" if url else "PR aperta")
    m = re.search(r"/pull/(\d+)", url)
    run.pr_number = int(m.group(1)) if m else None
    _after_pr(run, root)


def _after_pr(run: Runner, root: Path) -> None:
    """v3.3 (par. 6.6, 14.11): nei brain `merge: coerenza` la PR del sync riceve lo status `coerenza` da `travaso.py check
    --pr`; negli altri resta la review umana."""
    if not run.coerenza:
        print("PR aperta: il merge (squash) lo fa un'altra persona dopo la review.")
        return
    if run.dry or not run.pr_number:
        print("PR aperta: merge automatico quando `brain-check` e `coerenza` sono verdi (check --pr al prossimo giro)")
        return
    rc = run_travaso(root, "check", ["--pr", str(run.pr_number), *_persona_args(root)], quiet=True)
    run.travaso_rc = _worst_rc(run.travaso_rc, rc)
    print("PR aperta: merge automatico quando `brain-check` e `coerenza` sono verdi.")


def _persona_args(root: Path) -> list[str]:
    p = kc.travaso_config(root).get("persona", "")
    return ["--persona", p] if p else []


def _worst_rc(cur: int, new: int) -> int:
    if new in (0, 12):
        return cur
    return new if cur in (0, 12) else cur


def _ops_bases(root: Path, nodes: list[kc.Node]) -> list[tuple[str, str]]:
    """(path assoluto NON risolto e normalizzato, path relativo alla radice con `/`) di ogni ops_dirs dei nodi."""
    rootp = os.path.normcase(os.path.abspath(str(root)))
    out = []
    for n in nodes:
        for d in n.profile.ops_dirs:
            b = os.path.normcase(os.path.abspath(str(n.dir / d)))
            if b.startswith(rootp + os.sep):
                out.append((b, os.path.relpath(b, rootp).replace("\\", "/")))
    return out


def ops_paths(root: Path, nodes: list[kc.Node], raw: list[str], cwd: Path | None = None) -> list[str]:
    """`--ops` (par. 13.3): path relativi alla cwd (o assoluti) -> relativi alla radice del repo, separatore `/`.
    Ognuno deve stare dentro (o essere) una `ops_dirs` di un nodo del brain, confrontando i path NON risolti
    (normalizzati, case-insensitive su Windows); nessun componente fra la radice e il path (ops_dir compresa) puo'
    essere un link, una junction o un reparse point (revisione Astra v3.2.1, rilievo 1). Altrimenti ConfigError
    (exit 3). I path possono non esistere (una cancellazione si committa)."""
    base = Path(cwd or Path.cwd())
    rootp = Path(os.path.abspath(str(root)))
    allowed = _ops_bases(root, nodes)
    shown = ", ".join(f"{rel}/" for _b, rel in allowed) or "nessuna (ops_dirs vuote)"
    out: list[str] = []
    for r in raw:
        p = Path(r)
        p = Path(os.path.abspath(str(p if p.is_absolute() else base / p)))     # `..` risolti solo lessicalmente
        s = os.path.normcase(str(p))
        if not any(s == b or s.startswith(b + os.sep) for b, _rel in allowed):
            raise kc.ConfigError(f"--ops {r}: fuori dalle cartelle operative del brain (ops_dirs dei nodi: {shown}). "
                                 "Il vault si committa col sync normale, il resto non va nel brain")
        link = kc.link_in_path(rootp, p)
        if link is not None:
            where = os.path.relpath(str(link), str(rootp)).replace("\\", "/")
            raise kc.ConfigError(f"--ops {r}: `{where}` e' un link, una junction o un reparse point: con --ops si "
                                 "committano solo file dentro cartelle vere di ops/ (un link potrebbe portare nel vault)")
        inner = _link_inside(p)
        if inner is not None:
            where = os.path.relpath(str(inner), str(rootp)).replace("\\", "/")
            raise kc.ConfigError(f"--ops {r}: dentro la cartella c'e' `{where}`, un link, una junction o un reparse "
                                 "point: git per Windows lo attraversa e committerebbe file di un'altra cartella (anche "
                                 "del vault). Toglilo o passa a --ops solo le sottocartelle vere")
        rel = os.path.relpath(str(p), str(rootp)).replace("\\", "/")
        if rel not in out:
            out.append(rel)
    return out


def _link_inside(p: Path) -> Path | None:
    """Primo link/junction/reparse point DENTRO la cartella `p` (visita senza seguire i link), oppure None. Serve
    perche' `git add -- <cartella>` su Windows attraversa le junction (verificato con git 2.45.2, fatto 38)."""
    if not p.is_dir() or kc.is_link(p):
        return None
    stack = [p]
    while stack:
        cur = stack.pop()
        try:
            entries = list(os.scandir(cur))
        except OSError:
            continue
        for ent in entries:
            ep = Path(ent.path)
            if kc.is_link(ep):
                return ep
            try:
                if ent.is_dir(follow_symlinks=False) and ent.name != ".git":
                    stack.append(ep)
            except OSError:
                continue
    return None


def verify_ops_staged(run: Runner, root: Path, nodes: list[kc.Node]) -> None:
    """Dopo `git add` di --ops: OGNI path dello staging reale (`git diff --cached --name-only -z`) deve stare sotto
    una ops_dirs dichiarata; altrimenti `git restore --staged` di tutto ed exit 3 (revisione Astra v3.2.1, rilievo 1)."""
    allowed = [rel.lower() for _b, rel in _ops_bases(root, nodes)]
    r = run.git("diff", "--cached", "--name-only", "-z")
    staged = [x for x in (r.stdout or "").split("\0") if x]
    bad = [x for x in staged if not any(x.lower() == a or x.lower().startswith(a + "/") for a in allowed)]
    if r.returncode != 0 or bad:
        if run.git("restore", "--staged", "--", ".").returncode != 0:
            run.git("reset", "-q")
        what = ", ".join(bad[:5]) if bad else "staging illeggibile"
        print(f"ERRORE configurazione (exit 3): dopo `git add` lo staging contiene path fuori dalle cartelle operative "
              f"({what}): staging svuotato, nessun commit")
        raise SyncAbort(3)


def ops_message(rels: list[str], message: str) -> str:
    """`ops: <msg>`; senza -m `ops <giorno logico> <path principale>` (il path se e' uno solo, altrimenti la cartella
    comune, altrimenti il primo)."""
    if message:
        return message if message.startswith("ops:") else f"ops: {message}"
    try:
        main = os.path.commonpath(rels).replace("\\", "/") if len(rels) > 1 else rels[0]
    except ValueError:
        main = ""
    return f"ops {kc.logical_today().isoformat()} {main or rels[0]}"


def commit_and_push(root: Path, targets: list[kc.Node], message: str, push: bool, dry_run_git: bool = False,
                    summary: dict | None = None, ops: list[str] | None = None,
                    ops_nodes: list[kc.Node] | None = None) -> None:
    """Commit + push del sync. Con `ops` (par. 13.3) il pathspec sono SOLO quei path e il messaggio e' `ops ...`: la
    validazione della destinazione, i controlli (staging, commit in uscita) e il push sono gli stessi."""
    print("\n== git ==")
    run = Runner(root, dry_run_git)
    if run.git("rev-parse", "--git-dir").returncode != 0:
        print("nessun repository git: commit saltato")
        return
    if ops:
        # niente pathspec di esclusione: i path sono gia' validati dentro le ops_dirs e i path vietati (dream, memoria,
        # .env, .secrets) li rifiuta comunque repo_check sullo staging. Misurato con git 2.45.2 su Windows: con un
        # `:(exclude)` qualunque, `git add -- ops/Projects/<p>/CLAUDE.md` non aggiunge nulla (exit 0) se il path ha un
        # segmento omonimo di una cartella tracciata alla radice (`projects/` del vault) dentro cartelle non tracciate
        paths, excludes = list(ops), []
        message = ops_message(ops, message)
        run.ops_nodes = list(ops_nodes if ops_nodes is not None else kc.iter_nodes(root))
        print(f"commit di ops/ separato dal vault: {', '.join(ops)}")
    else:
        paths, excludes = commit_pathspec(root, targets)
    try:
        dest = destination(root)
    except kc.ConfigError as e:
        print(f"DESTINAZIONE NON VALIDA (exit {EXIT_DEST}): {e}")
        raise SyncAbort(EXIT_DEST) from e
    if dry_run_git:
        print(f"[dry-run-git] modalita' github: {dest.mode or '(non dichiarata)'}; le operazioni git/gh che cambiano "
              "qualcosa vengono solo stampate")
    if push and dest.mode in ("personal", "org") and not dest.problem:
        check_rewrites(run, dest.owner, dest.repo)    # prima di ogni commit e di ogni accesso di rete
    run.coerenza = dest.mode == "org" and dest.merge == "coerenza" and push and (root / "scripts" / "travaso.py").is_file()
    if dest.mode == "org":
        sync_org(run, root, dest, paths, excludes, message, push, summary or {})
    else:
        sync_personal(run, root, dest, paths, excludes, message, push)
    return run.travaso_rc


# ----------------------------------------------------------------------------
# v3.3: travaso (SPEC v3.3 par. 8.2, 14.12, 14.24)
# ----------------------------------------------------------------------------
def travaso_target(root: Path) -> tuple[str, Path | None, str, str]:
    """(ruolo, script, persona, problema). Ruolo: 'mittente' (brain con `travaso:` repo+clone -> `<clone>/scripts/travaso.py`),
    'ricevente' (brain con `github.travaso: true` -> il PROPRIO scripts/travaso.py), '' (nessun travaso). `problema` non
    vuoto = "TRAVASO NON CONFIGURATO: ..." (exit 10). Il path del clone viene SOLO da brain.yaml, mai dalla riga di comando."""
    cfg = kc.travaso_config(root)
    try:
        gh = kc.github_config(root)
    except kc.ConfigError:
        gh = {}
    if cfg.get("repo") or cfg.get("clone"):
        clone = Path(cfg.get("clone") or "")
        persona = cfg.get("persona", "")
        why = ""
        if not cfg.get("clone"):
            why = "travaso.clone manca in brain.yaml"
        elif not clone.is_dir():
            why = f"travaso.clone non esiste ({clone})"
        elif git(clone, "rev-parse", "--show-toplevel").returncode != 0:
            why = f"travaso.clone non e' un repository git ({clone})"
        elif not (clone / "scripts" / "travaso.py").is_file():
            why = f"scripts/travaso.py assente nel clone {clone} (il brain aziendale non e' a v3.3?)"
        elif not persona:
            why = "travaso.persona manca in brain.yaml"
        else:
            parsed = parse_github(remote_owner(clone)[1])
            if parsed is None or (parsed[0].lower(), parsed[1].lower()) != (cfg.get("owner", "").lower(), cfg.get("repo", "").lower()):
                why = f"origin del clone {clone} non e' {cfg.get('owner')}/{cfg.get('repo')}"
            # la persona si valida su travaso.yaml di ORIGIN/MAIN dentro travaso.py, mai sulla copia locale (giro 2, #21)
        if why:
            return "mittente", None, persona, (f"TRAVASO NON CONFIGURATO: {why}. Clona il brain aziendale "
                                               f"({cfg.get('owner')}/{cfg.get('repo')}) e inizializzalo con scaffold/inizializza_clone.py "
                                               "--travaso-persona/--travaso-clone, poi rilancia")
        return "mittente", clone / "scripts" / "travaso.py", persona, ""
    if gh.get("travaso"):
        script = root / "scripts" / "travaso.py"
        if not script.is_file():
            return "ricevente", None, cfg.get("persona", ""), "TRAVASO NON CONFIGURATO: scripts/travaso.py assente nel brain (motore < 3.3)"
        return "ricevente", script, cfg.get("persona", ""), ""
    return "", None, "", ""


def _m(text: str) -> str:
    """Mai segreti nei messaggi del wrapper (anche un path con un token dentro): maschera prima di stampare (#13)."""
    try:
        from secrets_scan import mask_secrets  # noqa: PLC0415
        return mask_secrets(str(text))[0]
    except ImportError:  # pragma: no cover
        return str(text)


def run_travaso(root: Path, sub: str, args: list[str], quiet: bool = True) -> int:
    """Esegue `travaso.py <sub> ...` con il python corrente (mittente: dal clone; ricevente: da se'). Output in chiaro."""
    role, script, persona, problem = travaso_target(root)
    if script is None:
        print(_m(problem or "TRAVASO NON CONFIGURATO: questo brain non dichiara `travaso:` in brain.yaml ne' github.travaso"))
        return EXIT_TRAVASO
    cmd = [sys.executable, str(script), sub, *args]
    if quiet and "--quiet" not in cmd:
        cmd.append("--quiet")
    env = {k: v for k, v in os.environ.items() if k not in ("BRAIN_ROOT", "BRAIN_ID", "BRAIN_NODE")}
    env["PYTHONUTF8"] = "1"
    sys.stdout.flush()
    try:
        r = subprocess.run(cmd, cwd=str(script.parent.parent), env=env, stdin=subprocess.DEVNULL)
    except OSError as e:
        print(_m(f"travaso non eseguibile: {e}"))
        return EXIT_TRAVASO
    return r.returncode


def travaso_exit(rc: int) -> int:
    """Exit di brain_sync dopo il travaso: 0 (ok o 12 rinviato), 13 (da verificare), 10 per 3/7/8/9/11 (par. 14.24)."""
    if rc in (0, 12):
        return 0
    if rc == 13:
        return EXIT_VERIFY
    return EXIT_TRAVASO


def travaso_args(a, root: Path, role: str, persona: str, sub: str) -> list[str]:
    args: list[str] = []
    if sub in ("send", "stato", "verifica") and role == "mittente":
        args += ["--from", str(root)]
        if sub != "verifica":
            args += ["--persona", persona]
    if sub == "send":
        if a.verdetto:
            args += ["--verdetto", a.verdetto]
        for p, m in zip(a.ferma or [], a.motivo or []):
            args += ["--ferma", p, "--motivo", m]
        if a.conferma_cancellazioni:
            args.append("--conferma-cancellazioni")
    if sub == "check":
        if a.pr:
            args += ["--pr", str(a.pr)]
        elif a.staged:
            args.append("--staged")
        if a.approvo:
            args.append("--approvo")
        if persona:
            args += ["--persona", persona]
    if sub == "decisioni" and a.scrivi:
        args.append("--scrivi")
    if sub == "stato" and role == "ricevente":
        args.append("--da-compilare")
    if a.no_ingest and sub in ("send", "decisioni", "check") and getattr(a, "travaso", None):
        args.append("--no-ingest")                        # solo nel dispatch esplicito: il post-passo decide da solo (N1)
    if a.dry_run_git and sub in ("send", "decisioni", "check"):
        args.append("--dry-run-git")
    return args


def travaso_post_step(a, root: Path) -> int:
    """Dopo un sync o un --ops riusciti: il mittente manda (`send`), il ricevente applica le decisioni (`decisioni`)."""
    role, script, persona, problem = travaso_target(root)
    if not role:
        return 0
    cfg = kc.travaso_config(root)
    if role == "mittente" and not cfg.get("auto", True):
        print("travaso: auto false in brain.yaml (a mano: brain_sync.py --travaso send)")
        return 0
    if a.no_push:
        print("travaso rinviato: --no-push")
        return 0
    if script is None:
        print(_m(problem))
        return EXIT_TRAVASO
    print("\n== travaso ==")
    sub = "send" if role == "mittente" else "decisioni"
    rc = run_travaso(root, sub, travaso_args(a, root, role, persona, sub), quiet=True)
    out = travaso_exit(rc)
    if out == EXIT_TRAVASO:
        print(f"TRAVASO FALLITO (exit {rc} di travaso.py): il sync resta buono; vedi le righe sopra (brain_sync exit {EXIT_TRAVASO})")
    return out


# ----------------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------------
def main(argv: list[str] | None = None) -> int:
    kc.utf8_stdout()
    ap = argparse.ArgumentParser(description="Catena lint -> llms.txt -> ingest -> commit (+pull/push controllati).")
    kc.add_common_args(ap)
    ap.add_argument("--all-nodes", action="store_true", help="tutti i nodi dell'albero (master); default: nodo corrente")
    ap.add_argument("--no-ingest", action="store_true",
                    help="salta l'ingest Qdrant (offline, o primo sync di un brain senza server configurato)")
    ap.add_argument("--no-commit", action="store_true",
                    help="niente commit ne' push: solo lint + llms.txt (+ ingest); utile al primo sync di un brain appena nato")
    ap.add_argument("--no-push", action="store_true", help="commit si', push no (niente pull --rebase ne' controllo dell'account gh)")
    ap.add_argument("--dry-run-git", action="store_true",
                    help="stampa le operazioni git/gh che cambiano qualcosa (add, commit, branch, push, PR) senza eseguirle")
    ap.add_argument("-m", "--message", default="", help="messaggio di commit (default: 'brain-sync <giorno logico>'; con --ops "
                    "diventa 'ops: <msg>', default 'ops <giorno> <path principale>')")
    ap.add_argument("--ops", nargs="+", metavar="PATH",
                    help="committa A PARTE solo questi path di ops/ (dentro una ops_dirs di un nodo): niente bump, lint, "
                         "llms.txt, ingest; poi lo stesso push del sync (personal: main per permesso; org: branch + PR)")
    tg = ap.add_argument_group("travaso (v3.3)")
    tg.add_argument("--no-travaso", action="store_true", help="niente travaso dopo il sync")
    tg.add_argument("--travaso", choices=TRAVASO_SUBS, default=None,
                    help="esegue SOLO questo sottocomando del travaso (niente lint/commit) e ritorna il suo esito")
    tg.add_argument("--travaso-only", action="store_true", help="= --travaso send")
    tg.add_argument("--verdetto", default=None, help="review_id del pacchetto verificato (con --travaso send)")
    tg.add_argument("--pr", type=int, default=None, help="numero della PR (con --travaso check)")
    tg.add_argument("--staged", action="store_true", help="controlla lo staging del brain aziendale (con --travaso check)")
    tg.add_argument("--approvo", action="store_true", help="approva la zona protetta (con --travaso check --pr)")
    tg.add_argument("--scrivi", action="store_true", help="rigenera decisioni/TRAVASO.md (con --travaso decisioni)")
    tg.add_argument("--ferma", action="append", default=[], metavar="PATH", help="ferma un pezzo in piu' (con --travaso send)")
    tg.add_argument("--motivo", action="append", default=[], help="motivo del --ferma corrispondente")
    tg.add_argument("--conferma-cancellazioni", action="store_true")
    a = ap.parse_args(argv)
    if a.ops and a.no_commit:
        print("ERRORE configurazione: --ops e --no-commit insieme non hanno senso (--ops e' un commit)")
        return 3
    if a.travaso_only:
        a.travaso = "send"
    if a.travaso:
        try:
            root = kc.resolve_root(a.root)
        except kc.ConfigError as e:
            print(f"ERRORE configurazione: {e}")
            return 3
        role, script, persona, problem = travaso_target(root)
        if script is None:
            print(_m(problem or "TRAVASO NON CONFIGURATO: questo brain non dichiara `travaso:` (mittente) ne' github.travaso: true (ricevente) in brain.yaml"))
            return EXIT_TRAVASO
        if a.travaso in ("send", "decisioni", "check") and (a.no_push or a.no_commit):
            print(f"travaso rinviato: {'--no-push' if a.no_push else '--no-commit'} (giro 2, #12: nessuna pubblicazione)")
            return 0
        rc = run_travaso(root, a.travaso, travaso_args(a, root, role, persona, a.travaso), quiet=a.travaso != "stato")
        return travaso_exit(rc)
    try:
        root = kc.resolve_root(a.root)
        nodes = kc.iter_nodes(root)
        targets = nodes if a.all_nodes else [kc.current_node(root, override=a.node, nodes=nodes)]
        kc.load_env(root, targets[0].dir)
        kc.brain_id(root)
    except kc.ConfigError as e:
        print(f"ERRORE configurazione: {e}")
        return 3
    if a.ops:
        try:
            rels = ops_paths(root, nodes, a.ops)
        except kc.ConfigError as e:
            print(f"ERRORE configurazione (exit 3): {e}")
            return 3
        try:
            with Lock(root):
                rc_check = commit_and_push(root, targets, a.message, push=not a.no_push, dry_run_git=a.dry_run_git,
                                           summary={"ops": rels}, ops=rels, ops_nodes=nodes)
        except SyncAbort as e:
            return int(e.code or 1)
        print("\nCommit di ops/ completato.")
        rc_t = 0 if a.no_travaso else travaso_post_step(a, root)
        return max(travaso_exit(rc_check), rc_t)
    py = sys.executable
    node_args = ["--all-nodes"] if a.all_nodes else ["--node", targets[0].path]
    scope_args = [] if a.all_nodes else ["--node", targets[0].path]
    summary = {"ingest": "saltato (--no-ingest)" if a.no_ingest else "?"}
    try:
        with Lock(root):
            bump_updated(root, targets)
            run("lint", [py, str(SCRIPTS / "lint_kb.py"), "--root", str(root), *scope_args], root)
            run("llms.txt", [py, str(SCRIPTS / "build_llms_txt.py"), "--root", str(root), *scope_args], root)
            if not a.no_ingest:
                key = "all" if a.all_nodes else targets[0].key
                state_p = kc.index_dir(root) / f"ingest_state.{key}.json"
                cur = vault_hash(root, targets, nodes)
                try:
                    prev = json.loads(state_p.read_text(encoding="utf-8")).get("vault_hash", "")
                except (OSError, ValueError):
                    prev = ""
                if cur == prev:
                    print("\n== qdrant == nessuna nota cambiata (mtime), ingest saltato")
                    summary["ingest"] = "nessuna nota cambiata"
                else:
                    run("qdrant ingest", [py, str(SCRIPTS / "rag" / "ingest.py"), "--root", str(root), *node_args], root)
                    # hash calcolato PRIMA dell'ingest: una nota salvata durante l'ingest
                    # risulta "da indicizzare" al giro dopo, non sparisce
                    kc.write_text(state_p, json.dumps({"vault_hash": cur}) + "\n")
                    summary["ingest"] = "eseguito"
            rc_check = 0
            if not a.no_commit:
                rc_check = commit_and_push(root, targets, a.message, push=not a.no_push, dry_run_git=a.dry_run_git,
                                           summary=summary)
    except SyncAbort as e:
        return int(e.code or 1)
    print("\nBrain sync completato.")
    if a.no_commit:
        return 0
    rc_t = 0 if a.no_travaso else travaso_post_step(a, root)
    return max(travaso_exit(rc_check), rc_t)


if __name__ == "__main__":
    sys.exit(main())
