"""travaso -- travaso automatico dal brain personale al brain aziendale (Brain Builder v3.3, SPEC v3.3 par. 2-6, 8, 9, 14).

Si esegue SEMPRE dalla copia in `scripts/` del CLONE del brain aziendale (regole e versione dell'azienda); il brain
personale lo lancia tramite il proprio `brain_sync.py` (post-passo), mai per path diretto. Sottocomandi:

    travaso.py send  --from <radice> --persona <p> [--brain <id>] [--verdetto <review_id>] [--ferma <path> --motivo <m>]
                     [--conferma-cancellazioni] [--dry-run-git] [--quiet] [--no-ingest]
    travaso.py check (--pr <n> [--approvo] | --staged) [--persona <p>] [--quiet] [--dry-run-git]
    travaso.py decisioni [--scrivi] [--quiet] [--dry-run-git] [--no-ingest]
    travaso.py stato [--from <radice> --persona <p>] [--da-compilare] [--quiet]
    travaso.py verifica [--from <radice>] [--review-id <id>] [--quiet]
    travaso.py init --brain-root <r> --clone <c> --persona <p> --brain <id>

Cosa fa `send` (par. 2): preflight senza mutazioni (collegamenti, radice sorgente, Master, destinazione, `gh`, fetch,
`travaso.yaml` e versione letti da `origin/main`, persona = login, allow-list dei brain, permesso, email noreply) ->
applica le decisioni gia' prese -> enumera il working tree della sorgente (snapshot dei byte, UNA lettura per file;
deny-list in `EXCLUDED_*`, segreti/binari/transcript/path di macchina esclusi e segnalati per nome) -> confronta con il
mirror su `origin/main` (aggiunte, modifiche, cancellazioni dimostrabili o ambigue, esclusi-ora che tengono la versione
precedente) -> controllo di coerenza deterministico sui FATTI strutturati (par. 5, regole `FACT_*`) contro il canon e il
registro delle decisioni -> strato semantico dell'agente (pacchetto di verifica ed exit 13; `--verdetto` puo' solo
aggiungere fermi) -> riconciliazione per file sul branch `travaso/auto/<persona>` (worktree usa-e-getta sotto
`.git/travaso/<tx>/`, mai force push), PR con status `coerenza` (success, `base:<sha7>`) e auto-merge squash -> branch
`travaso/attesa/<persona>` con i soli file fermi, PR `da-decidere` con status failure e UNA issue versionata per file
(assegnata al responsabile dell'area del canon contraddetto) -> esito in `workspace/travaso/<owner>-<repo>/` del brain
personale (mascherato) e 1-3 righe a schermo (par. 9).

Exit: 0 ok (anche 0 azioni); 3 config/radice non valida; 7 stop (PR chiusa, conflitto, worktree, blob diverso dallo
snapshot); 8 file vietati nei commit in uscita; 9 destinazione/identita'/autorizzazione/versione; 11 cancellazioni
ambigue oltre soglia o insieme vuoto (`--conferma-cancellazioni`); 12 rinviato (offline, gh assente); 13 da verificare
(pacchetto scritto: l'agente esegue `<id>-travaso verifica` e rilancia con `--verdetto`).

Controllo applicativo forte, non garanzia: il modello di minaccia sono gli errori, non un avversario (disclosure).
"""
from __future__ import annotations

import argparse
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import time
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from urllib.parse import quote

sys.path.insert(0, str(Path(__file__).resolve().parent))
import kb_config as kc  # noqa: E402
import repo_check  # noqa: E402
import brain_sync as bs  # noqa: E402
from secrets_scan import mask_secrets  # noqa: E402

TRAVASO_VERSION = "3.3.2"
EXIT_CONFIG, EXIT_STOP, EXIT_REFUSED, EXIT_DEST, EXIT_DELETIONS, EXIT_DEFERRED, EXIT_VERIFY = 3, 7, 8, 9, 11, 12, 13
BRANCH_AUTO = "travaso/auto/{persona}"
BRANCH_ATTESA = "travaso/attesa/{persona}"
BRANCH_DECISO = "travaso/deciso/{issue}"
LOCK_REF = "refs/travaso-lock/{issue}"
STATUS_CONTEXT = "coerenza"
LABEL_DA_DECIDERE, LABEL_DECISO, LABEL_IN_APPLICAZIONE = "da-decidere", "travaso-deciso", "in-applicazione"
LABEL_SEMANTICA = "semantica-non-verificata"
ZONE = kc.TRAVASO_ZONE                      # sources/travaso
REGISTER_DIR = "decisioni/travaso"
REGISTER_MD = "decisioni/TRAVASO.md"
PROTECTED_ZONES = (".github/", "scripts/", "docs/", "TEAM.md", "SECURITY.md", "travaso.yaml", "brain.config.yaml", "CODEOWNERS")
CATALOG_FOLDERS = ("self", "areas", "projects", "concepts", "docs", "entities", "data", "code", "outputs", "sources", "workspace", "ops")
LOCK_STALE_SEC = int(os.environ.get("TRAVASO_LOCK_STALE_SEC", "1800"))
TX_STALE_SEC = 2 * 3600
PACKAGE_FILE_MAX = 8 * 1024
PACKAGE_TOTAL_MAX = 200 * 1024
DELETION_THRESHOLD = 0.5
PR_FILES_MAX = 40
STATUS_MAX = 140

# ---------------------------------------------------------------------------- eleggibilita' (par. 3, 14.3): UNICO punto
EXCLUDED_DIRS = {".git", ".secrets", ".memory-backup", ".claude", ".codex", ".agents", ".github", "scripts", ".venv", "venv",
                 ".obsidian", ".tmp", "node_modules", "__pycache__", ".pytest_cache", ".travaso", "_showcase", "_template",
                 "_tipi", "_derived"}
REPORTED_DIRS = {".secrets": "sempre escluso (.secrets/)", ".memory-backup": "sempre escluso (memoria: .memory-backup/)"}
MEMORY_PREFIX = ".memory"                   # ogni segmento `.memory*` (par. 14.3)
EXCLUDED_ROOT_FILES = {"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "CONTEXT.md", "nodo.md", "brain.yaml", "brain.config.yaml",
                       "brain.profile.yaml", "brains.yaml", "doctor.toml", "llms.txt", "_index.md", "README.md", "CONVENTIONS.md",
                       "ONBOARDING.md", "TEAM.md", "SECURITY.md", "INDICE.md", "requirements.lock", ".gitignore", ".gitattributes",
                       ".template-manifest.json", "PLAN.md", "PLAN-REVIEW-LOG.md", "travaso.yaml"}
EXCLUDED_GLOBS = ("*.code-workspace", "requirements*.txt")
REPORTED_GLOBS = {"*.jsonl": "sempre escluso (*.jsonl: transcript o log dell'agente)",
                  "transcript*": "sempre escluso (transcript*)"}
EXCLUDED_REL = {"workspace/travaso": None, "workspace/feed-state.json": None, "workspace/journal/_templates": None,
                "workspace/dream": "sempre escluso (workspace/dream/: proposte dream)",
                "sources/memory": "sempre escluso (sources/memory/: snapshot della memoria)"}
OPS_MEMORY_NAMES = {"memory", "MEMORY.md"}
TRANSCRIPT_SIGNATURES = (('"parentUuid"', '"sessionId"'), ("api-request-blob",), (".claude/projects",), (".codex/sessions",))
MACHINE_PATH_RE = re.compile(r"[A-Za-z]:[\\/]|\\\\[^\\]+\\|/home/|/Users/|/mnt/")
PATH_CHECKED_NAMES = {"README.md", "CLAUDE.md", "AGENTS.md", "CLAUDE.local.md"}

# ---------------------------------------------------------------------------- fatti (par. 5.2, 14.14): regole v1
FACT_FM_EXCLUDED = {"title", "summary", "tags", "related", "status", "created", "updated", "source", "aliases", "provenienza",
                    "decisioni_travaso", "template_version", "node_path", "brain_id", "kind", "mode", "nome", "name"}
FACT_LINE_RE = re.compile(r"^\s*[-*]?\s*\*{0,2}([^:*|`#\[\]]{2,60}?)\*{0,2}\s*:\s*(.{1,120}?)\s*$")
FACT_KEY_MAX, FACT_VALUE_MAX, FACT_TEXT_MAX = 60, 120, 40
FACT_GENERIC_STEMS = {"readme", "stato", "index", "note", "todo", "_index", "notes", "appunti", "varie"}
FACT_SUBJECT_PREFIXES = ("cliente-", "ente-", "entita-", "persona-", "tool-", "strumento-", "fornitore-", "competitor-",
                         "progetto-", "project-")
FACT_SKIP_KEYS = {"http", "https", "vedi", "nota", "note", "link", "esempio", "es"}
_UNIT_MAP = {"€": "eur", "euro": "eur", "eur": "eur", "$": "usd", "usd": "usd", "£": "gbp", "gbp": "gbp", "%": "%"}
_DATE_RES = (re.compile(r"^(\d{1,2})[/-](\d{1,2})[/-](\d{4})$"), re.compile(r"^(\d{4})-(\d{2})-(\d{2})$"))
_ID_RE = re.compile(r"^(?=.*[a-z])(?=.*\d)[a-z0-9]+([.\-_][a-z0-9]+)+$")
_NUM_RE = re.compile(r"^([+-]?)(\d[\d.,]*)$")

QUIET = False
FAULT = os.environ.get("TRAVASO_FAULT", "")


class Stop(Exception):
    def __init__(self, code: int, msg: str):
        super().__init__(msg)
        self.code, self.msg = code, msg


def mask(s: str) -> str:
    return mask_secrets(str(s))[0]


def _out(text, limit: int = 200) -> str:
    """Testo per console/errori/JSON: PRIMA maschera, POI tronca (par. 14.13). Una sola funzione per tutti i canali."""
    s = mask(str(text))
    return s if len(s) <= limit else s[:limit - 1] + "…"


def say(msg: str) -> None:
    """Riga di servizio (mascherata); con --quiet non si stampa."""
    if not QUIET:
        print(mask(msg), flush=True)


def fault(point: str, *args: str) -> None:
    """Punti di guasto per i test (`TRAVASO_FAULT=<punto>`): con `TRAVASO_FAULT_SCRIPT` esegue lo script, altrimenti
    interrompe il processo come un crash (par. 14.8, 14.18)."""
    if FAULT != point:
        return
    script = os.environ.get("TRAVASO_FAULT_SCRIPT", "")
    if script:
        subprocess.run([sys.executable, script, *args], check=False)
        return
    if point.startswith("eccezione"):
        raise RuntimeError(f"guasto simulato: {point}")
    sys.stdout.flush()
    os._exit(99)


def now_iso() -> str:
    return dt.datetime.now().strftime("%Y-%m-%dT%H:%M:%S")


def sha256_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def git(cwd: Path, *args: str, input_bytes: bytes | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(["git", "-C", str(cwd), *args], capture_output=True, input=input_bytes,
                          stdin=None if input_bytes is not None else subprocess.DEVNULL)


def git_out(cwd: Path, *args: str) -> str:
    r = git(cwd, *args)
    return r.stdout.decode("utf-8", "replace").strip() if r.returncode == 0 else ""


def git_ok(cwd: Path, *args: str) -> bool:
    return git(cwd, *args).returncode == 0


def git_err(r: subprocess.CompletedProcess) -> str:
    return _out(r.stderr.decode("utf-8", "replace").strip(), 200)

def file_id(rel: str, counter: dict) -> str:
    """Nome del file nelle uscite: se il NOME stesso contiene un segreto, un id interno `file-<n>` (par. 14.13)."""
    if repo_check.secret_kinds("x.txt", rel.encode("utf-8")) or repo_check.secret_kinds(rel, rel.encode("utf-8")):
        counter.setdefault(rel, f"file-{len(counter) + 1}")
        return counter[rel]
    return rel


def yaml_mod():
    y = kc._yaml_module()
    if y is None:
        raise Stop(EXIT_CONFIG, "serve PyYAML nel python che esegue il travaso (requirements.txt del motore)")
    return y


def yaml_dump(obj) -> str:
    return yaml_mod().safe_dump(obj, sort_keys=False, allow_unicode=True, default_flow_style=False)


# ---------------------------------------------------------------------------- contesto del clone (par. 6.2, 14.5, 14.21)
@dataclass
class Ctx:
    clone: Path
    run: bs.Runner
    owner: str = ""
    repo: str = ""
    git_dir: Path = field(default_factory=Path)
    quiet: bool = False
    dry: bool = False
    no_ingest: bool = False
    ty: dict = field(default_factory=dict)          # travaso.yaml letto da origin/main
    login: str = ""
    persona: str = ""
    base_sha: str = ""
    brain_id: str = ""                               # brain_id del brain aziendale
    nodes: list = field(default_factory=list)
    tx: "Tx | None" = None
    out_lines: list[str] = field(default_factory=list)

    @property
    def full(self) -> str:
        return f"{self.owner}/{self.repo}"

    @property
    def org(self) -> str:
        return self.owner

    def gh(self, *args: str, write: bool = False, input_text: str | None = None):
        return self.run.gh(*args, write=write, input_text=input_text)

    def gh_json(self, *args: str):
        """Lettura JSON da gh. 404 / "non trovato" = None (assenza); ogni ALTRO errore = Stop 9 (#24): mai confondere un
        errore di rete o di autorizzazione con un'assenza."""
        r = self.gh(*args)
        if r is None:
            raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente o senza risposta")
        if r.returncode != 0:
            err = ((r.stderr or "") + (r.stdout or "")).lower()
            if "404" in err or "not found" in err or "could not resolve" in err or "no pull requests found" in err:
                return None
            raise Stop(EXIT_DEST, f"gh {' '.join(args[:3])} in errore: {_out((r.stderr or r.stdout or '').strip(), 160)}")
        try:
            return json.loads(r.stdout)
        except ValueError:
            return None

    def gh_api_write(self, method: str, path: str, body: dict | None = None):
        """Scrittura REST: errori di autorizzazione/validazione = exit 9 (mai 12), par. 14.24."""
        args = ["api", "-X", method, path]
        text = None
        if body is not None:
            args += ["--input", "-"]
            text = json.dumps(body)
        r = self.gh(*args, write=True, input_text=text)
        if r is None:
            raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente o senza risposta")
        if r.returncode != 0:
            raise Stop(EXIT_DEST, f"GitHub rifiuta {method} {path}: {_out(r.stderr.strip(), 200)}")
        try:
            return json.loads(r.stdout) if r.stdout.strip() else {}
        except ValueError:
            return {}

    def persone(self) -> dict:
        return self.ty.get("persone") or {}

    def aree(self) -> dict:
        return self.ty.get("aree") or {}

    def area_of(self, persona: str) -> str:
        return str((self.persone().get(persona) or {}).get("area") or "")

    def login_of(self, persona: str) -> str:
        return str((self.persone().get(persona) or {}).get("login") or "")

    def responsabile(self, area: str) -> tuple[str, str, str]:
        """(persona responsabile, login, area effettiva): area ignota -> responsabile_default (par. 6.4)."""
        a = self.aree().get(area) if area else None
        if isinstance(a, dict) and a.get("responsabile"):
            p = str(a["responsabile"])
            return p, self.login_of(p), area
        p = str(self.ty.get("responsabile_default") or "")
        return p, self.login_of(p), self.area_of(p)

    def team_of(self, area: str) -> str:
        a = self.aree().get(area) if area else None
        return str(a.get("team") or "") if isinstance(a, dict) else ""

    def policy(self) -> str:
        v = str(self.ty.get("verifica_semantica") or "richiesta").strip().lower()
        return "facoltativa" if v == "facoltativa" else "richiesta"


def _check_link_base(label: str, base: Path, code: int) -> None:
    if kc.is_link(base):
        raise Stop(code, f"{label} e' un link, una junction o un reparse point ({base}): non si procede (par. 14.5)")


def _check_link_inside(label: str, base: Path, target: Path, code: int) -> None:
    hit = kc.link_in_path(base, target)
    if hit is not None:
        raise Stop(code, f"{label}: `{hit}` e' un link, una junction o un reparse point: non si procede (par. 14.5)")


def _check_link_chain(label: str, orig: Path, code: int) -> None:
    """Path ORIGINALE (non risolto, par. 14.5): la base stessa e ogni componente dall'ancora in giu' non devono essere
    link, junction o reparse point."""
    p = Path(os.path.abspath(str(orig)))
    if kc.is_link(p):
        raise Stop(code, f"{label} e' un link, una junction o un reparse point ({p}): non si procede (par. 14.5)")
    hit = kc.link_in_path(Path(p.anchor), p)
    if hit is not None:
        raise Stop(code, f"{label}: `{hit}` nel percorso e' un link, una junction o un reparse point: non si procede (par. 14.5)")


def open_ctx(root_arg: str | None, dry: bool, quiet: bool, no_ingest: bool = False) -> Ctx:
    """Clone del brain aziendale = radice del motore (come gli altri script), oppure --root. Nessuna mutazione.
    I collegamenti si controllano sul path ORIGINALE (argomento o posizione dello script), prima di risolverlo; un
    git-common-dir fuori dal clone (`.git` file) si controlla con il suo genitore (#5)."""
    orig = Path(root_arg) if root_arg else Path(sys.argv[0]).parent.parent if sys.argv and sys.argv[0] else Path.cwd()
    _check_link_chain("il clone del brain aziendale", orig, EXIT_DEST)
    try:
        clone = kc.resolve_root(root_arg)
    except kc.ConfigError as e:
        raise Stop(EXIT_CONFIG, f"clone del brain aziendale non riconosciuto: {e}") from e
    _check_link_base("il clone del brain aziendale", clone, EXIT_DEST)
    if (clone / ".git").is_file():
        # `.git` file (worktree o clone staccato): il path scritto dentro si controlla COM'E' SCRITTO, prima che git lo
        # risolva (git riporta --git-common-dir gia' risolto e nasconderebbe una junction, #5)
        try:
            raw = (clone / ".git").read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            raw = ""
        if raw.lower().startswith("gitdir:"):
            gd_raw = raw.split(":", 1)[1].strip()
            _check_link_chain("il repository principale del clone (gitdir nel file .git)",
                              Path(gd_raw) if Path(gd_raw).is_absolute() else clone / gd_raw, EXIT_DEST)
    gd = git_out(clone, "rev-parse", "--git-common-dir")
    if not gd:
        raise Stop(EXIT_CONFIG, f"{clone} non e' un repository git (clona il brain aziendale e usa inizializza_clone.py)")
    git_dir = Path(gd) if Path(gd).is_absolute() else (clone / gd)
    git_dir = Path(os.path.normpath(str(git_dir)))
    _check_link_base("la cartella .git del clone", git_dir, EXIT_DEST)
    try:
        git_dir.relative_to(clone)
    except ValueError:
        _check_link_base("il repository principale del clone (git-common-dir)", git_dir.parent, EXIT_DEST)
        _check_link_inside("il repository principale del clone", git_dir.parent, git_dir, EXIT_DEST)
        _check_link_chain("il repository principale del clone", git_dir.parent, EXIT_DEST)
    if (clone / ".git").exists():
        _check_link_inside("il clone", clone, clone / ".git", EXIT_DEST)
    for rel in (ZONE, kc.TRAVASO_WORKSPACE, "decisioni"):
        p = clone / rel
        if p.exists():
            _check_link_inside("il clone", clone, p, EXIT_DEST)
            for sub in p.rglob("*"):
                if kc.is_link(sub):
                    raise Stop(EXIT_DEST, f"il clone: `{sub.relative_to(clone).as_posix()}` e' un link/junction (par. 14.5)")
    run = bs.Runner(clone, dry)
    ctx = Ctx(clone=clone, run=run, git_dir=git_dir, quiet=quiet, dry=dry, no_ingest=no_ingest)
    try:
        gh_cfg = kc.github_config(clone)
    except kc.ConfigError as e:
        raise Stop(EXIT_DEST, str(e)) from e
    if gh_cfg.get("mode") != "org":
        raise Stop(EXIT_DEST, f"il clone {clone.name} non e' un brain d'organizzazione (github.mode {gh_cfg.get('mode') or 'assente'}): "
                              "il travaso vale solo verso un brain aziendale con github.mode org e merge coerenza")
    _owner, url = bs.remote_owner(clone)
    parsed = bs.parse_github(url)
    if parsed is None:
        raise Stop(EXIT_DEST, f"il clone non ha un remote `origin` GitHub ({_out(url or 'assente', 120)})")
    ctx.owner, ctx.repo = parsed
    if gh_cfg.get("owner") and gh_cfg.get("repo") and (gh_cfg["owner"].lower(), gh_cfg["repo"].lower()) != (ctx.owner.lower(), ctx.repo.lower()):
        raise Stop(EXIT_DEST, f"origin del clone punta a {ctx.full} ma brain.yaml dichiara {gh_cfg['owner']}/{gh_cfg['repo']}")
    try:
        ctx.nodes = kc.iter_nodes(clone)
    except kc.ConfigError as e:
        raise Stop(EXIT_CONFIG, f"profilo del brain aziendale non leggibile: {e}") from e
    ctx.brain_id = yaml_brain_id(clone) or clone.name
    return ctx

def yaml_brain_id(root: Path) -> str:
    """brain_id da nodo.md/brain.yaml SENZA guardare l'ambiente (BRAIN_ID del processo e' quello di un altro brain)."""
    v = kc.fm_str(kc._read_node_meta(Path(root)).get("brain_id")) or kc.fm_str(kc._brain_yaml(root).get("brain_id"))
    return v


def gh_login_strict(ctx: Ctx) -> str:
    r = ctx.gh("api", "user", "-q", ".login")
    if r is None:
        raise Stop(EXIT_DEFERRED, "travaso rinviato: `gh` assente o senza risposta (installa GitHub CLI e fai `gh auth login`)")
    if r.returncode != 0 or not r.stdout.strip():
        raise Stop(EXIT_DEST, f"gh non autorizzato o non loggato: {_out(r.stderr.strip(), 160) or 'nessun login'} (gh auth status)")
    return r.stdout.strip()

def fetch_or_defer(ctx: Ctx) -> None:
    """UN solo fetch per corsa (par. 14.9): `base_sha` resta fissato e si ricontrolla prima di ogni mutazione.
    In dry-run NESSUN fetch (#12): si usa `origin/main` locale e lo si dice."""
    if QUIET:
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            bs.check_rewrites(ctx.run, ctx.owner, ctx.repo)
    else:
        bs.check_rewrites(ctx.run, ctx.owner, ctx.repo)
    if ctx.dry:
        if not ctx.run.has_ref("refs/remotes/origin/main"):
            raise Stop(EXIT_DEFERRED, "dry-run: origin/main locale assente, serve un fetch (rilancia senza --dry-run-git)")
        print("[dry-run-git] dry: base locale non aggiornata (nessun fetch)")
        ctx.base_sha = git_out(ctx.clone, "rev-parse", "refs/remotes/origin/main")
        return
    f = ctx.run.git("fetch", "origin", "--quiet", "--prune")
    if f.returncode != 0:
        raise Stop(EXIT_DEFERRED, f"travaso rinviato: `git fetch origin` fallito (offline?): {_out(f.stderr.strip(), 120)}")
    if not ctx.run.has_ref("refs/remotes/origin/main"):
        raise Stop(EXIT_DEST, "origin/main assente: il primo push del brain aziendale lo fa `github_org.py apply`")
    ctx.base_sha = git_out(ctx.clone, "rev-parse", "refs/remotes/origin/main")

def assert_base(ctx: Ctx) -> None:
    """Prima di ogni mutazione: origin/main deve essere ancora la base fissata all'inizio della corsa (par. 14.9)."""
    cur = git_out(ctx.clone, "rev-parse", "refs/remotes/origin/main")
    if ctx.base_sha and cur and cur != ctx.base_sha:
        raise Stop(EXIT_STOP, f"la base origin/main e' cambiata durante la corsa ({ctx.base_sha[:7]} -> {cur[:7]}): nessuna mutazione, "
                              "rilancia il travaso")

def show_main(ctx: Ctx, path: str, ref: str = "refs/remotes/origin/main") -> bytes | None:
    r = git(ctx.clone, "cat-file", "-p", f"{ref}:{path}")
    return r.stdout if r.returncode == 0 else None


def load_travaso_yaml(ctx: Ctx) -> None:
    """`travaso.yaml` letto da origin/main (mai dalla copia di lavoro), versione del motore confrontata (par. 14.21)."""
    raw = show_main(ctx, "travaso.yaml")
    if raw is None:
        raise Stop(EXIT_DEST, f"travaso.yaml assente su origin/main di {ctx.full}: il brain non accetta travasi "
                              "(lo genera `github_org.py scaffold`/`apply` per i brain con travaso.accetta)")
    try:
        data = yaml_mod().safe_load(raw.decode("utf-8-sig", "replace"))
    except Exception as e:  # noqa: BLE001
        raise Stop(EXIT_DEST, f"travaso.yaml su origin/main non valido: {e}") from e
    if not isinstance(data, dict):
        raise Stop(EXIT_DEST, "travaso.yaml su origin/main non e' una mappa")
    org, repo = str(data.get("org") or ""), str(data.get("repo") or "")
    if (org.lower(), repo.lower()) != (ctx.owner.lower(), ctx.repo.lower()):
        raise Stop(EXIT_DEST, f"origin del clone e' {ctx.full} ma travaso.yaml dichiara {org}/{repo}: clone sbagliato")
    ctx.ty = data
    mine = Path(__file__).read_bytes().replace(b"\r\n", b"\n")
    theirs = show_main(ctx, "scripts/travaso.py")
    if theirs is None or theirs.replace(b"\r\n", b"\n") != mine:
        raise Stop(EXIT_DEST, "aggiorna il clone (git pull): scripts/travaso.py locale diverso da origin/main (versione "
                              f"locale {TRAVASO_VERSION}); nessuna mutazione eseguita")


def identity_checks(ctx: Ctx, persona: str, brain_id: str | None = None) -> None:
    """persona <-> login, allow-list dei brain (presente = vincolante, anche vuota: par. 14.4), owner Organization, permesso
    push, email noreply (par. 6.2, 14.15)."""
    ctx.login = gh_login_strict(ctx)
    persone = ctx.persone()
    if persona not in persone:
        raise Stop(EXIT_DEST, f"persona `{persona}` non presente in travaso.yaml di {ctx.full} (persone: {', '.join(sorted(persone)) or '-'})")
    want = ctx.login_of(persona)
    if want.lower() != ctx.login.lower():
        raise Stop(EXIT_DEST, f"persona `{persona}` corrisponde al login `{want}` ma l'account gh attivo e' `{ctx.login}`: "
                              f"gh auth switch --user {want}")
    ctx.persona = persona
    allowed = (persone.get(persona) or {}).get("brains")
    if brain_id and isinstance(allowed, list):
        if not allowed:
            raise Stop(EXIT_DEST, f"`persone.{persona}.brains: []` in travaso.yaml: nessun brain ammesso per {persona} "
                                  f"(aggiungi `{brain_id}` alla lista o togli la chiave)")
        if brain_id not in [str(x) for x in allowed]:
            raise Stop(EXIT_DEST, f"brain `{brain_id}` non e' nell'allow-list `persone.{persona}.brains` di travaso.yaml "
                                  f"({', '.join(str(x) for x in allowed)})")
    otype = bs.owner_type(ctx.owner, ctx.run)
    if otype != "Organization":
        raise Stop(EXIT_DEST, f"`{ctx.owner}` non e' un'organizzazione GitHub ({otype or 'tipo non verificabile'}): il travaso va solo in un brain d'org")
    perm = bs.repo_permission(ctx.owner, ctx.repo, ctx.run)
    if perm is not True:
        raise Stop(EXIT_DEST, f"l'account `{ctx.login}` non ha permesso di scrittura su {ctx.full} (o il repo non e' visibile): "
                              "chiedi al responsabile dell'org (team con push)")
    r = ctx.gh("api", f"repos/{ctx.full}", "--jq", ".private")
    is_public = r is not None and r.returncode == 0 and r.stdout.strip().lower() == "false"
    if is_public:
        email = git_out(ctx.clone, "config", "--get", "user.email")
        if email and not email.lower().endswith("@users.noreply.github.com"):
            raise Stop(EXIT_DEST, f"{ctx.full} e' pubblico: l'email di commit del clone non e' un indirizzo noreply di GitHub. "
                                  "Imposta `git config user.email <id>+<login>@users.noreply.github.com` nel clone")

# ---------------------------------------------------------------------------- sorgente: radice, brain_id, snapshot (par. 3, 14.3, 14.4, 14.18)
@dataclass
class SourceFile:
    rel: str
    data: bytes
    sha256: str
    size: int
    text: str | None          # None = binario


@dataclass
class Source:
    root: Path
    brain_id: str
    nodes: list
    head_sha: str
    dirty: int
    is_kit: bool


@dataclass
class Snapshot:
    eligible: dict[str, SourceFile] = field(default_factory=dict)
    excluded: list[tuple[str, str]] = field(default_factory=list)      # (rel, motivo) SEGNALATI
    ignored: int = 0                                                   # infrastruttura, in silenzio
    present: set[str] = field(default_factory=set)                     # tutti i path del working tree


def _source_mode(root: Path) -> str:
    y = kc._brain_yaml(root)
    m = kc.fm_str(y.get("mode")) if isinstance(y, dict) else ""
    return m or kc.fm_str(kc._read_node_meta(root).get("mode"))


def load_source(from_root: str, brain_arg: str | None, consenti_master: bool) -> Source:
    _check_link_chain("la radice sorgente", Path(from_root), EXIT_CONFIG)
    root = Path(from_root).resolve()
    if not root.is_dir():
        raise Stop(EXIT_CONFIG, f"--from {from_root}: cartella inesistente")
    top = git_out(root, "rev-parse", "--show-toplevel")
    if not top or Path(top).resolve() != root:
        raise Stop(EXIT_CONFIG, f"--from {root}: deve essere la RADICE di un repository git (toplevel = radice)")
    has_marker = (root / "brain.yaml").is_file() or (root / "nodo.md").is_file()
    has_catalog = any((root / f).is_dir() for f in CATALOG_FOLDERS)
    if not has_marker and not has_catalog:
        raise Stop(EXIT_CONFIG, f"--from {root}: non sembra un brain (ne' brain.yaml/nodo.md ne' una cartella del catalogo "
                                f"{', '.join(CATALOG_FOLDERS[:6])}...)")
    if _source_mode(root) == "master" and not consenti_master:
        raise Stop(EXIT_DEST, "il Master non travasa: se e' voluto, travaso.consenti_master: true (brain.yaml della sorgente)")
    bid = (brain_arg or "").strip()
    if not bid:
        bid = yaml_brain_id(root)
    if not bid:
        cfg = root / ".travaso" / "config.yaml"
        if cfg.is_file():
            m = re.search(r"^brain:\s*[\"']?([A-Za-z0-9-]+)", cfg.read_text(encoding="utf-8-sig"), re.M)
            bid = m.group(1) if m else ""
    if not bid:
        raise Stop(EXIT_CONFIG, "brain_id della sorgente non trovato: per un brain non kit passa --brain <id> "
                                "(o esegui `travaso.py init`)")
    if not kc.TRAVASO_ID_RE.match(bid):
        raise Stop(EXIT_CONFIG, f"brain_id `{bid}` non valido: atteso {kc.TRAVASO_ID_RE.pattern}")
    try:
        nodes = kc.iter_nodes(root)
    except kc.ConfigError as e:
        raise Stop(EXIT_CONFIG, f"profilo della sorgente non leggibile: {e}") from e
    head = git_out(root, "rev-parse", "HEAD")
    dirty = len([x for x in git_out(root, "status", "--porcelain", "--untracked-files=all").splitlines() if x.strip()])
    return Source(root=root, brain_id=bid, nodes=nodes, head_sha=head or "(nessun commit)", dirty=dirty, is_kit=has_marker)

def _node_for(rel: str, nodes: list) -> tuple[object, str]:
    """(nodo piu' profondo che contiene il path, path relativo al nodo)."""
    best, best_rel = nodes[0], rel
    for n in nodes:
        if n.is_root:
            continue
        pre = n.path + "/"
        if rel.startswith(pre) and (best.is_root or len(n.path) > len(best.path)):
            best, best_rel = n, rel[len(pre):]
    return best, best_rel


def classify_path(rel: str, nodes: list, memory_prefixes: tuple[str, ...]) -> tuple[str, str | None]:
    """('ok' | 'silenzio' | 'segnalato', motivo) per un path relativo alla radice. Confronti case-insensitive con
    separatori normalizzati (par. 14.3): `MEMORY.md` e le cartelle `memory/` sono escluse OVUNQUE."""
    rel = rel.replace("\\", "/")
    parts = rel.split("/")
    if ".." in parts or rel.startswith("/") or ":" in rel:
        return "segnalato", "path non ammesso (`..` o assoluto)"
    low = [p.lower() for p in parts]
    reported_dirs = {k.lower(): v for k, v in REPORTED_DIRS.items()}
    excluded_dirs = {d.lower() for d in EXCLUDED_DIRS}
    for seg in low[:-1]:
        if seg in reported_dirs:
            return "segnalato", reported_dirs[seg]
        if seg.startswith(MEMORY_PREFIX) or seg == "memory":
            return "segnalato", f"sempre escluso (memoria: {seg}/)"
        if seg in excluded_dirs:
            return "silenzio", None
    name = parts[-1]
    lname = name.lower()
    if lname.startswith(".env"):
        return "segnalato", "sempre escluso (.env*: nemmeno .env.example)"
    if lname.startswith(MEMORY_PREFIX) or lname == "memory.md":
        return "segnalato", f"sempre escluso (memoria: {name})"
    for g, why in REPORTED_GLOBS.items():
        if PurePosixPath(lname).match(g):
            return "segnalato", why
    for g in EXCLUDED_GLOBS:
        if PurePosixPath(lname).match(g.lower()):
            return "silenzio", None
    if lname in ("_index.md", ".keep", ".gitkeep"):
        return "silenzio", None
    norm = "/".join(low)
    for pre in memory_prefixes:
        pre = pre.replace("\\", "/").strip("/").lower()
        if pre and (norm == pre or norm.startswith(pre + "/")):
            return "segnalato", f"sempre escluso (memoria del nodo: {pre}/)"
    node, nrel = _node_for(rel, nodes)
    nparts = nrel.split("/")
    nlow = nrel.lower()
    if len(nparts) == 1:
        return "silenzio", None                      # file di radice/nodo: fuori (CLAUDE.md, README.md, brain.yaml, ...)
    for prefix, why in EXCLUDED_REL.items():
        if nlow == prefix or nlow.startswith(prefix + "/"):
            return ("segnalato", why) if why else ("silenzio", None)
    prof = node.profile
    allowed = {x.lower() for x in (set(CATALOG_FOLDERS) if prof.is_default else set(prof.folders) | set(prof.raw_dirs) | set(prof.ops_dirs))}
    first = nparts[0].lower()
    if first not in allowed:
        return "silenzio", None
    if first in {x.lower() for x in prof.raw_dirs} or first == "sources":
        for cr in prof.corpus_roots:
            cr = cr.strip("/").lower()
            if nlow == cr or nlow.startswith(cr + "/"):
                return "silenzio", None
    return "ok", None

def _transcript_signature(text: str) -> bool:
    flat = text.replace("\\", "/")
    return any(all(tok in flat for tok in sig) for sig in TRANSCRIPT_SIGNATURES)

def _machine_path_line(text: str) -> int | None:
    for i, ln in enumerate(text.splitlines(), 1):
        if MACHINE_PATH_RE.search(ln):
            return i
    return None


def enumerate_source(src: Source) -> Snapshot:
    """Insieme di partenza = working tree (`git ls-files --cached --others --exclude-standard`); ogni file ammesso si legge
    UNA volta (snapshot dei byte: scansione, hash e copia usano lo stesso buffer, par. 14.18)."""
    snap = Snapshot()
    r = git(src.root, "ls-files", "-z", "--cached")
    r2 = git(src.root, "ls-files", "-z", "--others", "--exclude-standard")
    if r.returncode != 0 or r2.returncode != 0:
        raise Stop(EXIT_CONFIG, f"git ls-files fallito nella sorgente: {git_err(r if r.returncode else r2)}")
    tracked = {x.decode("utf-8", "replace") for x in r.stdout.split(b"\0") if x}
    rels = sorted(tracked | {x.decode("utf-8", "replace") for x in r2.stdout.split(b"\0") if x})
    mem = repo_check.memory_prefixes(src.root)
    fault("prima-lettura", str(src.root))
    for rel in rels:
        p = src.root / rel
        try:
            os.lstat(p)
            snap.present.add(rel)
        except OSError:
            if rel in tracked:
                continue                                  # tracciato ma assente: cancellazione (par. 14.16)
            snap.excluded.append((rel, "illeggibile (sparito durante la lettura)"))
            continue
        if repo_check.secret_kinds("nome.txt", rel.encode("utf-8")):
            snap.excluded.append((rel, "possibile segreto nel NOME del file (il path finirebbe nella storia git)"))
            continue
        kind, why = classify_path(rel, src.nodes, mem)
        if kind == "silenzio":
            snap.ignored += 1
            continue
        if kind == "segnalato":
            snap.excluded.append((rel, why or "escluso"))
            continue
        hit = kc.link_in_path(src.root, p)
        if hit is not None:
            snap.excluded.append((rel, f"link, junction o reparse point nel percorso ({hit.relative_to(src.root).as_posix()})"))
            continue
        why = repo_check.path_reason(rel, mem)
        if why:
            snap.excluded.append((rel, why))
            continue
        try:
            if not p.is_file():
                snap.excluded.append((rel, "illeggibile (non e' un file regolare o sparito durante la lettura)"))
                continue
            data = p.read_bytes()
        except OSError as e:
            snap.excluded.append((rel, f"illeggibile ({e.__class__.__name__}: sparito o bloccato durante la lettura)"))
            continue
        big = repo_check.size_reason(rel, len(data))
        if big:
            snap.excluded.append((rel, big))
            continue
        text = None if repo_check.is_small_binary(rel) else repo_check.decode_text(data)
        if text is not None:
            if _transcript_signature(text):
                snap.excluded.append((rel, "transcript o memoria dell'agente (firma nel testo)"))
                continue
            kinds = repo_check.secret_kinds(rel, data)
            if kinds:
                snap.excluded.append((rel, "possibile segreto nel contenuto (" + ", ".join(kinds) + ")"))
                continue
            node, nrel = _node_for(rel, src.nodes)
            nparts = nrel.split("/")
            if nparts[0] in (set(node.profile.ops_dirs) | {"ops"}) and nparts[-1] in PATH_CHECKED_NAMES:
                ln = _machine_path_line(text)
                if ln is not None:
                    snap.excluded.append((rel, f"path di macchina (riga {ln}): non portabile, resta fuori"))
                    continue
        snap.eligible[rel] = SourceFile(rel=rel, data=data, sha256=sha256_bytes(data), size=len(data), text=text)
    fault("dopo-lettura", str(src.root))
    return snap


# ---------------------------------------------------------------------------- fatti strutturati (par. 5.2, 14.14)
@dataclass(frozen=True)
class Fact:
    subjects: tuple[str, ...]
    key: str
    value: str          # normalizzato e tipizzato: num:..., date:..., id:..., txt:...
    raw_key: str
    raw_value: str
    line: int


def _strip_accents(s: str) -> str:
    return "".join(ch for ch in unicodedata.normalize("NFKD", s) if not unicodedata.combining(ch))


def norm_text(s: str) -> str:
    s = _strip_accents(str(s)).lower().replace("*", "").replace("_", " ").replace("`", "")
    s = re.sub(r"\s+", " ", s).strip()
    s = re.sub(r"[.;:,!?]+$", "", s).strip()
    return s


def _norm_subject(s: str) -> str:
    s = norm_text(s)
    s = re.sub(r"[^\w\s-]", "", s)
    return re.sub(r"\s+", " ", s).strip()


def _parse_number(core: str) -> str | None:
    """`1.200,50` -> 1200.5, `1,200.50` -> 1200.5, `1.200.000` -> 1200000, `1200` -> 1200; UNA sola separazione (`1.5`,
    `1,200`) e' ambigua (it/en) -> None = confronto testuale."""
    dots, commas = core.count("."), core.count(",")
    if dots == 0 and commas == 0:
        return str(int(core))
    if dots and commas:
        last = max(core.rfind("."), core.rfind(","))
        dec_sep = core[last]
        int_part = re.sub(r"[.,]", "", core[:last])
        frac = core[last + 1:]
        if not re.fullmatch(r"\d*", frac) or not int_part.isdigit():
            return None
        return _fmt_num(int_part, frac) if dec_sep else None
    sep = "." if dots else ","
    n = dots or commas
    if n == 1:
        return None                                   # ambiguo
    groups = core.split(sep)
    if all(g.isdigit() for g in groups) and all(len(g) == 3 for g in groups[1:]):
        return str(int("".join(groups)))
    return None


def _fmt_num(int_part: str, frac: str) -> str:
    frac = frac.rstrip("0")
    return f"{int(int_part)}.{frac}" if frac else str(int(int_part))


def normalize_value(raw: str) -> str:
    v = norm_text(raw)
    v = v.strip("\"'")
    if not v:
        return "txt:"
    for rx in _DATE_RES:
        m = rx.match(v)
        if m:
            a, b, c = m.groups()
            y, mth, d = (int(a), int(b), int(c)) if len(a) == 4 else (int(c), int(b), int(a))
            try:
                return "date:" + dt.date(y, mth, d).isoformat()
            except ValueError:
                return "txt:" + v
    if _ID_RE.match(v) and not re.fullmatch(r"[\d.,]+", v):
        return "id:" + v
    m = re.match(r"^([^\d\s+-]{1,4})?\s*([+-]?\d[\d.,]*)\s*([^\d\s]{1,5}|[a-z]{1,4})?$", v)
    if m:
        pre, num, post = m.group(1) or "", m.group(2), m.group(3) or ""
        unit = _UNIT_MAP.get(post.lower()) or _UNIT_MAP.get(pre.lower()) or ""
        if (post and not unit) or (pre and not unit):
            return "txt:" + v
        sign = "-" if num.startswith("-") else ""
        parsed = _parse_number(num.lstrip("+-"))
        if parsed is not None:
            return f"num:{sign}{parsed}" + (f" {unit}" if unit else "")
        return "txt:" + v
    return "txt:" + re.sub(r"(?<=[a-z])\.(?=[a-z]|$)", "", v)       # S.p.A. -> spa (abbreviazioni)


def _namespace_and_stem(rel: str) -> tuple[str, str]:
    prov = kc.travaso_provenance(rel)
    inner = prov[2] if prov else rel
    parts = inner.split("/")
    ns = next((p for p in parts[:-1] if p in CATALOG_FOLDERS), parts[0] if len(parts) > 1 else "")
    return ns, PurePosixPath(parts[-1]).stem


def subjects_for(rel: str, fm: dict) -> tuple[str, ...]:
    ns, stem = _namespace_and_stem(rel)
    out: list[str] = []
    st = stem.lower()
    for pre in FACT_SUBJECT_PREFIXES:
        if st.startswith(pre) and len(st) > len(pre):
            st = st[len(pre):]
            break
    if st not in FACT_GENERIC_STEMS and stem.lower() not in FACT_GENERIC_STEMS:
        out.append(f"{ns}/{_norm_subject(st.replace('-', ' ').replace('_', ' '))}")
    title = kc.fm_str(fm.get("title")) if fm else ""
    if title:
        t = _norm_subject(title)
        if t and t not in FACT_GENERIC_STEMS:
            out.append(f"{ns}/{t}")
    aliases = fm.get("aliases") if fm else None
    for a in (aliases if isinstance(aliases, list) else [aliases] if aliases else []):
        t = _norm_subject(kc.fm_str(a))
        if t:
            out.append(f"{ns}/{t}")
    seen: list[str] = []
    for s in out:
        if s.endswith("/") or s in seen:
            continue
        seen.append(s)
    return tuple(seen)


def _fact_like(value: str) -> bool:
    v = value.strip()
    if not v or len(v) > FACT_VALUE_MAX:
        return False
    return any(ch.isdigit() for ch in v) or len(v) <= FACT_TEXT_MAX


def extract_facts(text: str, rel: str) -> list[Fact]:
    """Fatti di una nota: frontmatter scalare (tranne i campi di servizio), righe `chiave: valore` e tabelle a due celle
    del corpo (intestazione e separatori saltati, blocchi di codice saltati). `.txt`: solo il corpo."""
    is_txt = rel.lower().endswith(".txt")
    fm: dict = {}
    body = text
    if is_txt:
        m = re.match(r"^\ufeff?---\s*\n.*?\n---\s*\n", text, re.S)
        body = text[m.end():] if m else text
    else:
        try:
            fm, body = kc.read_frontmatter(text)
        except kc.FrontmatterError:
            fm, body = {}, text
    subjects = subjects_for(rel, fm)
    if not subjects:
        return []
    facts: list[Fact] = []
    if not is_txt:
        for k, v in fm.items():
            kn = norm_text(str(k))
            if kn in FACT_FM_EXCLUDED or not isinstance(v, (str, int, float, bool, dt.date)) or isinstance(v, bool):
                continue
            raw = kc.fm_str(v)
            if _fact_like(raw) and 2 <= len(kn) <= FACT_KEY_MAX:
                facts.append(Fact(subjects, kn, normalize_value(raw), str(k), raw, 0))
    in_code = False
    table_header_pending = False
    for i, ln in enumerate(body.splitlines(), 1):
        s = ln.strip()
        if s.startswith("```") or s.startswith("~~~"):
            in_code = not in_code
            continue
        if in_code or not s:
            table_header_pending = False
            continue
        if s.startswith("|"):
            cells = [c.strip() for c in s.strip("|").split("|")]
            if all(re.fullmatch(r":?-{2,}:?", c) for c in cells if c):
                continue                                  # separatore
            if not table_header_pending:
                table_header_pending = True               # prima riga = intestazione
                continue
            cells = [c for c in cells if c]
            if len(cells) == 2:
                _add_fact(facts, subjects, cells[0], cells[1], i)
            continue
        table_header_pending = False
        if s.startswith("#"):
            continue
        m = FACT_LINE_RE.match(ln)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if "http" in key.lower() or "[[" in key or key.strip().startswith("<"):
            continue
        _add_fact(facts, subjects, key, val, i)
    return facts


def _add_fact(facts: list[Fact], subjects: tuple[str, ...], key: str, val: str, line: int) -> None:
    kn = norm_text(key)
    if not (2 <= len(kn) <= FACT_KEY_MAX) or kn in FACT_SKIP_KEYS or not _fact_like(val):
        return
    if len(kn.split()) > 6:
        return                                            # frase, non chiave
    facts.append(Fact(subjects, kn, normalize_value(val), key.strip(), val.strip(), line))


# ---------------------------------------------------------------------------- canon e registro (par. 5.1, 5.3, 14.6, 14.15)
@dataclass
class CanonFact:
    value: str
    raw: str
    persona: str | None      # None = azienda
    area: str
    nota: str
    data: str


@dataclass
class Incongruenza:
    soggetto: str
    chiave: str
    nuovo: str
    nuovo_raw: str
    canon: str
    canon_raw: str
    canon_persona: str      # persona o "canon"
    canon_area: str
    canon_nota: str
    canon_data: str
    contro_decisione: int | None = None
    fonte: str = "fatti"    # fatti | agente | manuale | verifica

    def key(self) -> tuple:
        return (self.soggetto, self.chiave, self.nuovo, self.canon)

    def as_dict(self) -> dict:
        return {"soggetto": self.soggetto, "chiave": self.chiave, "nuovo": self.nuovo_raw, "nuovo_norm": self.nuovo,
                "canon": self.canon_raw, "canon_norm": self.canon, "canon_persona": self.canon_persona,
                "canon_area": self.canon_area, "canon_nota": self.canon_nota, "canon_data": self.canon_data,
                "contro_decisione": self.contro_decisione, "fonte": self.fonte}


class Canon:
    """Canon su origin/main: note compilate (radice e nodi), decisioni/, raw di ALTRE persone; registro delle decisioni."""

    def __init__(self, ctx: Ctx, persona: str, ref: str = "refs/remotes/origin/main"):
        self.ctx, self.persona, self.ref = ctx, persona, ref
        self.facts: dict[tuple[str, str], list[CanonFact]] = {}
        self.texts: dict[str, str] = {}
        self.meta: dict[str, dict] = {}
        self.register: list[dict] = []
        self.reg_index: dict[tuple[str, str], list[dict]] = {}
        self.n_facts = 0
        self._load()

    def _tree(self) -> dict[str, str]:
        r = git(self.ctx.clone, "ls-tree", "-r", "-z", self.ref)
        out: dict[str, str] = {}
        if r.returncode != 0:
            return out
        for rec in r.stdout.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            f = meta.decode().split()
            if len(f) == 3 and f[1] == "blob":
                out[path.decode("utf-8", "replace")] = f[2]
        return out

    def _is_canon_path(self, path: str) -> bool:
        low = path.lower()
        if low.endswith("/_index.md") or low == "_index.md":
            return False
        parts = path.split("/")
        if any(seg in kc.EXCLUDE_DIRS or seg.startswith(".") for seg in parts[:-1]):
            return False
        if path.startswith("decisioni/") and low.endswith(".md"):
            return True
        prov = kc.travaso_provenance(path)
        if prov is not None:
            return prov[0] != self.persona and low.endswith((".md", ".txt"))
        if not low.endswith(".md"):
            return False
        node, nrel = _node_for(path, self.ctx.nodes)
        first = nrel.split("/")[0]
        return first in node.profile.folders and "/" in nrel

    def _load(self) -> None:
        tree = self._tree()
        wanted = {p: s for p, s in tree.items() if self._is_canon_path(p)}
        reg = {p: s for p, s in tree.items() if p.startswith(REGISTER_DIR + "/") and p.endswith(".yaml")}
        blobs = repo_check._blob_contents(self.ctx.clone, sorted(set(wanted.values()) | set(reg.values())))
        for path, sha in sorted(wanted.items()):
            data = blobs.get(sha)
            if data is None:
                continue
            text = repo_check.decode_text(data)
            if text is None:
                continue
            self.texts[path] = text
            persona, area, data_s = self._provenance(path, text)
            self.meta[path] = {"persona": persona, "area": area, "data": data_s}
            for f in extract_facts(text, path):
                self.n_facts += 1
                for s in f.subjects:
                    self.facts.setdefault((s, f.key), []).append(CanonFact(f.value, f.raw_value, persona, area, path, data_s))
        for path, sha in sorted(reg.items()):
            data = blobs.get(sha)
            if not data:
                continue
            try:
                entry = yaml_mod().safe_load(data.decode("utf-8-sig", "replace"))
            except Exception:  # noqa: BLE001
                continue
            if isinstance(entry, dict) and entry.get("issue"):
                self.register.append(entry)
                for f in entry.get("fatti") or []:
                    if isinstance(f, dict) and f.get("soggetto") and f.get("chiave"):
                        self.reg_index.setdefault((str(f["soggetto"]), str(f["chiave"])), []).append(entry)

    def _provenance(self, path: str, text: str) -> tuple[str | None, str, str]:
        prov = kc.travaso_provenance(path)
        if prov is not None:
            p = prov[0]
            return p, self.ctx.area_of(p), self._date_of(text)
        try:
            fm, _ = kc.read_frontmatter(text)
        except kc.FrontmatterError:
            fm = {}
        pv = fm.get("provenienza")
        if isinstance(pv, dict) and pv.get("persona"):
            p = str(pv["persona"])
            return p, str(pv.get("area") or self.ctx.area_of(p)), kc.fm_str(pv.get("data")) or self._date_of(text, fm)
        src = kc.fm_str(fm.get("source"))
        m = re.search(r"sources/travaso/([a-z0-9-]+)/", src)
        if m:
            return m.group(1), self.ctx.area_of(m.group(1)), self._date_of(text, fm)
        return None, "", self._date_of(text, fm)

    @staticmethod
    def _date_of(text: str, fm: dict | None = None) -> str:
        if fm is None:
            try:
                fm, _ = kc.read_frontmatter(text)
            except kc.FrontmatterError:
                fm = {}
        return kc.fm_str(fm.get("updated")) or kc.fm_str(fm.get("created")) or "?"

    # --- controllo (par. 5.3, 14.6, 14.15)
    def check_text(self, rel: str, text: str, persona: str | None = None, sha256: str = "") -> tuple[list[Incongruenza], list[str], int | None, int]:
        """(incongruenze, annotazioni, escluso per decisione #n, fatti confrontati). `persona` = autore del file (dalla
        provenienza, #11), default la persona del controllo. Il registro vale PER FILE (dest + hash, #6) e per fatto."""
        me = self.persona if persona is None else persona
        facts = extract_facts(text, rel)
        inc: dict[tuple, Incongruenza] = {}
        notes: list[str] = []
        excluded_by: int | None = None
        for e in self.register:                           # #6: esclusione persistente per file (anche senza fatti strutturati)
            if str(e.get("esito")) == "canon" and str(e.get("dest") or "") == rel and sha256 and str(e.get("hash_file") or "") == sha256:
                excluded_by = int(e["issue"])
                notes.append(f"file escluso per decisione #{excluded_by} (vale il canon) finche' il contenuto non cambia")
        for f in facts:
            decided = [e for s2 in f.subjects for e in self.reg_index.get((s2, f.key), [])]
            for s in f.subjects:
                for cf in self.facts.get((s, f.key), []):
                    if cf.value == f.value:
                        continue
                    ratified = None
                    for e in decided:
                        for ef in e.get("fatti") or []:
                            if str(ef.get("soggetto")) in f.subjects and str(ef.get("chiave")) == f.key and \
                                    str(ef.get("nuovo_norm") or "") == f.value and str(ef.get("canon_norm") or "") == cf.value:
                                ratified = e
                    if ratified is not None:
                        n = int(ratified["issue"])
                        if str(ratified.get("esito")) == "canon":
                            excluded_by = n
                            notes.append(f"`{s}` {f.key}: {f.raw_value!r} contraddice la decisione #{n}: vale {cf.raw!r}")
                        else:
                            notes.append(f"`{s}` {f.key}: ratificato dalla decisione #{n}")
                        continue
                    same_person = cf.persona is not None and cf.persona == me
                    contro = None
                    if same_person:
                        for e in decided:
                            for ef in e.get("fatti") or []:
                                if str(ef.get("soggetto")) not in f.subjects or str(ef.get("chiave")) != f.key:
                                    continue
                                es_ = str(e.get("esito"))
                                if es_ in ("nuovo", "entrambi") and str(ef.get("nuovo_norm") or "") == cf.value:
                                    contro = int(e["issue"])
                                if es_ == "canon" and str(ef.get("canon_norm") or "") == cf.value:      # #15: valore canon confermato
                                    contro = int(e["issue"])
                        if contro is None:
                            continue                      # chi ha scritto un fatto puo' aggiornarlo
                    item = Incongruenza(s, f.key, f.value, f.raw_value, cf.value, cf.raw, cf.persona or "canon", cf.area,
                                        cf.nota, cf.data, contro)
                    inc.setdefault((f.key, f.value, cf.value, cf.nota), item)
            # par. 14.15: un fatto MIO gia' ratificato dal registro che ora cambia e' un'incongruenza anche se il mio raw
            # non e' nel canon (il canon ha solo il raw delle altre persone); #15: vale anche per un valore canon confermato
            for e in decided:
                if str(e.get("persona") or "") != me and str(e.get("esito")) != "canon":
                    continue
                for ef in e.get("fatti") or []:
                    if str(ef.get("soggetto")) not in f.subjects or str(ef.get("chiave")) != f.key:
                        continue
                    es_ = str(e.get("esito"))
                    if es_ in ("nuovo", "entrambi") and str(e.get("persona") or "") == me:
                        rat = str(ef.get("nuovo_norm") or "")
                        raw_rat = str(ef.get("nuovo") or rat)
                    elif es_ == "canon" and str(ef.get("canon_persona") or "canon") in (me, "canon") and me:
                        rat = str(ef.get("canon_norm") or "")
                        raw_rat = str(ef.get("canon") or rat)
                    else:
                        continue
                    if rat and rat != f.value:
                        nota = str(e.get("dest") or e.get("path") or f"{REGISTER_DIR}/{e.get('issue')}.yaml")
                        item = Incongruenza(f.subjects[0], f.key, f.value, f.raw_value, rat, raw_rat, me or "canon",
                                            self.ctx.area_of(me) if me else "", nota, str(e.get("data") or "?"), int(e["issue"]))
                        inc.setdefault((f.key, f.value, rat, nota), item)
        return list(inc.values()), notes, excluded_by, len(facts)

    def excerpts(self, rel: str, text: str, limit_bytes: int) -> list[dict]:
        """Estratti del canon pertinenti per il pacchetto di verifica (par. 14.1): stesso soggetto, wikilink citati,
        title e nomi propri cercati nel testo del canon. Mascherati e limitati."""
        facts = extract_facts(text, rel)
        subjects = {s for f in facts for s in f.subjects}
        chosen: dict[str, str] = {}
        for (s, _k), lst in self.facts.items():
            if s in subjects:
                for cf in lst:
                    chosen.setdefault(cf.nota, "soggetto")
        links = set(re.findall(r"\[\[([^\]|#]+)", text))
        for path in self.texts:
            if PurePosixPath(path).stem in links:
                chosen.setdefault(path, "wikilink")
        try:
            fm, body = kc.read_frontmatter(text)
        except kc.FrontmatterError:
            fm, body = {}, text
        terms = {t for t in [kc.fm_str(fm.get("title"))] if len(t) >= 4}
        terms |= {m for m in re.findall(r"\b[A-Z][a-zà-ú]+(?:\s+[A-Z][a-zà-ú]+)+", body)}
        for path, ctext in self.texts.items():
            if path in chosen or len(chosen) >= 12:
                break
            low = ctext.lower()
            if any(t.lower() in low for t in terms):
                chosen[path] = "nome o titolo"
        out: list[dict] = []
        used = 0
        for path, why in sorted(chosen.items(), key=lambda kv: (0 if kv[1] == "soggetto" else 1, kv[0]))[:8]:
            lines = self.texts[path].splitlines()
            keep = []
            for ln in lines:
                if any(t.lower() in ln.lower() for t in terms) or FACT_LINE_RE.match(ln) or ln.startswith("|"):
                    keep.append(ln.strip())
            est = "\n".join(keep[:30]) if keep else "\n".join(lines[:15])
            est = _out(est, 1500)
            if used + len(est) > limit_bytes:
                break
            used += len(est)
            meta = self.meta.get(path, {})
            out.append({"nota": path, "persona": meta.get("persona") or "canon", "area": meta.get("area") or "",
                        "data": meta.get("data") or "?", "perche": why, "estratto": est})
        return out


# ---------------------------------------------------------------------------- strato semantico (par. 14.1): pacchetto e verdetto
def package_dir(from_root: Path, owner: str, repo: str, review_id: str) -> Path:
    return Path(from_root) / kc.TRAVASO_WORKSPACE / f"{owner}-{repo}" / review_id


def package_digest(files: dict, base_sha: str, persona: str, brain: str, owner: str = "", repo: str = "") -> tuple[str, str]:
    """(sha256 intero, review_id = primi 16 esadecimali) del pacchetto: file, base, persona, brain e DESTINAZIONE (N7)."""
    core = json.dumps({"files": files, "base_sha": base_sha, "persona": persona, "brain": brain, "owner": owner, "repo": repo},
                      sort_keys=True, ensure_ascii=False)
    full = sha256_bytes(core.encode("utf-8"))
    return full, full[:16]

def build_package(ctx: Ctx, src: Source, canon: Canon, items: dict[str, SourceFile], checks: dict[str, tuple]) -> tuple[str, dict, str]:
    """(review_id, verifica.json, verifica.md): per ogni file cambiato testo nuovo (mascherato, <= 8 KB), fatti, incongruenze
    deterministiche ed estratti del canon; <= 200 KB totali; review_id = sha256 del pacchetto (primi 16 esadecimali)."""
    files: dict[str, dict] = {}
    total = 0
    for rel in sorted(items):
        sf = items[rel]
        inc, notes, _excl, n = checks.get(rel, ([], [], None, 0))
        text = sf.text if sf.text is not None else "(binario: nessun testo)"
        text = mask(text)
        if len(text) > PACKAGE_FILE_MAX:
            text = text[:PACKAGE_FILE_MAX] + "\n[... troncato a 8 KB ...]"
        facts = [{"soggetto": f.subjects[0], "chiave": f.key, "valore": mask(f.raw_value), "norm": f.value}
                 for f in extract_facts(sf.text or "", rel)][:60]
        entry = {"hash": sf.sha256, "size": sf.size, "testo": text, "fatti": facts,
                 "incongruenze_deterministiche": [i.as_dict() for i in inc], "note": notes,
                 "canon": canon.excerpts(rel, sf.text or "", max(2000, PACKAGE_FILE_MAX - len(text)))}
        size = len(json.dumps(entry, ensure_ascii=False))
        if total + size > PACKAGE_TOTAL_MAX:
            entry = {"hash": sf.sha256, "size": sf.size, "testo": "(omesso: pacchetto oltre 200 KB; verifica aprendo il file "
                     "nel brain personale)", "fatti": facts[:20], "incongruenze_deterministiche": [i.as_dict() for i in inc],
                     "note": notes, "canon": []}
            size = len(json.dumps(entry, ensure_ascii=False))
        total += size
        files[rel] = entry
    full_sha, review_id = package_digest(files, ctx.base_sha, ctx.persona, src.brain_id, ctx.owner, ctx.repo)
    pkg = {"review_id": review_id, "sha256": full_sha, "versione": TRAVASO_VERSION, "quando": now_iso(), "owner": ctx.owner,
           "repo": ctx.repo, "persona": ctx.persona, "brain": src.brain_id, "base_sha": ctx.base_sha, "policy": ctx.policy(),
           "files": files,
           "istruzioni": ("Leggi SOLO questo pacchetto (mai il clone aziendale). Per ogni file scrivi in verdetto.json "
                          "{\"review_id\": ..., \"files\": {\"<path>\": {\"esito\": \"coerente\"} | {\"esito\": \"incongruente\", "
                          "\"soggetto\", \"chiave\", \"nuovo\", \"canon\", \"fonte_canon\", \"motivo\"} | {\"esito\": "
                          "\"non-verificabile\", \"motivo\"}}}. Il verdetto puo' solo AGGIUNGERE fermi.")}
    md = [f"# Verifica semantica del travaso -- {ctx.persona} -> {ctx.full} (review_id `{review_id}`)", "",
          f"Base `origin/main` {ctx.base_sha[:7]}, {len(files)} file cambiati, policy `{ctx.policy()}`. Leggi solo questo file: "
          "mai il clone aziendale. Scrivi `verdetto.json` accanto (schema in verifica.json: `istruzioni`), poi:",
          f"    brain_sync.py --travaso send --verdetto {review_id}", ""]
    for rel, e in files.items():
        md += [f"## `{rel}`  (sha256 {e['hash'][:12]})", ""]
        if e["incongruenze_deterministiche"]:
            md.append("Incongruenze deterministiche gia' trovate (il file e' comunque fermo per queste):")
            md += [f"- `{i['soggetto']}` {i['chiave']}: {i['nuovo']!r} vs {i['canon']!r} ({i['canon_persona']}, {i['canon_nota']}, {i['canon_data']})"
                   for i in e["incongruenze_deterministiche"]]
            md.append("")
        if e["fatti"]:
            md.append("Fatti estratti: " + "; ".join(f"{f['chiave']}={f['valore']}" for f in e["fatti"][:15]))
            md.append("")
        md += ["### Testo nuovo", "", "```", e["testo"], "```", ""]
        if e["canon"]:
            md.append("### Canon pertinente")
            for c in e["canon"]:
                md += ["", f"- `{c['nota']}` ({c['persona']}, {c['data']}; motivo: {c['perche']})", "", "```", c["estratto"], "```"]
            md.append("")
    return review_id, pkg, "\n".join(md) + "\n"


def write_package(from_root: Path, ctx: Ctx, review_id: str, pkg: dict, md: str) -> Path:
    d = package_dir(from_root, ctx.owner, ctx.repo, review_id)
    for f in (d / "verifica.json", d / "verifica.md"):
        _check_link_inside("workspace/travaso", from_root, f, EXIT_CONFIG)       # catena completa fino al file (#5)
    kc.write_text(d / "verifica.json", mask(json.dumps(pkg, ensure_ascii=False, indent=1)) + "\n")
    kc.write_text(d / "verifica.md", mask(md))
    return d

def load_verdict(from_root: Path, ctx: Ctx, review_id: str, brain: str = "") -> tuple[dict, dict, str]:
    """(verifica.json, verdetto.json, problema). `problema` vuoto = verdetto utilizzabile; altrimenti il motivo per cui NESSUN
    file e' verificato: digest diverso, identita' diversa (persona, brain, destinazione: N7), base cambiata (#1).
    Prima di leggere: nessun link lungo la catena fino ai file (#5)."""
    d = package_dir(from_root, ctx.owner, ctx.repo, review_id)
    vj, vd = d / "verifica.json", d / "verdetto.json"
    _check_link_inside("workspace/travaso", from_root, vj, EXIT_CONFIG)
    _check_link_inside("workspace/travaso", from_root, vd, EXIT_CONFIG)
    if not vj.is_file():
        raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: pacchetto {vj} assente (rilancia send senza --verdetto)")
    if not vd.is_file():
        raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: manca {vd}: l'agente deve scriverlo (`<id>-travaso verifica`)")
    try:
        pkg = json.loads(vj.read_text(encoding="utf-8-sig"))
        ver = json.loads(vd.read_text(encoding="utf-8-sig"))
    except ValueError as e:
        raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: JSON non valido ({e})") from e
    if str(pkg.get("review_id")) != review_id or str(ver.get("review_id")) != review_id:
        raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: review_id diverso nel pacchetto o nel verdetto: nessun file verificato")
    files = ver.get("files")
    if not isinstance(files, dict):
        raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: verdetto.json senza la mappa `files`")
    for rel, v in files.items():
        if not isinstance(v, dict) or str(v.get("esito")) not in ("coerente", "incongruente", "non-verificabile"):
            raise Stop(EXIT_CONFIG, f"--verdetto {review_id}: esito non valido per `{rel}` (coerente | incongruente | non-verificabile)")
    full, rid = package_digest(pkg.get("files") or {}, str(pkg.get("base_sha") or ""), str(pkg.get("persona") or ""),
                               str(pkg.get("brain") or ""), str(pkg.get("owner") or ""), str(pkg.get("repo") or ""))
    if rid != review_id or str(pkg.get("sha256") or "") != full:
        return pkg, ver, "digest del pacchetto diverso da quello ricostruito (pacchetto manomesso o incompleto)"
    ident = (str(pkg.get("persona") or ""), str(pkg.get("brain") or ""), str(pkg.get("owner") or "").lower(), str(pkg.get("repo") or "").lower())
    if ident != (ctx.persona, brain, ctx.owner.lower(), ctx.repo.lower()):
        return pkg, ver, (f"identita' del pacchetto diversa dalla corsa (pacchetto: {ident[0]}/{ident[1]} -> {ident[2]}/{ident[3]}; "
                          f"corsa: {ctx.persona}/{brain} -> {ctx.full})")
    if str(pkg.get("base_sha") or "") != ctx.base_sha:
        return pkg, ver, f"base cambiata (pacchetto su origin/main {str(pkg.get('base_sha'))[:7]}, ora {ctx.base_sha[:7]})"
    return pkg, ver, ""

# ---------------------------------------------------------------------------- transazione e worktree (par. 6.1, 14.5)
class Tx:
    """Worktree usa-e-getta sotto `<git dir>/travaso/<ts>/`, registrato in `<ts>.json`: si rimuove SOLO quello registrato
    (in `finally`), piu' quelli di transazioni stantie (> 2 h)."""

    def __init__(self, ctx: Ctx):
        self.ctx = ctx
        self.base = ctx.git_dir / "travaso"
        self.ts = dt.datetime.now().strftime("%Y%m%d-%H%M%S-") + f"{os.getpid()}"
        self.json = self.base / f"{self.ts}.json"
        self.worktree: Path | None = None
        self.locks: dict[str, str] = {}                   # ref -> sha del PROPRIO blob

    def _cleanup_stale(self) -> None:
        if not self.base.is_dir():
            return
        for j in self.base.glob("*.json"):
            try:
                meta = json.loads(j.read_text(encoding="utf-8"))
                if time.time() - float(meta.get("ts", 0)) < TX_STALE_SEC:
                    continue
                wt = Path(meta.get("worktree", ""))
                if wt.exists() and wt.parent == self.base and not kc.is_link(wt):
                    git(self.ctx.clone, "worktree", "remove", "--force", str(wt))
                    shutil.rmtree(wt, ignore_errors=True)
                j.unlink(missing_ok=True)
            except (OSError, ValueError):
                continue
        git(self.ctx.clone, "worktree", "prune")

    def open(self, base_ref: str) -> Path:
        if self.ctx.dry:
            raise Stop(EXIT_STOP, "dry-run: nessun worktree (bug: percorso di mutazione raggiunto in dry)")
        _check_link_inside("la cartella .git del clone", self.ctx.git_dir, self.base, EXIT_DEST)   # PRIMA del cleanup (par. 14.5)
        self.base.mkdir(parents=True, exist_ok=True)
        _check_link_base("la cartella delle transazioni", self.base, EXIT_DEST)
        self._cleanup_stale()
        wt = self.base / self.ts
        if wt.exists():
            raise Stop(EXIT_STOP, f"cartella del worktree gia' presente: {wt}")
        self.json.write_text(json.dumps({"ts": time.time(), "worktree": str(wt), "pid": os.getpid(), "base": base_ref}), encoding="utf-8")
        r = git(self.ctx.clone, "worktree", "add", "--detach", "-q", str(wt), base_ref)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"git worktree add fallito: {git_err(r)}")
        _check_link_inside("il worktree", self.ctx.git_dir, wt, EXIT_DEST)
        self.worktree = wt
        fault("eccezione-nel-worktree")
        return wt

    def checkout(self, ref: str) -> None:
        assert self.worktree is not None
        r = git(self.worktree, "checkout", "-q", "--detach", ref)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"checkout di {ref} nel worktree fallito: {git_err(r)}")
        git(self.worktree, "clean", "-fdq")

    def close(self) -> None:
        if self.worktree is not None:
            r = git(self.ctx.clone, "worktree", "remove", "--force", str(self.worktree))
            if r.returncode != 0 and self.worktree.exists():
                shutil.rmtree(self.worktree, ignore_errors=True)
                git(self.ctx.clone, "worktree", "prune")
            if self.worktree.exists():
                print(mask(f"ATTENZIONE: worktree non rimovibile: {self.worktree} (rimuovilo a mano: git worktree remove --force)"))
            self.worktree = None
        self.json.unlink(missing_ok=True)
        for ref in list(self.locks):
            self.release_lock(ref)

    def acquire_lock(self, issue: int, payload: dict) -> bool:
        """Lock atomico `refs/travaso-lock/<issue>` -> blob (par. 14.8, fatto 40). Occupato e fresco = si salta; occupato e
        STANTIO = stop esplicito (nessun takeover automatico: lo sblocca una persona con `decisioni --sblocca <n>`, #8)."""
        ref = LOCK_REF.format(issue=issue)
        ctx = self.ctx
        if ctx.dry:
            return True
        fault("prima-del-lock", str(issue))
        blob = ctx.gh_api_write("POST", f"repos/{ctx.full}/git/blobs", {"content": json.dumps(payload), "encoding": "utf-8"})
        mine = str(blob.get("sha", ""))
        if self._post_ref(ref, mine):
            self.locks[ref] = mine
            return True
        cur_sha, data = self._read_lock(ref)
        if not cur_sha:
            if self._post_ref(ref, mine):
                self.locks[ref] = mine
                return True
            return False
        age = time.time() - float(data.get("ts", time.time()))
        if age <= LOCK_STALE_SEC:
            return False
        ts = dt.datetime.fromtimestamp(float(data.get("ts", 0))).strftime("%Y-%m-%d %H:%M:%S") if data.get("ts") else "?"
        raise Stop(EXIT_STOP, f"lock stantio su issue #{issue} (runner `{data.get('runner', '?')}`, ts {ts}, {int(age // 60)} min): "
                              f"se il processo e' morto, `decisioni --sblocca {issue}`")

    def sblocca(self, issue: int) -> str:
        """`--sblocca <n>`: cancellazione ESPLICITA del lock dopo averlo riletto; commento sulla issue (#8)."""
        ref = LOCK_REF.format(issue=issue)
        ctx = self.ctx
        cur_sha, data = self._read_lock(ref)
        if not cur_sha:
            return f"#{issue}: nessun lock da sbloccare"
        if ctx.dry:
            return f"[dry-run-git] #{issue}: lock di `{data.get('runner', '?')}` NON rimosso"
        ctx.gh_api_write("DELETE", f"repos/{ctx.full}/git/refs/{ref[5:]}")
        again, _d = self._read_lock(ref)
        if again:
            raise Stop(EXIT_DEST, f"--sblocca {issue}: il lock e' ancora presente dopo la cancellazione (ricreato da un'altra corsa?)")
        issue_comment(ctx, issue, f"travaso-stato: lock sbloccato a mano da @{ctx.login} (era di `{data.get('runner', '?')}`, "
                                  f"ts {data.get('ts', '?')}): l'applicazione riparte da questa corsa.")
        return f"#{issue}: lock di `{data.get('runner', '?')}` sbloccato da @{ctx.login}"

    def _post_ref(self, ref: str, sha: str) -> bool:
        r = self.ctx.gh("api", "-X", "POST", f"repos/{self.ctx.full}/git/refs", "--input", "-", write=True,
                        input_text=json.dumps({"ref": ref, "sha": sha}))
        if r is None:
            raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente")
        if r.returncode == 0:
            return True
        err = (r.stderr or "") + (r.stdout or "")
        if "already exists" in err.lower():
            return False
        raise Stop(EXIT_DEST, f"GitHub rifiuta il lock {ref}: {_out(err.strip(), 160)}")

    def _read_lock(self, ref: str) -> tuple[str, dict]:
        cur = self.ctx.gh_json("api", f"repos/{self.ctx.full}/git/ref/{ref[5:]}")
        sha = str((cur or {}).get("object", {}).get("sha", ""))
        meta = self.ctx.gh_json("api", f"repos/{self.ctx.full}/git/blobs/{sha}") if sha else None
        try:
            data = json.loads(base64.b64decode((meta or {}).get("content", "")).decode("utf-8")) if meta else {}
        except (ValueError, UnicodeDecodeError):
            data = {}
        return sha, data if isinstance(data, dict) else {}

    def release_lock(self, ref: str) -> None:
        """Rilascio SOLO del proprio lock: rilettura, poi DELETE (la finestra fra rilettura e DELETE non ha CAS su GitHub:
        dichiarata nel README). DELETE in errore = exit 9 (#24)."""
        mine = self.locks.pop(ref, None)
        if self.ctx.dry or mine is None:
            return
        cur, _d = self._read_lock(ref)
        if cur == mine:
            r = self.ctx.gh("api", "-X", "DELETE", f"repos/{self.ctx.full}/git/refs/{ref[5:]}", write=True)
            if r is None or r.returncode != 0:
                raise Stop(EXIT_DEST, f"rilascio del lock {ref} fallito: {_out((r.stderr if r else '') or 'gh assente', 160)} "
                                      "(se resta, una persona lo toglie con `decisioni --sblocca`)")

# ---------------------------------------------------------------------------- branch, PR, status, issue (par. 6, 14.7, 14.9, 14.10)
PR_FIELDS = "number,state,url,headRefOid,headRefName,labels,autoMergeRequest,title,body"
CLOSED_MARK = "<!-- travaso-chiusa:"      # nel corpo di una PR chiusa DAL TRAVASO (diff vuoto): non e' un "no" di una persona


def pr_for_branch(ctx: Ctx, branch: str) -> dict | None:
    """PR piu' recente del branch (OPEN, MERGED o CLOSED); None se non ce n'e'. gh in errore = stop (G11)."""
    r = ctx.gh("pr", "list", "--repo", ctx.full, "--head", branch, "--state", "all", "--limit", "5", "--json", PR_FIELDS)
    if r is None:
        raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente o senza risposta")
    if r.returncode != 0:
        raise Stop(EXIT_DEST, f"`gh pr list --head {branch}` in errore: mi fermo senza toccare nulla ({_out(r.stderr.strip(), 160)})")
    try:
        lst = json.loads(r.stdout or "[]")
    except ValueError:
        raise Stop(EXIT_DEST, f"`gh pr list --head {branch}`: risposta illeggibile")
    if not lst:
        return None
    lst.sort(key=lambda x: -int(x.get("number") or 0))
    return lst[0]

def prepare_branch(ctx: Ctx, tx: Tx, branch: str, stop_if_closed: bool) -> tuple[str, dict | None, bool]:
    """(base ref del worktree, PR aperta o None, 'merged_from_main'). Branch con PR OPEN -> si riusa (commit in coda, merge
    da origin/main se indietro: conflitto = exit 7); MERGED/assente -> origin/main; CLOSED senza merge -> exit 7 (auto).
    Nessun secondo fetch (par. 14.9): una head diversa da quella conosciuta = stop."""
    pr = pr_for_branch(ctx, branch)
    remote = f"refs/remotes/origin/{branch}"
    state = str((pr or {}).get("state") or "").upper()
    if pr and state == "CLOSED":
        if stop_if_closed and CLOSED_MARK not in str(pr.get("body") or ""):
            # chiusa da una persona = "no" (par. 14.10); chiusa dal travaso perche' il diff era vuoto = si riparte da main
            raise Stop(EXIT_STOP, f"la PR del branch {branch} e' CHIUSA senza merge ({pr.get('url', '')}): nessun travaso. "
                                  f"Riaprila oppure cancella il branch remoto (git push origin --delete {branch}) e rilancia")
        pr = None
    if pr and state == "OPEN" and ctx.run.has_ref(remote):
        known = git_out(ctx.clone, "rev-parse", remote)
        oid = str(pr.get("headRefOid") or "")
        if oid and oid != known:
            raise Stop(EXIT_STOP, f"la PR {pr.get('url', '')} ha head {oid[:7]} ma origin/{branch} e' {known[:7]}: si e' mossa "
                                  "durante la corsa, rilancia")
        if tx.worktree is None:
            tx.open(remote)
        else:
            tx.checkout(remote)
        merged = False
        if not git_ok(tx.worktree, "merge-base", "--is-ancestor", "refs/remotes/origin/main", "HEAD"):
            m = git(tx.worktree, "merge", "--no-edit", "-q", "refs/remotes/origin/main")
            if m.returncode != 0:
                git(tx.worktree, "merge", "--abort")
                raise Stop(EXIT_STOP, f"merge di origin/main nel branch {branch} con conflitti: risolvi a mano nella PR "
                                      f"{pr.get('url', '')} (exit {EXIT_STOP})")
            merged = True
        return remote, pr, merged
    if tx.worktree is None:
        tx.open("refs/remotes/origin/main")
    else:
        tx.checkout("refs/remotes/origin/main")
    return "refs/remotes/origin/main", (pr if state == "OPEN" else None), False

def restore_from_main(wt: Path, prefix: str) -> None:
    """Il prefisso nel worktree torna IDENTICO a origin/main (--no-overlay: i file in piu' spariscono)."""
    in_main = git_ok(wt, "cat-file", "-e", f"refs/remotes/origin/main:{prefix.rstrip('/')}")
    if in_main:
        r = git(wt, "restore", "--source=refs/remotes/origin/main", "--staged", "--worktree", "--no-overlay", "--", prefix)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"git restore di {prefix} fallito: {git_err(r)}")
    else:
        git(wt, "rm", "-r", "-q", "--cached", "--ignore-unmatch", "--", prefix)
        shutil.rmtree(wt / prefix, ignore_errors=True)


def write_files(wt: Path, files: dict[str, bytes], delete: set[str]) -> None:
    for rel in sorted(delete):
        p = wt / rel
        if p.exists():
            p.unlink()
    for rel, data in files.items():
        p = wt / rel
        _check_link_inside("il worktree", wt, p, EXIT_DEST)        # ogni componente fino al file (par. 14.5)
        p.parent.mkdir(parents=True, exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)

def stage_and_verify(wt: Path, paths: list[str], expected: dict[str, str]) -> bool:
    """`git add -A` dei path; i blob in staging devono avere ESATTAMENTE gli hash dello snapshot (par. 14.18).
    Ritorna True se lo staging differisce da HEAD."""
    for p in paths:
        if p != "." and not (wt / p).exists() and not git_out(wt, "ls-files", "--", p):
            continue                                      # prefisso assente sia nel worktree sia nell'indice
        r = git(wt, "add", "-A", "--", p)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"git add {p} fallito: {git_err(r)}")
    if expected:
        r = git(wt, "ls-files", "-s", "-z", "--", *sorted(expected))
        staged: dict[str, str] = {}
        for rec in r.stdout.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            f = meta.decode().split()
            if len(f) >= 2:
                staged[path.decode("utf-8", "replace")] = f[1]
        blobs = repo_check._blob_contents(wt, sorted(set(staged.values())))
        for path, h in expected.items():
            sha = staged.get(path)
            if sha is None or sha256_bytes(blobs.get(sha, b"")) != h:
                raise Stop(EXIT_STOP, f"blob in staging di `{path}` diverso dallo snapshot letto: corsa interrotta, niente push")
    return git(wt, "diff", "--cached", "--quiet").returncode != 0


def commit_in(wt: Path, message: str, dry: bool, ctx: "Ctx | None" = None) -> str:
    if dry:
        print(f"[dry-run-git] git commit -m {message.splitlines()[0]!r}")
        return git_out(wt, "rev-parse", "HEAD")
    if ctx is not None:
        assert_base(ctx)
    r = git(wt, "commit", "-q", "-m", mask(message))
    if r.returncode != 0:
        raise Stop(EXIT_STOP, f"commit nel worktree fallito: {git_err(r)}")
    return git_out(wt, "rev-parse", "HEAD")

def outgoing_or_refuse(ctx: Ctx, wt: Path) -> tuple[int, str]:
    stats: dict = {}
    try:
        commits, probs = repo_check.outgoing_problems(wt, "HEAD", repo_check.memory_prefixes(ctx.clone), stats=stats)
    except repo_check.RepoCheckError as e:
        raise Stop(EXIT_REFUSED, f"controllo dei commit in uscita non eseguibile ({e}): nessun push") from e
    if probs:
        lines = "\n".join(mask(p.line()) for p in probs[:10])
        raise Stop(EXIT_REFUSED, f"RIFIUTATO: {len(probs)} problemi nei commit in uscita (commit, path, tipo), nessun push:\n{lines}")
    return len(commits), repo_check.scan_note(stats)


def push_branch(ctx: Ctx, wt: Path, branch: str) -> None:
    """Prima del push: base ancora quella fissata; ref locale di sicurezza `refs/travaso-local/<persona>/<ts>` (errore =
    stop, #10). Poi push all'URL canonico; il branch locale sopravvive al worktree."""
    assert_base(ctx)
    head = git_out(wt, "rev-parse", "HEAD")
    if not ctx.dry:
        safe = f"refs/travaso-local/{ctx.persona or 'clone'}/{dt.datetime.now().strftime('%Y%m%d-%H%M%S')}-{head[:7]}"
        r = git(ctx.clone, "update-ref", safe, head)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"ref locale di sicurezza non scrivibile ({safe}): {git_err(r)}; nessun push")
    run = bs.Runner(wt, ctx.dry)
    if QUIET:
        import contextlib
        import io
        with contextlib.redirect_stdout(io.StringIO()):
            p = bs.push_canonical(run, ctx.owner, ctx.repo, branch)
    else:
        p = bs.push_canonical(run, ctx.owner, ctx.repo, branch)
    if p.returncode != 0:
        raise Stop(EXIT_STOP, f"push di {branch} fallito: {_out(p.stderr.strip(), 200)} (copia locale in refs/travaso-local/)")
    if not ctx.dry:
        r = git(ctx.clone, "branch", "-f", branch, head)
        if r.returncode != 0:
            raise Stop(EXIT_STOP, f"branch locale {branch} non aggiornato: {git_err(r)}")

def pr_create(ctx: Ctx, branch: str, title: str, body: str, labels: list[str]) -> dict:
    args = ["pr", "create", "--repo", ctx.full, "--base", "main", "--head", branch, "--title", mask(title), "--body-file", "-"]
    for lb in labels:
        args += ["--label", lb]
    r = ctx.gh(*args, write=True, input_text=mask(body))
    if r is None:
        raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente")
    if r.returncode != 0 and labels and "label" in (r.stderr or "").lower():
        say(f"AVVISO: label {labels} non create sul repo (github_org.py apply): PR senza label")
        r = ctx.gh(*[a for a in args if a not in labels and a != "--label"], write=True, input_text=mask(body))
    if r is None or r.returncode != 0:
        raise Stop(EXIT_DEST, f"creazione della PR per {branch} fallita: {_out((r.stderr if r else '') or 'gh assente', 200)}")
    url = (r.stdout.strip().splitlines() or [""])[-1] if not ctx.dry else f"https://github.com/{ctx.full}/pull/0"
    m = re.search(r"/pull/(\d+)", url)
    return {"number": int(m.group(1)) if m else 0, "url": url, "state": "OPEN", "body": body}

def _gh_write(ctx: Ctx, what: str, *args: str, input_text: str | None = None) -> subprocess.CompletedProcess:
    """Scrittura gh che DEVE riuscire (par. 14.24): errore = exit 9 con il motivo, mai silenzio."""
    r = ctx.gh(*args, write=True, input_text=input_text)
    if r is None:
        raise Stop(EXIT_DEFERRED, f"travaso rinviato: gh assente ({what})")
    if r.returncode != 0:
        raise Stop(EXIT_DEST, f"{what} fallito: {_out((r.stderr or r.stdout or '').strip(), 200)}")
    return r


def pr_edit_body(ctx: Ctx, number: int, body: str) -> None:
    """SOLO REST (fatto live, gh 2.70.0: `gh pr edit` fallisce sempre per il campo deprecato projectCards)."""
    if ctx.dry:
        print(f"[dry-run-git] corpo della PR #{number} aggiornato")
        return
    ctx.gh_api_write("PATCH", f"repos/{ctx.full}/pulls/{number}", {"body": mask(body)})


def pr_close(ctx: Ctx, number: int, comment: str) -> None:
    """Commento, chiusura e cancellazione del branch: SOLO REST (mai `gh pr close`)."""
    if ctx.dry:
        print(f"[dry-run-git] PR #{number} chiusa: {_out(comment, 80)}")
        return
    view = ctx.gh_json("pr", "view", str(number), "--repo", ctx.full, "--json", "headRefName,state,body")
    body = str((view or {}).get("body") or "").rstrip("\n")
    ctx.gh_api_write("POST", f"repos/{ctx.full}/issues/{number}/comments", {"body": mask(comment)})
    ctx.gh_api_write("PATCH", f"repos/{ctx.full}/pulls/{number}",
                     {"state": "closed", "body": f"{body}\n\n{CLOSED_MARK} {_out(comment, 120)} -->\n"})
    branch = str((view or {}).get("headRefName") or "")
    if branch:
        r = ctx.gh("api", "-X", "DELETE", f"repos/{ctx.full}/git/refs/heads/{branch}", write=True)
        if r is None:
            raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente")
        err = ((r.stderr or "") + (r.stdout or "")).lower()
        if r.returncode != 0 and "does not exist" not in err and "404" not in err:
            raise Stop(EXIT_DEST, f"cancellazione del branch {branch} dopo la chiusura della PR #{number} fallita: {_out(err.strip(), 160)}")

def post_status(ctx: Ctx, sha: str, state: str, description: str) -> None:
    desc = _out(description, STATUS_MAX)
    if ctx.dry:
        print(f"[dry-run-git] status {STATUS_CONTEXT}={state} su {sha[:7]}: {desc}")
        return
    assert_base(ctx)
    ctx.gh_api_write("POST", f"repos/{ctx.full}/statuses/{sha}",
                     {"state": state, "context": STATUS_CONTEXT, "description": desc})

def enable_automerge(ctx: Ctx, pr: dict) -> dict:
    """`gh pr merge --auto --squash --delete-branch` (se non gia' attivo); poi rilegge la PR: se GitHub ha fuso subito
    (requisiti gia' soddisfatti) ritorna la PR con state MERGED (#26)."""
    if not pr.get("autoMergeRequest"):
        _gh_write(ctx, f"auto-merge della PR #{pr['number']}", "pr", "merge", "--auto", "--squash", "--delete-branch", "--repo", ctx.full, str(pr["number"]))
    view = ctx.gh_json("pr", "view", str(pr["number"]), "--repo", ctx.full, "--json", "state,headRefOid,url,number")
    if isinstance(view, dict) and view.get("state"):
        pr = {**pr, **view}
    return pr

def ensure_labels(ctx: Ctx, names: list[str]) -> None:
    have = ctx.gh_json("api", f"repos/{ctx.full}/labels?per_page=100")
    known = {x.get("name", "").lower() for x in have} if isinstance(have, list) else set()
    for n in names:
        if n.lower() not in known:
            r = ctx.gh("api", "-X", "POST", f"repos/{ctx.full}/labels", "--input", "-", write=True,
                       input_text=json.dumps({"name": n, "color": "ededed"}))
            if r is None or r.returncode != 0:          # #24: mai in silenzio
                raise Stop(EXIT_DEST, f"creazione della label `{n}` fallita: {_out((r.stderr if r else '') or 'gh assente', 160)} "
                                      "(le label le crea `github_org.py apply`; serve il permesso triage/push)")
            known.add(n.lower())

def issue_comment(ctx: Ctx, number: int, body: str) -> None:
    if ctx.dry:
        print(f"[dry-run-git] commento sulla issue #{number}: {_out(body, 80)}")
        return
    ctx.gh_api_write("POST", f"repos/{ctx.full}/issues/{number}/comments", {"body": mask(body)})


def issue_edit_body(ctx: Ctx, number: int, body: str) -> None:
    """SOLO REST (mai `gh issue edit`)."""
    if ctx.dry:
        return
    ctx.gh_api_write("PATCH", f"repos/{ctx.full}/issues/{number}", {"body": mask(body)})


def issue_close(ctx: Ctx, number: int) -> None:
    """SOLO REST (mai `gh issue close`)."""
    if ctx.dry:
        print(f"[dry-run-git] issue #{number} chiusa")
        return
    ctx.gh_api_write("PATCH", f"repos/{ctx.full}/issues/{number}", {"state": "closed"})


def issue_labels(ctx: Ctx, number: int, add: list[str] = (), remove: list[str] = ()) -> None:
    """Label via REST: POST per aggiungere, DELETE per togliere (label assente sulla issue = 404, ignorato)."""
    if ctx.dry:
        return
    if add:
        ctx.gh_api_write("POST", f"repos/{ctx.full}/issues/{number}/labels", {"labels": list(add)})
    for lb in remove:
        r = ctx.gh("api", "-X", "DELETE", f"repos/{ctx.full}/issues/{number}/labels/{quote(lb, safe='')}", write=True)
        if r is None:
            raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente")
        err = ((r.stderr or "") + (r.stdout or "")).lower()
        if r.returncode != 0 and "404" not in err and "does not exist" not in err and "not found" not in err:
            raise Stop(EXIT_DEST, f"rimozione della label `{lb}` dalla issue #{number} fallita: {_out(err.strip(), 160)}")

MACHINE_RE = re.compile(r"<!--\s*travaso:\s*(\{.*?\})\s*-->", re.S)
VERSION_RE = re.compile(r"<!--\s*travaso-versione:\s*(\d+)\s*-->")


def machine_of(issue: dict) -> dict | None:
    """Dati macchina = ULTIMO commento `<!-- travaso: {...} -->` (par. 14.7); ripiego sul corpo."""
    for c in reversed(issue.get("comments") or []):
        m = MACHINE_RE.search(c.get("body") or "")
        if m:
            try:
                return json.loads(m.group(1))
            except ValueError:
                continue
    m = MACHINE_RE.search(issue.get("body") or "")
    if m:
        try:
            return json.loads(m.group(1))
        except ValueError:
            return None
    return None


def list_issues(ctx: Ctx, labels: list[str], state: str = "open") -> list[dict]:
    """Elenco issue; un errore di `gh issue list` e' exit 9, MAI una lista vuota (par. 14.24)."""
    args = ["issue", "list", "--repo", ctx.full, "--state", state, "--limit", "200",
            "--json", "number,title,body,state,labels,assignees,comments,url,author"]
    for lb in labels:
        args += ["--label", lb]
    r = ctx.gh(*args)
    if r is None:
        raise Stop(EXIT_DEFERRED, "travaso rinviato: gh assente (issue list)")
    if r.returncode != 0:
        raise Stop(EXIT_DEST, f"`gh issue list` in errore: {_out(r.stderr.strip(), 160)} (controlla gh auth status e i permessi)")
    try:
        data = json.loads(r.stdout or "[]")
    except ValueError:
        raise Stop(EXIT_DEST, "`gh issue list`: risposta illeggibile")
    return data if isinstance(data, list) else []

@dataclass
class Fermo:
    """Un file fermo: destinazione nel repo aziendale, contenuto, incongruenze e dati per la issue."""
    dest: str                  # path nel repo aziendale (mirror o canon)
    src_rel: str               # path nel brain personale (= dest per check --staged/--pr)
    data: bytes
    sha256: str
    incongruenze: list[Incongruenza]
    kind: str = "travaso"      # travaso | pr
    head_sha: str = ""         # kind pr: head della PR
    pr_number: int = 0
    motivo: str = ""           # fermo manuale o verdetto
    issue: int = 0
    areas: list[str] = field(default_factory=list)
    assignee: str = ""


def _areas_for(ctx: Ctx, f: Fermo) -> tuple[list[str], str, str]:
    """Aree contraddette (prima = quella del canon della prima incongruenza), responsabile della prima, login."""
    areas: list[str] = []
    for i in f.incongruenze:
        a = i.canon_area or (ctx.area_of(i.canon_persona) if i.canon_persona != "canon" else "")
        if not a:
            a = ctx.responsabile("")[2]
        if a and a not in areas:
            areas.append(a)
    if not areas:
        own = ctx.area_of(ctx.persona) if ctx.persona else ""        # fermo manuale o verifica: l'area di chi manda
        areas = [own or ctx.responsabile("")[2]]
    p, login, area = ctx.responsabile(areas[0])
    return [a for a in areas if a], p, login


def issue_title(ctx: Ctx, f: Fermo) -> str:
    if f.incongruenze:
        i = f.incongruenze[0]
        extra = f" (+{len(f.incongruenze) - 1})" if len(f.incongruenze) > 1 else ""
        return f"Da decidere: {i.soggetto.split('/', 1)[-1]} — {i.chiave}{extra}"
    return f"Da decidere: {PurePosixPath(f.src_rel).stem} — {_out(f.motivo, 50) or 'verifica manuale'}"   # maschera POI tronca (#13)

def issue_body(ctx: Ctx, f: Fermo, versione: int, persona: str, brain: str, pr_url: str) -> tuple[str, dict]:
    areas, resp_p, resp_login = _areas_for(ctx, f)
    rows = []
    for n, i in enumerate(f.incongruenze, 1):
        rows.append(f"| {n} | {i.chiave}: {i.nuovo_raw} | {persona}, `{f.src_rel}` | {i.canon_raw} | "
                    f"{i.canon_persona}, `{i.canon_nota}`, {i.canon_data}{' (contro decisione #%d)' % i.contro_decisione if i.contro_decisione else ''}"
                    f"{' [' + i.fonte + ']' if i.fonte != 'fatti' else ''} |")
    who = [f"@{resp_login}" if resp_login else "(responsabile non trovato)"]
    teams = [ctx.team_of(a) for a in areas if ctx.team_of(a)]
    others = []
    for a in areas[1:]:
        _p, lg, _a = ctx.responsabile(a)
        if lg and f"@{lg}" not in who:
            others.append(f"@{lg} ({a})")
    lines = [f"Travaso di **{persona}** (brain `{brain}`), file `{f.dest}`" + (f" — PR {pr_url}" if pr_url else "") + ".", ""]
    if f.motivo:
        lines += [f"Motivo: {f.motivo}", ""]
    if rows:
        lines += ["| # | " + persona + " dice | nota | aveva scritto | chi, nota, data |", "|---|---|---|---|---|", *rows, ""]
    lines += ["Decidi con UNA casella (o un commento `vale: nuovo|canon|entrambi v%d`):" % versione,
              "- [ ] vale il nuovo (A)", "- [ ] vale il canon (B)", "- [ ] valgono entrambi (contesti diversi)", "",
              "Facoltativo, per \"entrambi\": `contesto nuovo: ...` e `contesto canon: ...` su due righe.", "",
              f"Puo' decidere: {', '.join(who)} (responsabile dell'area {areas[0] if areas else '?'}), i team "
              f"{', '.join('`' + t + '`' for t in dict.fromkeys(teams + ['direzione']))}." + (" Altre aree: " + ", ".join(others) + "." if others else ""),
              f"In copia: @{ctx.login}. Versione {versione} (se il file cambia, le caselle si azzerano).",
              f"<!-- travaso-versione: {versione} -->"]
    machine = {"kind": f.kind, "persona": persona, "brain": brain, "path": f.src_rel, "dest": f.dest, "pr": f.pr_number,
               "hash_file": f.sha256, "base_sha": ctx.base_sha, "head_sha": f.head_sha, "versione": versione,
               "aree": areas, "fatti": [i.as_dict() for i in f.incongruenze], "motivo": f.motivo, "travaso_versione": TRAVASO_VERSION}
    return "\n".join(lines) + "\n", machine


def _fatti_key(fatti: list) -> list[tuple]:
    return sorted((str(f.get("chiave")), str(f.get("nuovo_norm") or f.get("nuovo") or ""), str(f.get("canon_norm") or f.get("canon") or ""))
                  for f in (fatti or []) if isinstance(f, dict))


def upsert_issues(ctx: Ctx, fermi: list[Fermo], persona: str, brain: str, pr_url: str) -> None:
    """Una issue per file fermo (riusata se aperta per lo stesso `dest`). La proposta e' versionata: la issue resta valida
    tale e quale SOLO se coincidono hash del file, fatti (chiavi e valori nuovo/canon), base e head (#7); altrimenti body
    rigenerato con caselle vuote, versione+1, `in-applicazione` tolto e stato azzerato ("proposta rinnovata vN", N3)."""
    if not fermi:
        return
    existing = list_issues(ctx, [LABEL_DA_DECIDERE, f"persona/{persona}"])
    by_dest: dict[str, tuple[dict, dict]] = {}
    for iss in existing:
        m = machine_of(iss)
        if m and m.get("dest"):
            by_dest[str(m["dest"])] = (iss, m)
    need_labels = {LABEL_DA_DECIDERE, LABEL_DECISO, LABEL_IN_APPLICAZIONE, f"persona/{persona}"}
    for f in fermi:
        f.areas, _p, f.assignee = _areas_for(ctx, f)
        need_labels |= {f"area/{a}" for a in f.areas}
    if any(f.dest not in by_dest for f in fermi) and not ctx.dry:
        ensure_labels(ctx, sorted(need_labels))
    for f in fermi:
        if f.dest in by_dest:
            iss, m = by_dest[f.dest]
            f.issue = int(iss["number"])
            same = (str(m.get("hash_file")) == f.sha256 and _fatti_key(m.get("fatti")) == _fatti_key([i.as_dict() for i in f.incongruenze])
                    and str(m.get("base_sha") or "") == ctx.base_sha and str(m.get("head_sha") or "") == (f.head_sha or "")
                    and str(m.get("motivo") or "") == (f.motivo or ""))
            if same:
                continue                                  # stessa proposta: la issue vale ancora
            versione = int(m.get("versione") or 1) + 1
            body, machine = issue_body(ctx, f, versione, persona, brain, pr_url)
            if ctx.dry:
                print(f"[dry-run-git] issue #{f.issue} aggiornata (versione {versione})")
                continue
            issue_edit_body(ctx, f.issue, body)                # REST (fatto live: niente `gh issue edit`)
            issue_labels(ctx, f.issue, add=[f"area/{a}" for a in f.areas], remove=[LABEL_IN_APPLICAZIONE] if LABEL_IN_APPLICAZIONE in _labels(iss) else [])
            issue_comment(ctx, f.issue, f"<!-- travaso: {json.dumps(machine, ensure_ascii=False)} -->")
            issue_comment(ctx, f.issue, f"travaso-stato: proposta rinnovata v{versione}: issue aggiornata il {kc.logical_today().isoformat()} "
                                        "perche' la proposta e' cambiata (file, fatti, base o head); stato azzerato, ricontrolla e rispunta la casella.")
            continue
        body, machine = issue_body(ctx, f, 1, persona, brain, pr_url)
        if ctx.dry:
            print(f"[dry-run-git] issue nuova: {issue_title(ctx, f)}")
            continue
        args = ["issue", "create", "--repo", ctx.full, "--title", mask(issue_title(ctx, f)), "--body-file", "-",
                "--label", LABEL_DA_DECIDERE, "--label", f"persona/{persona}"]
        for a in f.areas:
            args += ["--label", f"area/{a}"]
        if f.assignee:
            args += ["--assignee", f.assignee]
        r = _gh_write(ctx, f"creazione della issue per `{f.dest}`", *args, input_text=mask(body))
        m = re.search(r"/issues/(\d+)", r.stdout or "")
        f.issue = int(m.group(1)) if m else 0
        issue_comment(ctx, f.issue, f"<!-- travaso: {json.dumps(machine, ensure_ascii=False)} -->")

def coverage_line(n_facts: int, semantica: str, unscanned: int) -> str:
    return f"fatti: {n_facts}; semantica: {semantica}; binari non scansionati: {unscanned}"


def status_description(ok: bool, n: int, fermi_issues: list[int], n_facts: int, semantica: str, base_sha: str) -> str:
    head = f"ok: {n} file" if ok else f"{len(fermi_issues)} pezzi fermi: " + " ".join(f"#{i}" for i in fermi_issues if i)
    return f"{head}; fatti: {n_facts}; semantica: {semantica}; base:{base_sha[:7]}"


# ---------------------------------------------------------------------------- esito (par. 5.3, 9, 14.13, 14.26)
class Esito:
    def __init__(self, ctx: Ctx, from_root: Path | None, persona: str, brain: str, cmd: str):
        self.ctx, self.from_root, self.persona, self.brain, self.cmd = ctx, from_root, persona, brain, cmd
        self.ts = dt.datetime.now().strftime("%Y-%m-%d-%H%M%S")
        self.ids: dict[str, str] = {}
        self.data: dict = {"comando": cmd, "versione": TRAVASO_VERSION, "quando": now_iso(), "owner": ctx.owner, "repo": ctx.repo,
                           "persona": persona, "brain": brain, "base_sha": ctx.base_sha, "inviati": [], "integrati": [],
                           "fermi": [], "da_verificare": [], "esclusi": [], "cancellati": [], "non_aggiornati": [], "ignorati": 0,
                           "pr_auto": None, "pr_attesa": None, "review_id": "", "copertura": {}, "note": [], "exit": 0, "azioni": 0}
        self.lines: list[str] = []

    def name(self, rel: str) -> str:
        return file_id(rel, self.ids)

    def dir(self) -> Path | None:
        if self.from_root is None:
            return None
        return self.from_root / kc.TRAVASO_WORKSPACE / f"{self.ctx.owner}-{self.ctx.repo}"

    def rel_md(self) -> str:
        return f"{kc.TRAVASO_WORKSPACE}/{self.ctx.owner}-{self.ctx.repo}/{self.ts}.md"

    def write(self, code: int) -> None:
        d = self.dir()
        if d is None:
            return
        self.data["exit"] = code
        try:
            for f in (d / f"{self.ts}.json", d / f"{self.ts}.md"):
                _check_link_inside("workspace/travaso", self.from_root, f, EXIT_CONFIG)   # catena fino al file (#5)
            kc.write_text(d / f"{self.ts}.json", mask(json.dumps(self.data, ensure_ascii=False, indent=1)) + "\n")
            kc.write_text(d / f"{self.ts}.md", mask(self.markdown(code)))
        except (OSError, Stop) as e:
            print(mask(f"AVVISO: esito non scritto in {d}: {e}"))

    def markdown(self, code: int) -> str:
        d = self.data
        out = [f"# Travaso {d['persona']} -> {self.ctx.full} -- {d['quando']} (exit {code})", "",
               f"Comando `{d['comando']}`, brain `{d['brain']}`, base origin/main `{(d['base_sha'] or '')[:7]}`, motore {TRAVASO_VERSION}.", ""]
        cov = d.get("copertura") or {}
        if cov:
            out += [f"Copertura: fatti {cov.get('fatti', 0)}; semantica {cov.get('semantica', '-')}; binari non scansionati {cov.get('binari_non_scansionati', 0)}.", ""]
        for key, title in (("inviati", "Inviati"), ("integrati", "Integrati"), ("fermi", "Fermi"), ("da_verificare", "Da verificare"),
                           ("cancellati", "Cancellati nel mirror"), ("non_aggiornati", "Non aggiornati"), ("esclusi", "Esclusi")):
            items = d.get(key) or []
            if not items:
                continue
            out.append(f"## {title} ({len(items)})")
            for it in items:
                if isinstance(it, dict):
                    extra = "; ".join(f"{k}: {v}" for k, v in it.items() if k not in ("path", "hash", "motivi") and v not in (None, "", [], 0, False))
                    out.append(f"- `{it.get('path')}`" + (f" ({extra})" if extra else ""))
                    for m in it.get("motivi") or []:
                        out.append(f"  - {m}")
                else:
                    out.append(f"- `{it}`")
            out.append("")
        for k in ("pr_auto", "pr_attesa"):
            if d.get(k):
                out.append(f"- {k}: #{d[k].get('number')} {d[k].get('url', '')} (head {str(d[k].get('sha', ''))[:7]})")
        if d.get("note"):
            out += ["", "## Note"] + [f"- {n}" for n in d["note"]]
        out += ["", "## Righe a schermo"] + [f"    {ln}" for ln in self.lines]
        return "\n".join(out) + "\n"

    def emit(self, lines: list[str]) -> None:
        self.lines = [mask(x) for x in lines]
        for ln in self.lines:
            print(ln, flush=True)


def _motivo(i: Incongruenza) -> str:
    s = f"{i.chiave}: {i.nuovo_raw!r} vs {i.canon_raw!r} ({i.canon_persona}, {i.canon_nota}, {i.canon_data})"
    if i.contro_decisione:
        s += f" contro decisione #{i.contro_decisione}"
    if i.fonte != "fatti":
        s += f" [{i.fonte}]"
    return s


def fermo_sentence(f: Fermo, persona: str) -> str:
    if f.incongruenze:
        i = f.incongruenze[0]
        who = "tu" if persona else persona
        return (f"{f.src_rel} — \"{i.chiave}: {i.nuovo_raw}\" ({who}) vs \"{i.canon_raw}\" ({i.canon_persona}, {i.canon_data})"
                + (f" → issue #{f.issue}" if f.issue else "") + (f" a @{f.assignee}" if f.assignee else ""))
    return f"{f.src_rel} — {f.motivo or 'verifica manuale'}" + (f" → issue #{f.issue}" if f.issue else "") + (f" a @{f.assignee}" if f.assignee else "")


# ---------------------------------------------------------------------------- dopo il merge (par. 14.17)
INGEST_ENV_ALLOW = ("SYSTEMROOT", "SYSTEMDRIVE", "PATH", "TEMP", "TMP", "PYTHONUTF8", "FASTEMBED_CACHE_PATH")


def ingest_env(clone: Path, base_env: dict | None = None) -> dict:
    """Ambiente ISOLATO per l'ingest del clone aziendale (N1): solo l'allowlist di sistema dall'ambiente del chiamante, piu'
    il `.env` del CLONE caricato esplicitamente. Nessuna variabile RAG_/QDRANT_/BRAIN_ del mittente puo' filtrare."""
    src = os.environ if base_env is None else base_env
    env = {k: src[k] for k in INGEST_ENV_ALLOW if src.get(k)}
    envp = clone / ".env"
    if envp.is_file():
        for k, v in kc._parse_env_file(envp).items():
            env[k] = v
    env["PYTHONUTF8"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return env


def post_merge_chores(ctx: Ctx, merged: bool = False) -> list[str]:
    """Dopo send/decisioni (par. 14.17): se c'e' stato un merge immediato, fetch PRIMA; fast-forward del main del clone se e'
    su main e PULITO (anche gli untracked, #17); ingest della zona travaso SOLO con clone allineato a origin/main e con la
    collection del clone (N1)."""
    notes: list[str] = []
    if ctx.dry:
        return notes
    if merged:
        f = ctx.run.git("fetch", "origin", "--quiet", "--prune")
        notes.append("fetch dopo il merge immediato" + ("" if f.returncode == 0 else " FALLITO"))
    branch = ctx.run.current_branch()
    dirty = bool(git_out(ctx.clone, "status", "--porcelain", "--untracked-files=all"))
    aligned = False
    if branch == "main" and not dirty:
        if git_ok(ctx.clone, "merge", "--ff-only", "-q", "refs/remotes/origin/main"):
            notes.append("main del clone aggiornato (fast-forward)")
            aligned = git_out(ctx.clone, "rev-parse", "HEAD") == git_out(ctx.clone, "rev-parse", "refs/remotes/origin/main")
        else:
            notes.append("main del clone NON avanza in fast-forward: riallinea a mano")
    else:
        notes.append(f"clone su `{branch or 'HEAD staccato'}`{' con modifiche o file non tracciati' if dirty else ''}: main non aggiornato")
    if ctx.no_ingest:
        notes.append("ingest aziendale saltato (--no-ingest)")
        return notes
    if not aligned:
        notes.append("ingest aziendale saltato: clone non allineato (serve main pulito, senza file non tracciati, uguale a origin/main)")
        return notes
    env = ingest_env(ctx.clone)
    clone_env = kc._parse_env_file(ctx.clone / ".env") if (ctx.clone / ".env").is_file() else {}
    coll = clone_env.get("RAG_COLLECTION", "")
    if not coll or not (clone_env.get("QDRANT_URL") or clone_env.get("RAG_ALLOW_EMBEDDED") == "1"):
        notes.append("ingest aziendale saltato (Qdrant non configurato nel .env del clone)")
        return notes
    if env.get("RAG_COLLECTION") != coll or env.get("QDRANT_URL") != clone_env.get("QDRANT_URL"):
        notes.append("ingest aziendale saltato: collection/endpoint non vengono dal clone (ambiente incoerente)")
        return notes
    notes.append(f"ingest aziendale: collection {coll} (dal clone)")
    try:
        r = subprocess.run([sys.executable, str(ctx.clone / "scripts" / "rag" / "ingest.py"), "--root", str(ctx.clone), "--node", "."],
                           cwd=str(ctx.clone), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
        notes.append("ingest aziendale eseguito" if r.returncode == 0 else
                     f"ingest aziendale saltato (exit {r.returncode}: {'Qdrant non raggiungibile' if r.returncode == 2 else 'vedi scripts/rag/ingest.py'})")
    except (OSError, subprocess.TimeoutExpired) as e:
        notes.append(f"ingest aziendale saltato ({e.__class__.__name__})")
    return notes

# ---------------------------------------------------------------------------- attesa (par. 6.4, 14.10, 14.11)
def rebuild_attesa(ctx: Ctx, tx: Tx, persona: str, overlay: dict[str, bytes], expected: dict[str, str], drop: set[str],
                   scope_prefix: str | None) -> tuple[dict | None, str, list[str], bool]:
    """Branch `travaso/attesa/<persona>` = origin/main + file fermi. Si tolgono `drop` e, se `scope_prefix` e' dato, tutti i
    file di quel prefisso non piu' in `overlay`; il resto del diff precedente si conserva. Ritorna (PR aperta o None, head,
    file in attesa dopo la ricostruzione)."""
    branch = BRANCH_ATTESA.format(persona=persona)
    base, pr, _merged = prepare_branch(ctx, tx, branch, stop_if_closed=False)
    wt = tx.worktree
    assert wt is not None
    old_head = git_out(wt, "rev-parse", "HEAD")
    prev = [x for x in git_out(wt, "diff", "--name-only", "refs/remotes/origin/main", "HEAD").splitlines() if x.strip()]
    keep = [p for p in prev if p not in drop and p not in overlay and not (scope_prefix and p.startswith(scope_prefix))]
    r = git(wt, "restore", "--source=refs/remotes/origin/main", "--staged", "--worktree", "--no-overlay", "--", ".")
    if r.returncode != 0:
        raise Stop(EXIT_STOP, f"ricostruzione del branch attesa fallita: {git_err(r)}")
    git(wt, "clean", "-fdq")
    for p in keep:
        if git_ok(wt, "cat-file", "-e", f"{old_head}:{p}"):
            git(wt, "checkout", "-q", old_head, "--", p)
    write_files(wt, overlay, set())
    staged = stage_and_verify(wt, ["."], expected)
    in_attesa = [x for x in git_out(wt, "diff", "--cached", "--name-only", "refs/remotes/origin/main").splitlines() if x.strip()]
    if not in_attesa:
        if pr:
            pr_close(ctx, int(pr["number"]), "attesa svuotata: nessun file fermo per questa persona.")
            say(f"PR attesa #{pr['number']} chiusa: nessun file fermo")
        return None, "", [], staged
    head = old_head
    if staged:
        head = commit_in(wt, f"travaso {persona} {kc.logical_today().isoformat()}: attesa ({len(in_attesa)} fermi)\n\n"
                             f"Travaso-Persona: {persona}\nTravaso-Login: {ctx.login}\nTravaso-Versione: {TRAVASO_VERSION}\n", ctx.dry)
        outgoing_or_refuse(ctx, wt)
        push_branch(ctx, wt, branch)
    return pr, head, in_attesa, staged


def attesa_status_and_issues(ctx: Ctx, tx: Tx, persona: str, brain: str, fermi: list[Fermo], pr: dict | None, head: str,
                             in_attesa: list[str], staged_changed: bool) -> dict | None:
    """PR da-decidere (creata o aggiornata), issue per file, status failure sul head (solo se manca o se c'e' un commit nuovo)."""
    branch = BRANCH_ATTESA.format(persona=persona)
    title = f"travaso {persona} {kc.logical_today().isoformat()}: da decidere ({len(in_attesa)} fermi)"
    body_lines = [f"File fermi del travaso di **{persona}** (brain `{brain}`): ogni file ha una issue con le caselle di decisione.",
                  "Questa PR NON si fonde da sola: la applica `travaso.py decisioni` dopo la decisione del responsabile.", ""]
    created = False
    if pr is None:
        pr = pr_create(ctx, branch, title, "\n".join(body_lines) + "\n", [LABEL_DA_DECIDERE])
        created = True
    upsert_issues(ctx, fermi, persona, brain, pr.get("url", ""))
    all_issues = list_issues(ctx, [LABEL_DA_DECIDERE, f"persona/{persona}"])
    nums: list[int] = []
    for iss in all_issues:
        m = machine_of(iss)
        if m and str(m.get("dest")) in in_attesa:
            nums.append(int(iss["number"]))
    nums = sorted(set(nums) | {f.issue for f in fermi if f.issue})
    body_lines += [f"## File ({len(in_attesa)})"] + [f"- `{p}`" + (f" → #{next((f.issue for f in fermi if f.dest == p and f.issue), '')}") for p in in_attesa]
    body_lines += ["", "## Issue"] + [f"- #{n}" for n in nums]
    fault("dopo-pr-attesa", str(pr.get("number") or 0))
    new_body = "\n".join(body_lines) + "\n"
    if created or staged_changed or (pr.get("body") or "") != new_body:       # ripresa idempotente: corpo mancante o vecchio
        pr_edit_body(ctx, int(pr["number"]), new_body)
    n_facts = sum(len(f.incongruenze) for f in fermi)
    desc = status_description(False, len(in_attesa), nums, n_facts, "non verificata (file fermi)", ctx.base_sha)
    if head and (staged_changed or created or not _has_status(ctx, head)):
        post_status(ctx, head, "failure", desc)
    return pr


def _has_status(ctx: Ctx, sha: str) -> bool:
    data = ctx.gh_json("api", f"repos/{ctx.full}/commits/{sha}/status")
    return any(s.get("context") == STATUS_CONTEXT for s in (data or {}).get("statuses", []))


# ---------------------------------------------------------------------------- send (par. 2-6, 14)
def _mirror_on_main(ctx: Ctx, prefix: str) -> dict[str, tuple[str, bytes]]:
    """{path interno: (sha git, byte)} del mirror su origin/main."""
    r = git(ctx.clone, "ls-tree", "-r", "-z", "refs/remotes/origin/main", "--", prefix)
    out: dict[str, str] = {}
    if r.returncode == 0:
        for rec in r.stdout.split(b"\0"):
            if not rec:
                continue
            meta, _, path = rec.partition(b"\t")
            f = meta.decode().split()
            if len(f) == 3 and f[1] == "blob":
                out[path.decode("utf-8", "replace")[len(prefix):]] = f[2]
    blobs = repo_check._blob_contents(ctx.clone, sorted(set(out.values())))
    return {inner: (sha, blobs.get(sha, b"")) for inner, sha in out.items() if inner != "README.md"}


def _deletion_provable(src: Source, rel: str, mirror_hash: str) -> bool:
    if git_out(src.root, "log", "--diff-filter=D", "--format=%H", "-n", "1", "--", rel):
        return True
    for h in git_out(src.root, "log", "--format=%H", "-n", "20", "--", rel).splitlines():
        r = git(src.root, "cat-file", "-p", f"{h}:{rel}")
        if r.returncode == 0 and sha256_bytes(r.stdout) == mirror_hash:
            return True
    return False


def _readme_bytes(ctx: Ctx, persona: str, brain: str) -> bytes:
    text = (f"# Travaso di {persona} — brain `{brain}`\n\n"
            f"Persona: `{persona}` (area {ctx.area_of(persona) or '?'}, login @{ctx.login_of(persona)}). Primo travaso: "
            f"{kc.logical_today().isoformat()}.\n\n"
            f"Questa cartella e' la copia grezza del brain personale `{brain}`: la compila `{ctx.brain_id}-sync` del brain aziendale (canon prima, hub prima),\n"
            "con `source:` e `provenienza:` nelle note compilate. Non modificare a mano: lo riscrive il travaso a ogni rito.\n")
    return text.encode("utf-8")


def _auto_commit_message(ctx: Ctx, src: Source, persona: str, added: int, modified: int, deleted: int) -> str:
    n = added + modified + deleted
    return (f"travaso {persona} {kc.logical_today().isoformat()}: {n} file (+{added} ~{modified} -{deleted})\n\n"
            f"Travaso-Persona: {persona}\nTravaso-Brain: {src.brain_id}\nTravaso-Area: {ctx.area_of(persona) or '?'}\n"
            f"Travaso-Login: {ctx.login}\nTravaso-Sorgente: {src.head_sha} (+{src.dirty} non committati)\n"
            f"Travaso-Versione: {TRAVASO_VERSION}\n")


def _auto_pr_body(ctx: Ctx, src: Source, persona: str, files: list[tuple[str, str]], fermi: list[Fermo], excluded: list[tuple[str, str]],
                  deleted: list[str], kept: list[tuple[str, str]], n_facts: int, semantica: str, scan: str, head: str) -> str:
    lines = [f"Travaso di **{persona}** (brain `{src.brain_id}`, area {ctx.area_of(persona) or '?'}, account `@{ctx.login}`) — "
             f"giorno logico {kc.logical_today().isoformat()}, motore {TRAVASO_VERSION}.", "",
             f"## File ({len(files)}) — sha256"]
    lines += [f"- `{p}` `{h[:12]}`" for p, h in files[:PR_FILES_MAX]] + ([f"- ... altri {len(files) - PR_FILES_MAX}"] if len(files) > PR_FILES_MAX else [])
    if deleted:
        lines += ["", f"## Cancellati ({len(deleted)})"] + [f"- `{p}`" for p in deleted[:PR_FILES_MAX]]
    if fermi:
        lines += ["", f"## Fermi ({len(fermi)}) — NON in questa PR"] + [f"- `{f.src_rel}`" + (f" → #{f.issue}" if f.issue else "") for f in fermi]
    if kept:
        lines += ["", f"## Non aggiornati ({len(kept)})"] + [f"- `{p}`: {w}" for p, w in kept[:PR_FILES_MAX]]
    if excluded:
        lines += ["", f"## Esclusi ({len(excluded)})"] + [f"- `{p}`: {w}" for p, w in excluded[:PR_FILES_MAX]]
    lines += ["", "## Controllo", f"- fatti confrontati: {n_facts}; incongruenze su questi file: 0 (i file con incongruenze sono fermi)",
              f"- semantica: {semantica}", f"- controllo applicativo: {scan}",
              f"- sorgente: HEAD {src.head_sha[:7]} (+{src.dirty} non committati)", "",
              f"Merge automatico quando `brain-check` e' verde (status `coerenza` su `{head[:7]}`, base main `{ctx.base_sha[:7]}`)."]
    return "\n".join(lines) + "\n"


def cmd_send(a) -> int:
    ctx = open_ctx(a.root, a.dry_run_git, a.quiet, a.no_ingest)
    from_root_orig = Path(a.from_)
    _check_link_chain("la radice sorgente", from_root_orig, EXIT_CONFIG)
    from_root = from_root_orig.resolve()
    tcfg = kc.travaso_config(from_root) if (from_root / "brain.yaml").is_file() or (from_root / "brain.config.yaml").is_file() else {}
    if tcfg.get("owner") and tcfg.get("repo") and (tcfg["owner"].lower(), tcfg["repo"].lower()) != (ctx.owner.lower(), ctx.repo.lower()):
        raise Stop(EXIT_DEST, f"il brain {from_root.name} travasa verso {tcfg['owner']}/{tcfg['repo']} ma questo clone e' {ctx.full}")
    src = load_source(a.from_, a.brain, bool(tcfg.get("consenti_master")))
    ws = from_root / kc.TRAVASO_WORKSPACE
    for p in (ws, ws / f"{ctx.owner}-{ctx.repo}"):
        if p.exists():
            _check_link_inside("il brain personale", from_root, p, EXIT_CONFIG)
    fetch_or_defer(ctx)
    load_travaso_yaml(ctx)
    identity_checks(ctx, a.persona, src.brain_id)
    persona = ctx.persona
    es = Esito(ctx, from_root, persona, src.brain_id, "send")
    tx = Tx(ctx)
    code = 0
    try:
        code = _send(ctx, tx, src, from_root, persona, a, es)
    except Stop as e:
        es.data["note"].append(e.msg)
        if not ctx.dry:
            es.write(e.code)
        raise
    finally:
        tx.close()
    if not ctx.dry:
        es.write(code)
    return code

SOURCES_RE = re.compile(r"<!--\s*travaso-sorgenti:\s*(\{.*?\})\s*-->", re.S)


def _sources_block(body: str) -> dict:
    m = SOURCES_RE.search(body or "")
    if not m:
        return {}
    try:
        d = json.loads(m.group(1))
        return d if isinstance(d, dict) else {}
    except ValueError:
        return {}


def _tree_hash(wt: Path, prefix: str) -> str:
    """Impronta del contenuto di una sorgente sul branch (ls-tree di HEAD nel worktree): record `travaso-sorgenti` (N4)."""
    return sha256_bytes(git_out(wt, "ls-tree", "-r", "HEAD", "--", prefix).encode("utf-8"))


def _sources_in(paths: list[str]) -> list[str]:
    out: list[str] = []
    for p in paths:
        prov = kc.travaso_provenance(p)
        if prov:
            pre = f"{ZONE}/{prov[0]}/{prov[1]}/"
            if pre not in out:
                out.append(pre)
    return out


def _withdraw_for_verification(ctx: Ctx, tx: Tx, persona: str, prefix: str, rels: list[str], brain: str) -> str:
    """#10: prima di uscire con 13 la PR auto aperta non deve contenere NESSUNO stato obsoleto di questa sorgente (file da
    verificare, diventati fermi, esclusi, cancellati, cambiati): il sottoalbero della sorgente torna a `main`, commit + push,
    status failure; diff vuoto = PR chiusa."""
    branch = BRANCH_AUTO.format(persona=persona)
    pr = pr_for_branch(ctx, branch)
    if not pr or str(pr.get("state")).upper() != "OPEN" or not ctx.run.has_ref(f"refs/remotes/origin/{branch}"):
        return ""
    _base, pr, merged = prepare_branch(ctx, tx, branch, stop_if_closed=False)
    wt = tx.worktree
    assert wt is not None
    before = [x for x in git_out(wt, "diff", "--name-only", "refs/remotes/origin/main", "HEAD", "--", prefix).splitlines() if x.strip()]
    restore_from_main(wt, prefix)
    touched = before
    stage_and_verify(wt, [prefix], {})
    staged = git(wt, "diff", "--cached", "--quiet").returncode != 0
    if not staged and not merged:
        return ""
    diff_all = [x for x in git_out(wt, "diff", "--cached", "--name-only", "refs/remotes/origin/main").splitlines() if x.strip()]
    if staged:
        commit_in(wt, f"travaso {persona} {kc.logical_today().isoformat()}: ritiro di {len(touched)} file di {brain} in attesa di verifica\n\n"
                      f"Travaso-Persona: {persona}\nTravaso-Brain: {brain}\nTravaso-Versione: {TRAVASO_VERSION}\n", ctx.dry, ctx)
    if not diff_all:
        if staged:
            push_branch(ctx, wt, branch)
        pr_close(ctx, int(pr["number"]), "ritirati i file in attesa di verifica: nulla da integrare.")
        return f"PR #{pr['number']} chiusa (ritirati {len(touched)} file)"
    outgoing_or_refuse(ctx, wt)
    push_branch(ctx, wt, branch)
    head = git_out(wt, "rev-parse", "HEAD")
    post_status(ctx, head, "failure", f"da verificare: {len(rels)} file ({brain}); nulla si fonde finche' manca il verdetto; base:{ctx.base_sha[:7]}")
    return f"ritirati {len(touched)} file dalla PR #{pr['number']} (status failure)"

def _send(ctx: Ctx, tx: Tx, src: Source, from_root: Path, persona: str, a, es: Esito) -> int:
    prefix = f"{ZONE}/{persona}/{src.brain_id}/"
    notes: list[str] = es.data["note"]
    if not ctx.dry:
        try:
            notes += [f"decisioni: {x}" for x in apply_decisions(ctx, tx, quiet_lines=True)]
        except Stop as e:
            if e.code in (EXIT_DEFERRED, EXIT_DEST):
                raise                                     # #24: autorizzazione/validazione non si assorbe
            notes.append(f"decisioni non applicate: {e.msg}")
    # ---- snapshot della sorgente
    snap = enumerate_source(src)
    es.data["ignorati"] = snap.ignored
    es.data["esclusi"] = [{"path": es.name(p), "motivo": w} for p, w in snap.excluded]
    reported = dict(snap.excluded)
    # ---- mirror su origin/main e categorie (par. 4, 14.16)
    main_mirror = _mirror_on_main(ctx, prefix)
    main_hash = {inner: sha256_bytes(data) for inner, (_sha, data) in main_mirror.items()}
    added = [r for r in snap.eligible if r not in main_mirror]
    modified = [r for r in snap.eligible if r in main_mirror and main_hash[r] != snap.eligible[r].sha256]
    unchanged = [r for r in snap.eligible if r in main_mirror and main_hash[r] == snap.eligible[r].sha256]
    kept: list[tuple[str, str]] = []
    deleted_ok: list[str] = []
    deleted_amb: list[str] = []
    for inner in sorted(main_mirror):
        if inner in snap.eligible:
            continue
        if inner in reported:
            kept.append((inner, "non aggiornato: escluso per " + reported[inner]))
        elif inner in snap.present:
            kept.append((inner, "non aggiornato: presente nella sorgente ma oggi fuori dalle cartelle del profilo (o infrastruttura)"))
        elif _deletion_provable(src, inner, main_hash[inner]):
            deleted_ok.append(inner)
        else:
            deleted_amb.append(inner)
    confirm = bool(a.conferma_cancellazioni)
    if not snap.eligible and main_mirror and deleted_amb and not confirm:
        raise Stop(EXIT_DELETIONS, f"insieme eleggibile VUOTO in {src.root} ({snap.ignored} file di infrastruttura, {len(snap.excluded)} esclusi) "
                                   f"e {len(deleted_amb)} file del mirror {prefix} non dimostrabilmente cancellati: --from sbagliato? "
                                   "Se e' voluto: --conferma-cancellazioni")
    if deleted_amb and main_mirror and len(deleted_amb) > DELETION_THRESHOLD * len(main_mirror) and not confirm:
        raise Stop(EXIT_DELETIONS, f"{len(deleted_amb)} file del mirror ({prefix}) non esistono nella sorgente e la sorgente non li ha mai "
                                   f"avuti in git ({len(deleted_amb)}/{len(main_mirror)} > 50%): --from sbagliato? Se e' voluto: "
                                   "--conferma-cancellazioni")
    deletions = deleted_ok + (deleted_amb if confirm else [])
    if deleted_amb and not confirm:
        notes.append(f"{len(deleted_amb)} cancellazioni ambigue sotto soglia NON applicate (--conferma-cancellazioni): " + ", ".join(deleted_amb[:5]))
    es.data["cancellati"] = [{"path": es.name(p), "dimostrata": p in deleted_ok} for p in deletions]
    es.data["non_aggiornati"] = [{"path": es.name(p), "motivo": w} for p, w in kept]
    changed = added + modified
    # ---- controllo deterministico e registro (par. 5, 14.6, 14.15, #6)
    canon = Canon(ctx, persona)
    checks: dict[str, tuple] = {}
    fermi: dict[str, Fermo] = {}
    by_decision: dict[str, int] = {}
    n_facts = 0
    for rel in changed:
        sf = snap.eligible[rel]
        if sf.text is None:
            checks[rel] = ([], [], None, 0)
            inc, ann, excl, nf = canon.check_text(prefix + rel, "", persona, sf.sha256)
        else:
            inc, ann, excl, nf = canon.check_text(prefix + rel, sf.text, persona, sf.sha256)
            checks[rel] = (inc, ann, excl, nf)
        n_facts += nf
        notes += [f"{rel}: {x}" for x in ann]
        if excl is not None:
            by_decision[rel] = excl
        elif inc:
            fermi[rel] = Fermo(prefix + rel, rel, sf.data, sf.sha256, inc)
    for rel, motivo in zip(a.ferma or [], a.motivo or []):
        rel = rel.replace("\\", "/").strip("/")
        if rel in snap.eligible and rel in changed and rel not in by_decision:
            f = fermi.setdefault(rel, Fermo(prefix + rel, rel, snap.eligible[rel].data, snap.eligible[rel].sha256, []))
            f.motivo = f"fermato da {persona}: {motivo}"
        elif rel in snap.eligible:
            notes.append(f"--ferma {rel}: il file non e' cambiato rispetto al mirror (o e' escluso per decisione), niente da fermare")
        else:
            notes.append(f"--ferma {rel}: path non eleggibile o inesistente")
    for rel, n in by_decision.items():
        es.data["esclusi"].append({"path": es.name(rel), "motivo": f"escluso per decisione #{n}: vale il canon (finche' il contenuto non cambia)"})
    # ---- strato semantico (par. 14.1, #1)
    need = [r for r in changed if r not in fermi and r not in by_decision]
    verified: dict[str, str] = {}
    review_id = ""
    verdict_problem = ""
    if a.verdetto:
        pkg, ver, verdict_problem = load_verdict(from_root, ctx, a.verdetto, src.brain_id)
        review_id = a.verdetto
        if verdict_problem:
            notes.append(f"verdetto {a.verdetto} NON utilizzabile: {verdict_problem}")
        for rel in ([] if verdict_problem else need):
            info = (pkg.get("files") or {}).get(rel)
            v = (ver.get("files") or {}).get(rel)
            if not info or not v or str(info.get("hash")) != snap.eligible[rel].sha256:
                continue
            esito = str(v.get("esito"))
            verified[rel] = esito
            if esito == "incongruente":
                sf = snap.eligible[rel]
                inc = Incongruenza(str(v.get("soggetto") or rel), str(v.get("chiave") or "semantica"), str(v.get("nuovo") or ""),
                                   str(v.get("nuovo") or ""), str(v.get("canon") or ""), str(v.get("canon") or ""), "canon", "",
                                   str(v.get("fonte_canon") or ""), "?", None, "agente")
                fermi[rel] = Fermo(prefix + rel, rel, sf.data, sf.sha256, [inc], motivo=str(v.get("motivo") or "verdetto dell'agente"))
            elif esito == "non-verificabile":
                sf = snap.eligible[rel]
                fermi[rel] = Fermo(prefix + rel, rel, sf.data, sf.sha256, [], motivo=f"verifica manuale: {v.get('motivo') or 'non verificabile dall\'agente'}")
    unverified = [r for r in need if r not in verified]
    policy = ctx.policy()
    da_verificare: list[str] = unverified if (unverified and policy == "richiesta") else []
    entrati = [r for r in changed if r not in fermi and r not in by_decision and r not in da_verificare]
    n_ver = sum(1 for r in entrati if verified.get(r) == "coerente")
    if entrati and n_ver == len(entrati):
        semantica = f"verificata ({review_id})"
    elif n_ver:
        semantica = f"parziale ({review_id}: {n_ver}/{len(entrati)})"
    else:
        semantica = "non verificata" + (" (policy facoltativa)" if policy == "facoltativa" and entrati else "")
    unscanned = sum(1 for r in snap.eligible if snap.eligible[r].text is None)
    es.data["copertura"] = {"fatti": n_facts, "semantica": semantica, "binari_non_scansionati": unscanned, "policy": policy}
    es.data["review_id"] = review_id
    fermi_list = list(fermi.values())
    # ---- dry-run: piano in memoria, nessuna mutazione locale ne' remota (#12)
    if ctx.dry:
        es.emit([f"[dry-run-git] Travaso verso {ctx.full}: {len(entrati)} inviati, {len(deletions)} cancellati, {len(fermi_list)} fermi, "
                 f"{len(da_verificare)} da verificare, {len(snap.excluded) + len(by_decision)} esclusi (piano: nessuna mutazione). "
                 + coverage_line(n_facts, semantica if not da_verificare else "da verificare", unscanned),
                 "[dry-run-git] " + ("; ".join(f"{r} -> {prefix}{r}" for r in entrati[:5]) or "nessun file da inviare")
                 + (f"; fermi: {', '.join(f.src_rel for f in fermi_list[:5])}" if fermi_list else "")])
        return 0
    fault("prima-della-mutazione", str(ctx.clone))
    assert_base(ctx)
    # ---- da verificare senza verdetto utilizzabile: ritiro dell'obsoleto, pacchetto ed exit 13 (#10)
    if da_verificare and (not a.verdetto or verdict_problem):
        withdrawn = _withdraw_for_verification(ctx, tx, persona, prefix, da_verificare, src.brain_id)
        rid, pkg, md = build_package(ctx, src, canon, {r: snap.eligible[r] for r in da_verificare}, checks)
        d = write_package(from_root, ctx, rid, pkg, md)
        es.data["review_id"] = rid
        es.data["da_verificare"] = [{"path": es.name(r), "hash": snap.eligible[r].sha256} for r in da_verificare]
        rel_pkg = f"{kc.TRAVASO_WORKSPACE}/{ctx.owner}-{ctx.repo}/{rid}/verifica.md"
        shown = [f"{es.name(p)} ({w.split(':')[0].split('(')[0].strip() or w})" for p, w in snap.excluded[:2]]
        tail = (f"Esclusi {len(snap.excluded)}: " + ", ".join(shown) + (" ..." if len(snap.excluded) > 2 else "") + ". ") if snap.excluded else ""
        why = f" ({verdict_problem})" if verdict_problem else ""
        es.emit([f"Travaso verso {ctx.full}: {len(da_verificare)} file da verificare{why} (pacchetto {rel_pkg}); "
                 f"{len(fermi_list)} fermi; {len(snap.excluded)} esclusi. {coverage_line(n_facts, 'da verificare', unscanned)}",
                 "Esegui la skill `" + (yaml_brain_id(from_root) or "<id>") + "-travaso verifica` (legge solo il pacchetto), "
                 f"poi: brain_sync.py --travaso send --verdetto {rid}" + (f". {withdrawn}" if withdrawn else ""),
                 f"{tail}Dettagli: {es.rel_md()}"])
        return EXIT_VERIFY
    # ---- branch auto (par. 6.1, 6.3, 14.9, 14.10, N4)
    branch_auto = BRANCH_AUTO.format(persona=persona)
    base, pr_auto, merged_main = prepare_branch(ctx, tx, branch_auto, stop_if_closed=True)
    wt = tx.worktree
    assert wt is not None
    restore_from_main(wt, prefix)
    overlay = {prefix + r: snap.eligible[r].data for r in entrati}
    expected = {prefix + r: snap.eligible[r].sha256 for r in entrati}
    if overlay and "README.md" not in {p[len(prefix):] for p in git_out(wt, "ls-files", "--", prefix).splitlines()}:
        overlay[prefix + "README.md"] = _readme_bytes(ctx, persona, src.brain_id)
    write_files(wt, overlay, {prefix + r for r in deletions})
    staged = stage_and_verify(wt, [prefix], expected)
    diff_main = [x for x in git_out(wt, "diff", "--cached", "--name-only", "refs/remotes/origin/main", "--", prefix).splitlines() if x.strip()]
    diff_all = [x for x in git_out(wt, "diff", "--cached", "--name-only", "refs/remotes/origin/main").splitlines() if x.strip()]
    azioni = 0
    head_auto = git_out(wt, "rev-parse", "HEAD")
    pr_files: list[tuple[str, str]] = [(p[len(prefix):], sha256_bytes((wt / p).read_bytes()) if (wt / p).is_file() else "cancellato") for p in diff_main]
    scan = repo_check.scan_note(None)
    line1 = ""
    missing_sources: list[str] = []
    integrati = False
    if not diff_all:
        if pr_auto:
            pr_close(ctx, int(pr_auto["number"]), "il contenuto delle sorgenti e' tornato uguale a main: nulla da integrare.")
            azioni += 1
            line1 = f"Travaso verso {ctx.full}: ritirati {len(entrati) + len(deletions)} file (PR #{pr_auto['number']} chiusa, nulla fuso)"
        else:
            line1 = f"Travaso verso {ctx.full}: 0 azioni (mirror allineato: {len(unchanged)} file)"
    else:
        if staged:
            n_del = len([p for p in diff_main if not (wt / p).is_file()])
            head_auto = commit_in(wt, _auto_commit_message(ctx, src, persona, len([r for r in entrati if r in added]),
                                                           len([r for r in entrati if r in modified]), n_del), ctx.dry, ctx)
        if staged or merged_main:
            head_auto = git_out(wt, "rev-parse", "HEAD")
            _n, scan = outgoing_or_refuse(ctx, wt)
            push_branch(ctx, wt, branch_auto)
            azioni += 1
        # N4: una riga per SORGENTE nel corpo della PR; lo status copre l'intero head
        fresh = bool(a.verdetto) and not verdict_problem and bool(verified)   # N4: verifica nuova e valida in QUESTA corsa
        records = _sources_block((pr_auto or {}).get("body") or "")
        records[prefix] = {"brain": src.brain_id, "semantica": semantica, "base_sha": ctx.base_sha, "review_id": review_id,
                           "hash": _tree_hash(wt, prefix),
                           "verificata": bool(entrati) and n_ver == len(entrati) or (not entrati and not diff_main)}
        in_diff = _sources_in(diff_all)
        if policy == "richiesta":
            for pre in in_diff:
                rec = records.get(pre) or {}
                same_tree = not rec.get("hash") or rec.get("hash") == _tree_hash(wt, pre)
                if pre == prefix:
                    ok_src = (n_ver == len(entrati)) if entrati else bool(rec.get("verificata")) and rec.get("base_sha") == ctx.base_sha
                else:
                    ok_src = bool(rec.get("verificata")) and rec.get("base_sha") == ctx.base_sha and same_tree
                if not ok_src:
                    missing_sources.append(str(rec.get("brain") or pre.rstrip("/").split("/")[-1]))
        labels = [LABEL_SEMANTICA] if (entrati and policy == "facoltativa" and n_ver < len(entrati)) else []
        body = _auto_pr_body(ctx, src, persona, pr_files, fermi_list, snap.excluded, deletions, kept, n_facts, semantica, scan, head_auto)
        body += f"\n<!-- travaso-sorgenti: {json.dumps(records, ensure_ascii=False)} -->\n"
        if pr_auto is None:
            pr_auto = pr_create(ctx, branch_auto, f"travaso {persona} {kc.logical_today().isoformat()}", body, labels)
            azioni += 1
        elif staged or merged_main or fresh or (pr_auto.get("body") or "") != body:
            pr_edit_body(ctx, int(pr_auto["number"]), body)   # N4: anche a byte invariati, se la verifica e' nuova
        if staged or merged_main or fresh or not _has_status(ctx, head_auto):
            if missing_sources:
                post_status(ctx, head_auto, "failure", f"sorgenti da verificare: {', '.join(missing_sources)}; fatti: {n_facts}; base:{ctx.base_sha[:7]}")
            else:
                post_status(ctx, head_auto, "success", status_description(True, len(diff_all), [], n_facts, semantica, ctx.base_sha))
                pr_auto = enable_automerge(ctx, pr_auto)
                integrati = str(pr_auto.get("state") or "").upper() == "MERGED"
        if missing_sources:
            line1 = f"Travaso verso {ctx.full}: {len(entrati)} inviati (PR #{pr_auto['number']}, FERMA: sorgenti da verificare {', '.join(missing_sources)})"
        elif integrati:
            line1 = f"Travaso verso {ctx.full}: {len(entrati)} integrati (PR #{pr_auto['number']} fusa subito: requisiti gia' soddisfatti)"
        elif staged or merged_main:
            line1 = f"Travaso verso {ctx.full}: {len(entrati)} inviati (PR #{pr_auto['number']}, in attesa dei check)"
        elif fresh:
            line1 = f"Travaso verso {ctx.full}: {len(entrati)} inviati (PR #{pr_auto['number']} gia' aperta: verifica registrata, status aggiornato)"
        else:
            line1 = f"Travaso verso {ctx.full}: 0 azioni (PR #{pr_auto['number']} gia' aggiornata con {len(diff_all)} file)"
        es.data["pr_auto"] = {"number": pr_auto["number"], "url": pr_auto.get("url", ""), "sha": head_auto}
    key = "integrati" if integrati else "inviati"
    es.data[key] = [{"path": es.name(r), "hash": snap.eligible[r].sha256} for r in entrati]
    # ---- branch attesa + issue (par. 6.4, 14.7)
    overlay_att = {f.dest: f.data for f in fermi_list}
    expected_att = {f.dest: f.sha256 for f in fermi_list}
    pr_att, head_att, in_attesa, att_staged = rebuild_attesa(ctx, tx, persona, overlay_att, expected_att, set(), prefix)
    if in_attesa:
        pr_att = attesa_status_and_issues(ctx, tx, persona, src.brain_id, fermi_list, pr_att, head_att, in_attesa, staged_changed=att_staged)
        es.data["pr_attesa"] = {"number": pr_att["number"], "url": pr_att.get("url", ""), "sha": head_att} if pr_att else None
        azioni += 1
    es.data["fermi"] = [{"path": es.name(f.src_rel), "issue": f.issue, "assegnatario": f.assignee, "aree": f.areas,
                         "motivi": [_motivo(i) for i in f.incongruenze] or [f.motivo]} for f in fermi_list]
    es.data["azioni"] = azioni
    # ---- esito a schermo (par. 9, 14.26): sempre al massimo 3 righe
    parts = []
    if fermi_list:
        parts.append(f"{len(fermi_list)} fermi")
    if unverified and policy == "richiesta" and a.verdetto:
        parts.append(f"{len(unverified)} da verificare")
    if snap.excluded or by_decision:
        parts.append(f"{len(snap.excluded) + len(by_decision)} esclusi")
    if deletions:
        parts.append(f"{len(deletions)} cancellati")
    line1 += ("; " + ", ".join(parts) if parts else "") + ". " + coverage_line(n_facts, semantica, unscanned)
    lines = [line1]
    if fermi_list:
        first = fermo_sentence(fermi_list[0], "tu")
        more = f" (+{len(fermi_list) - 1} altri)" if len(fermi_list) > 1 else ""
        lines.append(f"{len(fermi_list)} {'pezzo fermo' if len(fermi_list) == 1 else 'pezzi fermi'}: {first}{more}")
    chores = post_merge_chores(ctx, merged=integrati)     # #17: dopo un merge immediato fetch + ff PRIMA dell'ingest
    notes += chores
    tail = []
    shown = [f"{es.name(p)} ({w.split(':')[0].split('(')[0].strip() or w})" for p, w in snap.excluded[:2]]
    if snap.excluded:
        tail.append(f"Esclusi {len(snap.excluded)}: " + ", ".join(shown) + (" ..." if len(snap.excluded) > 2 else "") + ".")
    rid_next = ""
    if unverified and policy == "richiesta" and a.verdetto:
        rid_next, pkg, md = build_package(ctx, src, canon, {r: snap.eligible[r] for r in unverified}, checks)
        write_package(from_root, ctx, rid_next, pkg, md)
        es.data["da_verificare"] = [{"path": es.name(r), "hash": snap.eligible[r].sha256} for r in unverified]
        es.data["review_id"] = rid_next
        tail.append(f"{len(unverified)} file cambiati dopo il pacchetto: nuovo pacchetto {rid_next}, verifica e rilancia con --verdetto {rid_next}.")
    ing = [c for c in chores if c.startswith("ingest aziendale")]
    tail.append(f"Dettagli: {es.rel_md()}" + (f"; {'; '.join(ing)}" if ing else ""))
    lines.append(" ".join(tail))
    es.emit(lines[:3])
    if rid_next or missing_sources:
        return EXIT_VERIFY
    return 0

# ---------------------------------------------------------------------------- decisioni (par. 6.5, 14.6, 14.7, 14.8)
BOX_RE = re.compile(r"^\s*[-*]\s*\[([xX ])\]\s*(vale il nuovo|vale il canon|valgono entrambi)", re.M)
BOX_CHOICE = {"vale il nuovo": "nuovo", "vale il canon": "canon", "valgono entrambi": "entrambi"}
COMMENT_CHOICE_RE = re.compile(r"^\s*vale:\s*(nuovo|canon|entrambi)\s+v(\d+)\s*$", re.I | re.M)
CONTEXT_RE = re.compile(r"^\s*contesto (nuovo|canon):\s*(.+?)\s*$", re.I | re.M)


def _labels(issue: dict) -> set[str]:
    return {str(x.get("name") or x) for x in issue.get("labels") or []}


def _comment_once(ctx: Ctx, issue: dict, marker: str, text: str) -> None:
    tag = f"<!-- travaso-avviso: {marker} -->"
    if any(tag in (c.get("body") or "") for c in issue.get("comments") or []):
        return
    issue_comment(ctx, int(issue["number"]), f"{text}\n{tag}")


def _version_of(issue: dict, m: dict) -> int:
    v = VERSION_RE.search(issue.get("body") or "")
    return int(v.group(1)) if v else int(m.get("versione") or 1)


GRAPHQL_EDITS = ("query($owner:String!,$name:String!,$number:Int!,$last:Int!,$before:String){repository(owner:$owner,name:$name)"
                 "{issue(number:$number){userContentEdits(last:$last,before:$before){totalCount pageInfo{hasPreviousPage startCursor}"
                 "nodes{editor{login} editedAt deletedAt diff}}}}}")
BOX_LABELS = {"nuovo": "vale il nuovo", "canon": "vale il canon", "entrambi": "valgono entrambi"}
EDITS_MAX_PAGES = 20


def _box_ticked(body: str, label: str) -> bool:
    return re.search(r"^\s*[-*]\s*\[[xX]\]\s*" + re.escape(label), body or "", re.M) is not None


def editor_of_tick(ctx: Ctx, number: int, version: int, choice: str) -> tuple[str | None, str]:
    """(editor, motivo). Chi ha spuntato LA casella scelta. Fatto 41: `userContentEdits.diff` e' il corpo INTERO della
    revisione, la creazione e' la prima revisione, l'ordine va ricostruito da `editedAt`, `totalCount` oltre la finestra
    richiede la paginazione (cursore `before`). Si pagina all'indietro finche' si trova la transizione [ ] -> [x] della
    casella (editor = quella revisione) o si raggiunge la creazione (stato iniziale = corpo della creazione, mai "casella
    vuota" per ipotesi). Una revisione eliminata (`deletedAt`) nella finestra rilevante, o una storia che non si riesce a
    completare = non dimostrabile (#7, #23)."""
    label = BOX_LABELS[choice]
    revs: list[dict] = []
    before: str | None = None
    reached_start = False
    for _page in range(EDITS_MAX_PAGES):
        args = ["api", "graphql", "-f", f"query={GRAPHQL_EDITS}", "-F", f"owner={ctx.owner}", "-F", f"name={ctx.repo}",
                "-F", f"number={number}", "-F", "last=20"]
        if before:
            args += ["-f", f"before={before}"]
        try:
            data = ctx.gh_json(*args)
        except Stop as e:
            return None, f"storia delle modifiche incompleta (pagina non leggibile: {_out(e.msg, 120)})"
        uce = ((((data or {}).get("data") or {}).get("repository") or {}).get("issue") or {}).get("userContentEdits") or {}
        page = [n for n in (uce.get("nodes") or []) if isinstance(n, dict)]
        if not page and not revs:
            return None, "storia delle modifiche vuota"
        revs = page + revs if before else list(page)
        info = uce.get("pageInfo") or {}
        revs.sort(key=lambda n: str(n.get("editedAt") or ""))
        final = revs[-1]
        if final.get("deletedAt"):
            return None, "storia delle modifiche incompleta (ultima revisione eliminata)"
        vm = VERSION_RE.search(str(final.get("diff") or ""))
        if not vm or int(vm.group(1)) != version or not _box_ticked(str(final.get("diff") or ""), label):
            return None, "la revisione finale non porta la casella spuntata con la versione corrente"
        # dall'ultima revisione all'indietro: la prima NON spuntata delimita la transizione
        for i in range(len(revs) - 1, -1, -1):
            n = revs[i]
            if n.get("deletedAt"):
                return None, "storia delle modifiche incompleta (revisione eliminata nella finestra rilevante)"
            if not _box_ticked(str(n.get("diff") or ""), label):
                return (revs[i + 1].get("editor") or {}).get("login"), "casella"
        if not info.get("hasPreviousPage"):
            reached_start = True
            break
        before = str(info.get("startCursor") or "")
        if not before:
            break
    if reached_start:
        return (revs[0].get("editor") or {}).get("login"), "casella gia' spuntata alla creazione"
    return None, "storia delle modifiche incompleta (oltre le pagine leggibili)"

def read_decision(ctx: Ctx, issue: dict, m: dict) -> tuple[str, str, str, int] | None:
    """(scelta, decisore, come, versione) oppure None (con eventuale commento di avviso, una volta per versione).
    La versione nel corpo deve coincidere con quella del commento macchina (#7)."""
    v = _version_of(issue, m)
    if int(m.get("versione") or v) != v:
        _comment_once(ctx, issue, f"versione-incoerente-v{v}", f"Versione del corpo ({v}) diversa da quella dei dati macchina "
                                                              f"({m.get('versione')}): la issue sara' rigenerata al prossimo travaso. Nessuna azione.")
        return None
    body = issue.get("body") or ""
    ticked = [c for c, label in BOX_LABELS.items() if _box_ticked(body, label)]
    if len(ticked) > 1:
        _comment_once(ctx, issue, f"due-caselle-v{v}", f"Due caselle spuntate (versione {v}): lasciane UNA sola, poi rilancio `decisioni`.")
        return None
    if len(ticked) == 1:
        editor, why = editor_of_tick(ctx, int(issue["number"]), v, ticked[0])
        if not editor:
            if "incompleta" in why:
                _comment_once(ctx, issue, f"storia-incompleta-v{v}", f"Storia delle modifiche incompleta ({why}): non posso attribuire "
                                                                    f"la spunta. Ridecidi con un commento `vale: {ticked[0]} v{v}`.")
            else:
                _comment_once(ctx, issue, f"editor-ignoto-v{v}", f"Non riesco a stabilire chi ha spuntato la casella ({why}): "
                                                               f"nessuna azione. In alternativa scrivi un commento `vale: {ticked[0]} v{v}`.")
            return None
        return ticked[0], editor, "casella", v
    for c in reversed(issue.get("comments") or []):
        mk = COMMENT_CHOICE_RE.search(c.get("body") or "")
        if mk:
            if int(mk.group(2)) != v:
                _comment_once(ctx, issue, f"versione-vecchia-v{v}", f"Il commento `vale: {mk.group(1)} v{mk.group(2)}` riguarda una versione "
                                                                    f"superata: la issue e' alla versione {v}. Rispunta o riscrivi `vale: ... v{v}`.")
                return None
            return mk.group(1).lower(), str((c.get("author") or {}).get("login") or ""), "commento", v
    return None

def is_authorized(ctx: Ctx, issue: dict, m: dict, login: str) -> tuple[bool, str]:
    assignees = {str(x.get("login") or x) for x in issue.get("assignees") or []}
    if login in assignees:
        return True, "assegnatario"
    teams = [ctx.team_of(a) for a in (m.get("aree") or []) if ctx.team_of(a)] + ["direzione"]
    for slug in dict.fromkeys(teams):
        data = ctx.gh_json("api", f"orgs/{ctx.org}/teams/{slug}/memberships/{login}")
        if data and str(data.get("state")) == "active":
            return True, f"team {slug}"
    return False, ", ".join(f"@{a}" for a in sorted(assignees)) + " o i team " + ", ".join(f"`{t}`" for t in dict.fromkeys(teams))


def _attesa_blob(ctx: Ctx, persona: str, dest: str) -> bytes | None:
    return show_main(ctx, dest, f"refs/remotes/origin/{BRANCH_ATTESA.format(persona=persona)}")


def _add_decision_frontmatter(text: str, entry: str) -> str:
    """`decisioni_travaso: ["#n chiave: vecchio -> nuovo"]` nel frontmatter della nota canon superata (modifica meccanica)."""
    m = re.match(r"^(﻿?---\s*\n)(.*?)(\n---\s*\n)", text, re.S)
    quoted = json.dumps(entry, ensure_ascii=False)
    if not m:
        return f"---\ndecisioni_travaso:\n  - {quoted}\n---\n\n" + text
    fm = m.group(2)
    if re.search(r"^decisioni_travaso:\s*$", fm, re.M):
        fm = re.sub(r"^(decisioni_travaso:\s*\n(?:\s+-\s.*\n?)*)", lambda mm: mm.group(1).rstrip("\n") + f"\n  - {quoted}\n", fm, count=1, flags=re.M)
        fm = fm.rstrip("\n")
    elif re.search(r"^decisioni_travaso:\s*\[", fm, re.M):
        fm = re.sub(r"^(decisioni_travaso:\s*\[)(.*?)\]", lambda mm: mm.group(1) + (mm.group(2) + ", " if mm.group(2).strip() else "") + quoted + "]", fm, count=1, flags=re.M)
    else:
        fm = fm + f"\ndecisioni_travaso:\n  - {quoted}"
    return m.group(1) + fm + m.group(3) + text[m.end():]


def prepare_deciso(ctx: Ctx, tx: Tx, issue: dict, m: dict, choice: str, decider: str, how: str, version: int) -> dict:
    """PR `travaso/deciso/<n>` con il registro (sempre), il file deciso (nuovo/entrambi, kind travaso) e il frontmatter della
    nota canon superata (nuovo). Status success + auto-merge. Idempotente: PR aperta esistente = riuso (riallineata e
    rivalutata se indietro, #9)."""
    n = int(issue["number"])
    branch = BRANCH_DECISO.format(issue=n)
    existing = pr_for_branch(ctx, branch)
    if existing and str(existing.get("state")).upper() == "OPEN":
        return _ensure_deciso_pr(ctx, tx, n, existing, issue, m)
    if tx.worktree is None:
        tx.open("refs/remotes/origin/main")
    else:
        tx.checkout("refs/remotes/origin/main")
    wt = tx.worktree
    assert wt is not None
    persona = str(m.get("persona") or "")
    dest = str(m.get("dest") or m.get("path") or "")
    body = issue.get("body") or ""
    contexts = {mk.group(1).lower(): mk.group(2) for mk in CONTEXT_RE.finditer(body)}
    files: dict[str, bytes] = {}
    expected: dict[str, str] = {}
    note_edits: list[str] = []
    if m.get("kind") == "travaso" and choice in ("nuovo", "entrambi"):
        blob = _attesa_blob(ctx, persona, dest)
        if blob is None:
            raise Stop(EXIT_STOP, f"issue #{n}: il file `{dest}` non e' piu' sul branch attesa di {persona}: nessuna azione")
        files[dest] = blob
        expected[dest] = sha256_bytes(blob)
    if choice == "nuovo":
        for f in m.get("fatti") or []:
            nota = str(f.get("canon_nota") or "")
            if not nota or kc.travaso_provenance(nota) is not None or nota in files:
                continue
            raw = show_main(ctx, nota)
            if raw is None:
                continue
            text = raw.decode("utf-8-sig", "replace")
            entry = f"#{n} {f.get('chiave')}: {f.get('canon')} -> {f.get('nuovo')}"
            files[nota] = _add_decision_frontmatter(text, entry).encode("utf-8")
            note_edits.append(nota)
    reg = {"issue": n, "kind": m.get("kind"), "persona": persona, "path": m.get("path"), "dest": dest, "brain": m.get("brain"),
           "versione": version, "hash_file": m.get("hash_file"), "base_sha": m.get("base_sha") or ctx.base_sha,
           "head_sha": m.get("head_sha") or "", "fatti": m.get("fatti") or [], "esito": choice, "motivo": m.get("motivo") or "",
           "contesti": ({"nuovo": contexts.get("nuovo", "non specificati"), "canon": contexts.get("canon", "non specificati")}
                        if choice == "entrambi" else {}),
           "deciso_da": decider, "revisione": f"{how} v{version}", "data": kc.logical_today().isoformat(),
           "stato": "applicata", "applicato": {"pr": 0, "sha": ""}, "note_canon_marcate": note_edits, "travaso_versione": TRAVASO_VERSION}
    reg_path = f"{REGISTER_DIR}/{n}.yaml"
    files[reg_path] = yaml_dump(reg).encode("utf-8")
    write_files(wt, files, set())
    stage_and_verify(wt, sorted(files), expected)
    msg = (f"travaso deciso #{n}: vale {choice} ({m.get('path')})\n\nTravaso-Persona: {persona}\nTravaso-Deciso-Da: {decider}\n"
           f"Travaso-Issue: {n}\nTravaso-Versione: {TRAVASO_VERSION}\n")
    head = commit_in(wt, msg, ctx.dry, ctx)
    outgoing_or_refuse(ctx, wt)
    push_branch(ctx, wt, branch)
    title = f"travaso deciso #{n}: vale {choice} — {m.get('path')}"
    pr_body = (f"Applica la decisione della issue #{n} (vale **{choice}**, decisa da @{decider}, {how} v{version}).\n\n"
               f"- registro: `{reg_path}`\n" + (f"- file: `{dest}`\n" if dest in files else "") +
               ("".join(f"- nota canon marcata: `{x}`\n" for x in note_edits)) +
               f"\nMerge automatico quando `brain-check` e' verde (status `coerenza` deciso in #{n}).\n")
    pr = pr_create(ctx, branch, title, pr_body, [])
    if pr.get("number"):
        reg["applicato"] = {"pr": pr["number"], "sha": head}
        write_files(wt, {reg_path: yaml_dump(reg).encode("utf-8")}, set())
        stage_and_verify(wt, [reg_path], {})
        head = commit_in(wt, f"travaso deciso #{n}: registro con PR #{pr['number']}\n\nTravaso-Issue: {n}\n", ctx.dry, ctx)
        push_branch(ctx, wt, branch)
    post_status(ctx, head, "success", f"deciso in #{n} (vale {choice}); base:{ctx.base_sha[:7]}")
    return enable_automerge(ctx, pr)


def _ensure_deciso_pr(ctx: Ctx, tx: Tx, n: int, pr: dict, issue: dict | None = None, m: dict | None = None) -> dict:
    """PR deciso aperta: se e' indietro rispetto a main la riallinea (merge da main) e RIVALUTA il file deciso contro il canon
    nuovo (#9): una contraddizione diversa dalle triple decise = nessun success, PR chiusa, file di nuovo in attesa, issue
    rinnovata (versione+1, `in-applicazione` tolto, commento) -> nuova decisione. Altrimenti status e auto-merge sul head."""
    branch = BRANCH_DECISO.format(issue=n)
    remote = f"refs/remotes/origin/{branch}"
    head = str(pr.get("headRefOid") or "")
    if ctx.run.has_ref(remote) and head and not git_ok(ctx.clone, "merge-base", "--is-ancestor", "refs/remotes/origin/main", remote):
        if tx.worktree is None:
            tx.open(remote)
        else:
            tx.checkout(remote)
        wt = tx.worktree
        mg = git(wt, "merge", "--no-edit", "-q", "refs/remotes/origin/main")
        if mg.returncode != 0:
            git(wt, "merge", "--abort")
            raise Stop(EXIT_STOP, f"PR deciso #{pr.get('number')}: merge di origin/main con conflitti, risolvi a mano ({pr.get('url', '')})")
        if m and m.get("kind") == "travaso" and issue is not None:
            renewed = _reevaluate_decision(ctx, tx, wt, n, pr, issue, m)
            if renewed is not None:
                return renewed
        outgoing_or_refuse(ctx, wt)
        push_branch(ctx, wt, branch)
        head = git_out(wt, "rev-parse", "HEAD")
        pr = {**pr, "headRefOid": head}
    if head and not _has_status(ctx, head):
        post_status(ctx, head, "success", f"deciso in #{n}; base:{ctx.base_sha[:7]}")
    return enable_automerge(ctx, pr)


def _reevaluate_decision(ctx: Ctx, tx: Tx, wt: Path, n: int, pr: dict, issue: dict, m: dict) -> dict | None:
    """#9: dopo il merge da main, il file deciso deve contraddire SOLO le triple gia' decise. Nuova contraddizione -> la
    decisione non vale piu': PR deciso chiusa, file riportato in attesa, issue rinnovata. Ritorna la PR chiusa o None."""
    persona, dest = str(m.get("persona") or ""), str(m.get("dest") or "")
    r = git(wt, "cat-file", "-p", f"HEAD:{dest}")
    if r.returncode != 0:
        return None
    text = repo_check.decode_text(r.stdout)
    if text is None:
        return None
    canon = Canon(ctx, persona)
    inc, _ann, _excl, _nf = canon.check_text(dest, text, persona, sha256_bytes(r.stdout))
    decided = set(_fatti_key(m.get("fatti")))
    new = [i for i in inc if _fatti_key([i.as_dict()])[0] not in decided and i.contro_decisione != n]
    if not new:
        return None
    issue_comment(ctx, n, "nuova contraddizione arrivata su main dopo la decisione: " + "; ".join(_motivo(i) for i in new[:3])
                  + f". La decisione v{m.get('versione')} non si applica: proposta rinnovata, serve una nuova decisione.")
    post_status(ctx, str(pr.get("headRefOid") or ""), "failure", f"nuova contraddizione dopo la decisione #{n}: ridecidere; base:{ctx.base_sha[:7]}")
    pr_close(ctx, int(pr["number"]), "decisione superata da una nuova contraddizione su main: la issue e' stata rinnovata.")
    rebuild_attesa(ctx, tx, persona, {dest: r.stdout}, {dest: sha256_bytes(r.stdout)}, set(), None)
    f = Fermo(dest, str(m.get("path") or dest), r.stdout, sha256_bytes(r.stdout), inc)
    upsert_issues(ctx, [f], persona, str(m.get("brain") or ""), "")
    issue_labels(ctx, n, remove=[LABEL_IN_APPLICAZIONE])
    return {**pr, "state": "CLOSED", "renewed": True}

def complete_decision(ctx: Ctx, tx: Tx, issue: dict, m: dict, pr: dict, choice: str) -> str:
    """Passi idempotenti DOPO la preparazione (anche in ripresa dopo un crash, #8): commento `preparata`, pulizia
    dell'attesa (kind travaso), status aggregato sul head della PR umana (kind pr)."""
    n = int(issue["number"])
    persona = str(m.get("persona") or "")
    marker = f"travaso-stato: preparata (PR #{pr['number']})"
    if not any(marker in (c.get("body") or "") for c in issue.get("comments") or []):
        issue_comment(ctx, n, f"{marker}: la issue si chiude quando la PR e' fusa.")
    if m.get("kind") == "travaso":
        dest = str(m.get("dest") or "")
        if _attesa_blob(ctx, persona, dest) is not None:
            _pr2, _h2, left, _st2 = rebuild_attesa(ctx, tx, persona, {}, {}, {dest}, None)
            if left and _pr2 is not None:
                attesa_status_and_issues(ctx, tx, persona, str(m.get("brain") or ""), [], _pr2, _h2, left, staged_changed=_st2)
        if choice == "canon" and not any("vale il canon:" in (c.get("body") or "") for c in issue.get("comments") or []):
            issue_comment(ctx, n, f"vale il canon: `{m.get('path')}` resta fuori finche' il contenuto non cambia; "
                                  f"{persona} vedra' la riga al prossimo rito.")
    else:
        refresh_pr_status(ctx, int(m.get("pr") or 0), str(m.get("head_sha") or ""))
    return f"#{n}: vale {choice} -> PR deciso #{pr['number']}"


def finalize_if_merged(ctx: Ctx, tx: Tx, issue: dict, m: dict) -> str | None:
    """Issue con `in-applicazione` (lock gia' acquisito): PR deciso MERGED -> chiude la issue (`travaso-deciso`) e aggiorna
    lo status aggregato (kind pr); OPEN -> riallinea/rivaluta, garantisce status e auto-merge, completa i passi mancanti;
    assente -> None (si riprepara)."""
    n = int(issue["number"])
    pr = pr_for_branch(ctx, BRANCH_DECISO.format(issue=n))
    if pr is None:
        return None
    st = str(pr.get("state")).upper()
    reg = _register_entry_on_main(ctx, n)
    choice = str(reg.get("esito") if reg else "") or _choice_from_comments(issue)
    if st == "MERGED":
        sha = str(pr.get("headRefOid") or "")
        if m.get("kind") == "travaso" and _attesa_blob(ctx, str(m.get("persona") or ""), str(m.get("dest") or "")) is not None:
            complete_decision(ctx, tx, issue, m, pr, choice)
        issue_labels(ctx, n, add=[LABEL_DECISO], remove=[LABEL_DA_DECIDERE, LABEL_IN_APPLICAZIONE])
        issue_comment(ctx, n, f"travaso-stato: applicata ({sha[:7]}) — PR #{pr['number']} fusa; decisione nel registro `{REGISTER_DIR}/{n}.yaml`.")
        issue_close(ctx, n)                                   # REST (fatto live: niente `gh issue close`)
        if m.get("kind") == "pr":
            refresh_pr_status(ctx, int(m.get("pr") or 0), str(m.get("head_sha") or ""))
        return f"#{n} applicata (PR #{pr['number']} fusa): issue chiusa"
    if st == "OPEN":
        pr = _ensure_deciso_pr(ctx, tx, n, pr, issue, m)
        if pr.get("renewed"):
            return f"#{n}: proposta rinnovata (nuova contraddizione su main), serve una nuova decisione"
        complete_decision(ctx, tx, issue, m, pr, choice)
        return f"#{n} preparata (PR #{pr['number']} in attesa dei check)"
    return None


def _register_entry_on_main(ctx: Ctx, n: int) -> dict:
    raw = show_main(ctx, f"{REGISTER_DIR}/{n}.yaml")
    if raw is None:
        return {}
    try:
        d = yaml_mod().safe_load(raw.decode("utf-8-sig", "replace"))
    except Exception:  # noqa: BLE001
        return {}
    return d if isinstance(d, dict) else {}


def _choice_from_comments(issue: dict) -> str:
    for c in reversed(issue.get("comments") or []):
        mk = re.search(r"travaso-stato: acquisita \(vale (nuovo|canon|entrambi)", c.get("body") or "")
        if mk:
            return mk.group(1)
    return ""

def apply_decisions(ctx: Ctx, tx: Tx, quiet_lines: bool = False, sblocca: int | None = None) -> list[str]:
    out: list[str] = []
    if sblocca:
        out.append(tx.sblocca(int(sblocca)))
    issues = list_issues(ctx, [LABEL_DA_DECIDERE])
    for issue in issues:
        n = int(issue["number"])
        m = machine_of(issue)
        if not m or m.get("kind") not in ("travaso", "pr"):
            continue
        if LABEL_IN_APPLICAZIONE in _labels(issue):
            # ripresa: anche lei acquisisce il lock (#8); occupato = un'altra corsa sta gia' riprendendo
            if ctx.dry:
                out.append(f"[dry-run-git] #{n}: in applicazione, nessuna mutazione")
                continue
            if not tx.acquire_lock(n, {"runner": ctx.login, "ts": time.time(), "issue": n, "ripresa": True}):
                out.append(f"#{n}: in applicazione da un'altra corsa, saltata")
                continue
            try:
                res = finalize_if_merged(ctx, tx, issue, m)
            finally:
                tx.release_lock(LOCK_REF.format(issue=n))
            if res:
                out.append(res)
                continue
        dec = read_decision(ctx, issue, m)
        if dec is None:
            continue
        choice, decider, how, version = dec
        ok, why = is_authorized(ctx, issue, m, decider)
        if not ok:
            _comment_once(ctx, issue, f"non-autorizzato-{decider}-v{version}", f"@{decider} non puo' decidere questa issue: possono {why}. Nessuna azione.")
            out.append(f"#{n}: {decider} non autorizzato")
            continue
        if str(m.get("base_sha") or "") != ctx.base_sha:                 # #7: la proposta vale per la base su cui e' stata fatta
            _comment_once(ctx, issue, f"base-cambiata-v{version}", f"La base e' cambiata dopo la proposta (main {str(m.get('base_sha'))[:7]} -> "
                                                                  f"{ctx.base_sha[:7]}): la issue sara' rigenerata al prossimo travaso/check. Nessuna azione.")
            out.append(f"#{n}: base cambiata, nessuna azione")
            continue
        persona = str(m.get("persona") or "")
        if m.get("kind") == "travaso":
            blob = _attesa_blob(ctx, persona, str(m.get("dest") or ""))
            if blob is None or sha256_bytes(blob) != str(m.get("hash_file")):
                _comment_once(ctx, issue, f"hash-diverso-v{version}", "Il file in attesa e' cambiato rispetto alla versione spuntata: "
                                                                     "la issue sara' rigenerata al prossimo travaso. Nessuna azione.")
                out.append(f"#{n}: file cambiato, nessuna azione")
                continue
        else:
            prv = ctx.gh_json("pr", "view", str(m.get("pr") or 0), "--repo", ctx.full, "--json", "headRefOid,state")
            if not prv or str(prv.get("headRefOid")) != str(m.get("head_sha")):
                _comment_once(ctx, issue, f"pr-mossa-v{version}", "La PR e' cambiata dopo la decisione (head diverso): ricontrolla con "
                                                                 f"`check --pr {m.get('pr')}`. Nessuna azione.")
                out.append(f"#{n}: PR cambiata, nessuna azione")
                continue
        if ctx.dry:
            out.append(f"[dry-run-git] #{n}: vale {choice} (da @{decider}): nessuna mutazione")
            continue
        if not tx.acquire_lock(n, {"runner": ctx.login, "ts": time.time(), "issue": n, "versione": version}):
            out.append(f"#{n}: in applicazione da un'altra corsa, saltata")
            continue
        try:
            issue_labels(ctx, n, add=[LABEL_IN_APPLICAZIONE])
            issue_comment(ctx, n, f"travaso-stato: acquisita (vale {choice}, {how} v{version} di @{decider}, runner @{ctx.login})")
            fault("dopo-acquisita")
            pr = prepare_deciso(ctx, tx, issue, m, choice, decider, how, version)
            if pr.get("renewed"):
                out.append(f"#{n}: proposta rinnovata (nuova contraddizione su main), serve una nuova decisione")
                continue
            fault("dopo-preparata")
            out.append(complete_decision(ctx, tx, issue, m, pr, choice))
        finally:
            tx.release_lock(LOCK_REF.format(issue=n))
    return out

def write_register_md(ctx: Ctx) -> Path:
    """`decisioni/TRAVASO.md` rigenerato dal registro (origin/main) nel clone: elenco leggibile, da committare col sync."""
    canon = Canon(ctx, persona="")
    lines = ["# Decisioni del travaso (registro)", "",
             f"Generato da `travaso.py decisioni --scrivi` il {kc.logical_today().isoformat()} da origin/main `{ctx.base_sha[:7]}`. "
             f"Fonte di verita': le issue `travaso-deciso` e `{REGISTER_DIR}/<issue>.yaml`.", ""]
    if not canon.register:
        lines.append("Nessuna decisione registrata.")
    for e in sorted(canon.register, key=lambda x: int(x.get("issue") or 0)):
        fatti = "; ".join(f"{f.get('chiave')}: {f.get('nuovo')} vs {f.get('canon')}" for f in (e.get("fatti") or [])[:3])
        ctxs = e.get("contesti") or {}
        extra = f" — contesti: nuovo={ctxs.get('nuovo')}; canon={ctxs.get('canon')}" if ctxs else ""
        lines.append(f"- #{e.get('issue')} ({e.get('data', '?')}) **vale {e.get('esito')}** — {e.get('persona')} `{e.get('path')}`"
                     f" — {fatti or e.get('motivo') or e.get('kind')} — deciso da @{e.get('deciso_da')} ({e.get('revisione')}), "
                     f"PR #{(e.get('applicato') or {}).get('pr', '?')}{extra}")
    p = ctx.clone / REGISTER_MD
    _check_link_inside("il clone", ctx.clone, p.parent, EXIT_DEST)
    if p.exists():
        _check_link_inside("il clone", ctx.clone, p, EXIT_DEST)
    kc.write_text(p, mask("\n".join(lines)) + "\n")
    return p

def cmd_decisioni(a) -> int:
    ctx = open_ctx(a.root, a.dry_run_git, a.quiet, a.no_ingest)
    fetch_or_defer(ctx)
    load_travaso_yaml(ctx)
    ctx.login = gh_login_strict(ctx)
    if bs.repo_permission(ctx.owner, ctx.repo, ctx.run) is not True:
        raise Stop(EXIT_DEST, f"l'account `{ctx.login}` non ha permesso di scrittura su {ctx.full}")
    tx = Tx(ctx)
    try:
        res = apply_decisions(ctx, tx, sblocca=getattr(a, "sblocca", None))
    finally:
        tx.close()
    lines = [f"Decisioni su {ctx.full}: " + ("; ".join(res) if res else "nessuna da applicare")]
    if a.scrivi:
        if ctx.dry:
            lines.append("[dry-run-git] decisioni/TRAVASO.md non scritto")
        else:
            p = write_register_md(ctx)
            lines.append(f"Registro scritto in {p.relative_to(ctx.clone).as_posix()} (committalo con brain_sync).")
    chores = post_merge_chores(ctx)
    if chores:
        lines.append("; ".join(chores))
    for ln in lines[:3]:
        print(mask(ln))
    return 0

# ---------------------------------------------------------------------------- check --pr / --staged (par. 6.6, 14.11)
def _persona_for_login(ctx: Ctx, explicit: str | None) -> str:
    if explicit:
        if explicit not in ctx.persone():
            raise Stop(EXIT_DEST, f"persona `{explicit}` non presente in travaso.yaml")
        if ctx.login_of(explicit).lower() != ctx.login.lower():
            raise Stop(EXIT_DEST, f"persona `{explicit}` ha login `{ctx.login_of(explicit)}`, ma l'account attivo e' `{ctx.login}`")
        return explicit
    mine = [p for p, v in ctx.persone().items() if str((v or {}).get("login") or "").lower() == ctx.login.lower()]
    if len(mine) == 1:
        return mine[0]
    if not mine:
        raise Stop(EXIT_DEST, f"il login `{ctx.login}` non corrisponde a nessuna persona di travaso.yaml")
    raise Stop(EXIT_DEST, f"il login `{ctx.login}` ha piu' persone ({', '.join(mine)}): --persona obbligatoria (brain.yaml travaso.persona)")


class CodeownersError(ValueError):
    pass


def _codeowners_match(pattern: str, path: str) -> bool:
    """Semantica di GitHub/gitignore (N5): `/docs/` ancorato alla radice e tutto il contenuto; `docs/` ovunque; `*` non
    attraversa `/`; `**` si'; `?` un carattere; un pattern senza `/` combacia a qualunque profondita'. Sintassi non
    supportata (`!`, `[...]`, `\\`) -> CodeownersError."""
    pat = pattern.strip()
    if not pat or pat.startswith("!") or "[" in pat or "\\" in pat:
        raise CodeownersError(pattern)
    anchored = pat.startswith("/")
    pat = pat.lstrip("/")
    dir_only = pat.endswith("/")
    pat = pat.rstrip("/")
    if not anchored and "/" not in pat:
        pat = "**/" + pat
    rx = ""
    i = 0
    while i < len(pat):
        ch = pat[i]
        if pat.startswith("**/", i):
            rx += "(?:.*/)?"
            i += 3
            continue
        if pat.startswith("**", i):
            rx += ".*"
            i += 2
            continue
        if ch == "*":
            rx += "[^/]*"
        elif ch == "?":
            rx += "[^/]"
        else:
            rx += re.escape(ch)
        i += 1
    return re.match("^" + rx + "(?:/.*)?$", path) is not None        # cio' che combacia con una cartella copre il contenuto


def _codeowner_teams(ctx: Ctx, path: str) -> list[str]:
    """Team proprietari di `path` secondo CODEOWNERS su origin/main: vince l'ULTIMA regola che combacia (come GitHub);
    nessuna regola = `direzione`. Una regola non interpretabile -> CodeownersError (N5)."""
    raw = show_main(ctx, ".github/CODEOWNERS")
    teams: list[str] = []
    if raw is None:
        return ["direzione"]
    for ln in raw.decode("utf-8", "replace").splitlines():
        parts = ln.split()
        if not parts or parts[0].startswith("#"):
            continue
        try:
            hit = _codeowners_match(parts[0], path)
        except CodeownersError as e:
            raise CodeownersError(ln.strip()) from e
        if hit:
            owners = [t.split("/", 1)[1] for t in parts[1:] if t.startswith("@") and "/" in t]
            if owners:
                teams = owners
    return teams or ["direzione"]


def _codeowner_team(ctx: Ctx, path: str) -> str:
    return _codeowner_teams(ctx, path)[0]


def _teams_label(ctx: Ctx, path: str) -> str:
    try:
        return "/".join(_codeowner_teams(ctx, path))
    except CodeownersError as e:
        return f"regola CODEOWNERS non interpretabile: {e}"

def _member_of(ctx: Ctx, login: str, team: str) -> bool:
    data = ctx.gh_json("api", f"orgs/{ctx.org}/teams/{team}/memberships/{login}")
    return bool(data) and str(data.get("state")) == "active"


def _approved_zones_from_statuses(ctx: Ctx, head: str) -> set[str]:
    """Zone protette gia' approvate su questo head (lo status precedente le elenca: GitHub non cancella gli status)."""
    data = ctx.gh_json("api", f"repos/{ctx.full}/commits/{head}/statuses")
    out: set[str] = set()
    for s in (data or []) if isinstance(data, list) else []:
        if s.get("context") != STATUS_CONTEXT:
            continue
        mk = re.search(r"approvat[ae](?: da @\S+)?: ([^;]+)", s.get("description") or "")
        if mk:
            out |= {x.strip() for x in mk.group(1).split(",") if x.strip()}
    return out


def refresh_pr_status(ctx: Ctx, pr_number: int, head: str) -> tuple[bool, str]:
    """N3: status AGGREGATO per head di una PR umana: success solo se nessuna issue aperta riguarda quel head, nessuna zona
    protetta non autorizzata, nessun path della zona del protocollo e ogni decisione presa e' gia' nel registro su main."""
    if not pr_number or not head:
        return False, ""
    pr = ctx.gh_json("pr", "view", str(pr_number), "--repo", ctx.full, "--json", "number,state,headRefOid,files,headRefName")
    if not pr or str(pr.get("headRefOid")) != head:
        return False, "PR cambiata"
    paths = [str(x.get("path")) for x in pr.get("files") or []]
    ok, desc = pr_assessment(ctx, pr_number, head, paths, approved=_approved_zones_from_statuses(ctx, head))
    post_status(ctx, head, "success" if ok else "failure", desc)
    return ok, desc


def _register_matches_proposal(reg: dict, m: dict) -> bool:
    """N3: il registro autorizza SOLO la proposta identica: issue, versione, hash_file, base_sha, head_sha, fatti."""
    if not reg or not m:
        return False
    same = (str(reg.get("issue")) == str(m.get("issue") or reg.get("issue")) and str(reg.get("versione") or "") == str(m.get("versione") or "")
            and str(reg.get("hash_file") or "") == str(m.get("hash_file") or "") and str(reg.get("base_sha") or "") == str(m.get("base_sha") or "")
            and str(reg.get("head_sha") or "") == str(m.get("head_sha") or "") and _fatti_key(reg.get("fatti")) == _fatti_key(m.get("fatti")))
    return same


def pr_assessment(ctx: Ctx, pr_number: int, head: str, paths: list[str], approved: set[str], n_facts: int = 0,
                  approver: str = "") -> tuple[bool, str]:
    reasons: list[str] = []
    protocol = [p for p in paths if p.startswith(ZONE + "/")]
    if protocol:
        reasons.append("zona del protocollo (solo il travaso scrive qui): " + ", ".join(protocol[:3]))
    protected = [p for p in paths if _is_protected(p)]
    unauthorized = [p for p in protected if p not in approved]
    if unauthorized:
        reasons.append("zona protetta non autorizzata: " + ", ".join(f"{p} (team {_teams_label(ctx, p)})" for p in unauthorized[:4])
                       + f" -> `check --pr {pr_number} --approvo` da un membro di quei team")
    open_issues = [i for i in list_issues(ctx, [LABEL_DA_DECIDERE]) if (machine_of(i) or {}).get("kind") == "pr"
                   and str((machine_of(i) or {}).get("head_sha")) == head]
    pending = [i for i in open_issues if LABEL_IN_APPLICAZIONE not in _labels(i)]
    if pending:
        reasons.append(f"{len(pending)} pezzi fermi: " + " ".join(f"#{i['number']}" for i in pending))
    decided: list[tuple[int, dict]] = [(int(i["number"]), machine_of(i) or {}) for i in open_issues if LABEL_IN_APPLICAZIONE in _labels(i)]
    for i in list_issues(ctx, [LABEL_DECISO], state="closed"):
        mm = machine_of(i) or {}
        if mm.get("kind") == "pr" and str(mm.get("head_sha")) == head:
            decided.append((int(i["number"]), mm))
    seen: set[int] = set()
    for n, mm in decided:
        if n in seen:
            continue
        seen.add(n)
        reg = _register_entry_on_main(ctx, n)
        if not reg:
            reasons.append(f"registro non integrato su main: #{n}")
            continue
        if not _register_matches_proposal(reg, mm):
            reasons.append(f"registro di #{n} non coincide con la proposta corrente (versione/hash/base/head/fatti): nuova decisione")
            continue
        if str(reg.get("esito")) == "canon":
            reasons.append(f"vale il canon per #{n}: il contenuto della PR va corretto")
    head_txt = f"zona protetta approvata da @{approver or '?'}: {', '.join(sorted(approved))}; " if approved else ""
    if reasons:
        return False, head_txt + "; ".join(reasons) + f"; base:{ctx.base_sha[:7]}"
    decided_txt = (f"decisioni integrate: {' '.join(f'#{n}' for n in sorted(seen))}; " if seen else "")
    return True, head_txt + decided_txt + status_description(True, len(paths), [], n_facts, "non verificata (brain aziendale)", ctx.base_sha)

def _is_protected(path: str) -> bool:
    return any(path == z or path.startswith(z) or (z == "CODEOWNERS" and path.endswith("CODEOWNERS")) for z in PROTECTED_ZONES)


def _canon_md_candidate(ctx: Ctx, path: str) -> bool:
    if not path.lower().endswith(".md") or path.endswith("_index.md") or kc.travaso_provenance(path) is not None:
        return False
    node, nrel = _node_for(path, ctx.nodes)
    first = nrel.split("/")[0]
    return "/" in nrel and (first in node.profile.folders or first == "decisioni")


def cmd_check(a) -> int:
    ctx = open_ctx(a.root, a.dry_run_git, a.quiet, a.no_ingest)
    fetch_or_defer(ctx)
    load_travaso_yaml(ctx)
    ctx.login = gh_login_strict(ctx)
    if bs.repo_permission(ctx.owner, ctx.repo, ctx.run) is not True:
        raise Stop(EXIT_DEST, f"l'account `{ctx.login}` non ha permesso di scrittura su {ctx.full}")
    persona = _persona_for_login(ctx, a.persona)
    ctx.persona = persona
    es = Esito(ctx, ctx.clone, persona, ctx.brain_id, "check")
    tx = Tx(ctx)
    try:
        code = _check_pr(ctx, tx, a, persona, es) if a.pr else _check_staged(ctx, tx, persona, es)
    except Stop as e:
        es.data["note"].append(e.msg)
        if not ctx.dry:
            es.write(e.code)
        raise
    finally:
        tx.close()
    if not ctx.dry:                                        # #12: in dry nessun esito su disco
        es.write(code)
    return code

def _file_persona(ctx: Ctx, path: str, text: str) -> str:
    """Autore del file per 'stessa persona = aggiornamento' (#11): provenienza del path o della nota, non il verificatore."""
    prov = kc.travaso_provenance(path)
    if prov:
        return prov[0]
    try:
        fm, _ = kc.read_frontmatter(text)
    except kc.FrontmatterError:
        return ""
    pv = fm.get("provenienza")
    if isinstance(pv, dict) and pv.get("persona"):
        return str(pv["persona"])
    src = kc.fm_str(fm.get("source"))
    mk = re.search(r"sources/travaso/([a-z0-9-]+)/", src)
    return mk.group(1) if mk else ""


def _pr_head_now(ctx: Ctx, number: int) -> str:
    view = ctx.gh_json("pr", "view", str(number), "--repo", ctx.full, "--json", "headRefOid,state")
    if not view:
        raise Stop(EXIT_DEST, f"PR #{number} non piu' leggibile")
    return str(view.get("headRefOid") or "")


def _check_pr(ctx: Ctx, tx: Tx, a, persona: str, es: Esito) -> int:
    pr = ctx.gh_json("pr", "view", str(a.pr), "--repo", ctx.full, "--json", "number,state,headRefOid,headRefName,baseRefName,url,files,title")
    if not pr:
        raise Stop(EXIT_DEST, f"PR #{a.pr} non trovata su {ctx.full}")
    if str(pr.get("state")).upper() != "OPEN":
        raise Stop(EXIT_STOP, f"PR #{a.pr} non e' aperta ({pr.get('state')})")
    branch = str(pr.get("headRefName") or "")
    if branch.startswith("travaso/"):
        raise Stop(EXIT_STOP, f"PR #{a.pr} e' una PR del travaso ({branch}): si decide con la issue da-decidere e la gestisce "
                              "`send`/`decisioni`, nessuno status da `check --pr` (N2)")
    head = str(pr.get("headRefOid") or "")
    if ctx.dry:
        ref = f"refs/remotes/origin/{branch}" if ctx.run.has_ref(f"refs/remotes/origin/{branch}") else "refs/remotes/origin/main"
    else:
        # N6: fetch OBBLIGATORIO del branch della PR; fallito = stop (mai proseguire su un ref vecchio); FETCH_HEAD = head letto
        f = ctx.run.git("fetch", "origin", "--quiet", f"+refs/heads/{branch}:refs/remotes/origin/{branch}")
        if f.returncode != 0:
            err = (f.stderr or "").lower()
            if "couldn't find remote ref" in err or "not found" in err:
                raise Stop(EXIT_DEST, f"branch della PR #{a.pr} (`{branch}`) assente su origin: {_out(f.stderr.strip(), 120)}")
            raise Stop(EXIT_DEFERRED, f"travaso rinviato: fetch del branch `{branch}` fallito (offline?): {_out(f.stderr.strip(), 120)}")
        fetched = git_out(ctx.clone, "rev-parse", f"refs/remotes/origin/{branch}")
        if fetched != head:
            raise Stop(EXIT_STOP, f"PR #{a.pr}: il branch `{branch}` e' a {fetched[:7]} ma la PR dichiara {head[:7]}: la PR si e' mossa, rilancia")
        ref = f"refs/remotes/origin/{branch}"
    paths = [str(x.get("path")) for x in pr.get("files") or []]
    protected = [p for p in paths if _is_protected(p)]
    canon = Canon(ctx, "")
    fermi: list[Fermo] = []
    n_facts = 0
    for p in paths:
        if not _canon_md_candidate(ctx, p):
            continue
        raw = show_main(ctx, p, ref)
        if raw is None:
            continue                                       # cancellato nella PR
        text = repo_check.decode_text(raw)
        if text is None:
            continue
        inc, ann, excl, nf = canon.check_text(p, text, _file_persona(ctx, p, text), sha256_bytes(raw))
        n_facts += nf
        es.data["note"] += [f"{p}: {x}" for x in ann]
        if excl is not None:
            inc = inc + [Incongruenza(p, "decisione", "contenuto", "contenuto corrente", f"decisione #{excl}", f"vale il canon (#{excl})",
                                      "canon", "", f"{REGISTER_DIR}/{excl}.yaml", "?", excl, "decisione")]
        if inc:
            fermi.append(Fermo(p, p, raw, sha256_bytes(raw), inc, kind="pr", head_sha=head, pr_number=int(pr["number"])))
    approved = _approved_zones_from_statuses(ctx, head)
    approver = ""
    if protected and a.approvo:
        # N5: chi approva deve appartenere al team code owner di OGNI zona protetta della PR (CODEOWNERS come GitHub)
        try:
            owners = {p: _codeowner_teams(ctx, p) for p in protected}
        except CodeownersError as e:
            raise Stop(EXIT_DEST, f"--approvo rifiutato: regola CODEOWNERS non interpretabile: {e}")
        covered = [p for p in protected if any(_member_of(ctx, ctx.login, t) for t in owners[p])]
        if not covered:
            zones = ", ".join(f"{p} (team {'/'.join(owners[p])})" for p in protected[:4])
            raise Stop(EXIT_DEST, f"--approvo: `{ctx.login}` non e' membro attivo di nessun team code owner delle zone protette "
                                  f"({zones}): nessuno status")
        if len(covered) == len(protected):
            approved |= set(protected)
            approver = ctx.login
        else:
            es.data["note"].append(f"--approvo di {ctx.login} insufficiente: copre {len(covered)}/{len(protected)} zone protette")
    if fermi and not ctx.dry:
        upsert_issues(ctx, fermi, persona, ctx.brain_id, str(pr.get("url") or ""))
    es.data["fermi"] = [{"path": f.src_rel, "issue": f.issue, "motivi": [_motivo(i) for i in f.incongruenze]} for f in fermi]
    es.data["copertura"] = {"fatti": n_facts, "semantica": "non verificata (controllo del brain aziendale)", "binari_non_scansionati": 0}
    ok, desc = pr_assessment(ctx, int(pr["number"]), head, paths, approved, n_facts, approver or (ctx.login if approved else ""))
    if not ctx.dry:
        fault("prima-dello-status", str(ctx.clone))
        now = _pr_head_now(ctx, int(pr["number"]))          # N6: status SOLO sullo sha ricontrollato un istante prima
        if now != head:
            raise Stop(EXIT_STOP, f"PR #{a.pr}: la PR si e' mossa ({head[:7]} -> {now[:7]}) prima dello status: nessuno status, rilancia")
    post_status(ctx, head, "success" if ok else "failure", desc)
    if ok:
        line = f"PR #{a.pr}: status coerenza SUCCESS su {head[:7]} ({len(paths)} file; fatti: {n_facts})"
    else:
        line = f"PR #{a.pr}: status coerenza FAILURE — {desc}"
        if fermi:
            line = f"PR #{a.pr}: status coerenza FAILURE — {len(fermi)} file con incongruenze: " + ", ".join(f"{f.src_rel} → #{f.issue}" for f in fermi) + f"; {desc}"
    es.emit([line])
    return 0

def _check_staged(ctx: Ctx, tx: Tx, persona: str, es: Esito) -> int:
    r = git(ctx.clone, "diff", "--cached", "--name-only", "--diff-filter=AM", "-z")
    staged = [x.decode("utf-8", "replace") for x in r.stdout.split(b"\0") if x]
    canon = Canon(ctx, "")
    fermi: list[Fermo] = []
    n_facts = 0
    for p in staged:
        if p.startswith(ZONE + "/"):
            rr = git(ctx.clone, "show", f":{p}")
            fermi.append(Fermo(p, p, rr.stdout, sha256_bytes(rr.stdout), [Incongruenza(p, "zona del protocollo", "scrittura a mano", "scrittura a mano",
                                                                                      "solo il travaso", "solo il travaso scrive in sources/travaso/", "canon", "", p, "?", None, "protocollo")]))
            continue
        if not _canon_md_candidate(ctx, p):
            continue
        rr = git(ctx.clone, "show", f":{p}")
        if rr.returncode != 0:
            continue
        text = repo_check.decode_text(rr.stdout)
        if text is None:
            continue
        inc, ann, excl, nf = canon.check_text(p, text, _file_persona(ctx, p, text) or persona, sha256_bytes(rr.stdout))
        n_facts += nf
        es.data["note"] += [f"{p}: {x}" for x in ann]
        if excl is not None:
            inc = inc + [Incongruenza(p, "decisione", "contenuto", "contenuto corrente", f"decisione #{excl}", f"vale il canon (#{excl})",
                                      "canon", "", f"{REGISTER_DIR}/{excl}.yaml", "?", excl, "decisione")]
        if inc:
            fermi.append(Fermo(p, p, rr.stdout, sha256_bytes(rr.stdout), inc))
    es.data["copertura"] = {"fatti": n_facts, "semantica": "non verificata (controllo del brain aziendale)", "binari_non_scansionati": 0}
    if not fermi:
        es.emit([f"check --staged ({persona}): {len(staged)} file in staging, fatti: {n_facts}, nessuna incongruenza."])
        return 0
    if ctx.dry:
        es.emit([f"[dry-run-git] check --staged: {len(fermi)} file incongruenti resterebbero fuori dal commit: " + ", ".join(f.src_rel for f in fermi)])
        return 0
    for f in fermi:
        git(ctx.clone, "restore", "--staged", "--", f.src_rel)
    fault("dopo-restore-staged", str(ctx.clone))
    still = [x.decode("utf-8", "replace") for x in git(ctx.clone, "diff", "--cached", "--name-only", "-z").stdout.split(b"\0") if x]
    left = [f.src_rel for f in fermi if f.src_rel in still]
    if left:                                              # #11: i fermi devono essere DAVVERO fuori dallo staging
        raise Stop(EXIT_STOP, f"file incongruenti ancora in staging dopo il ritiro ({', '.join(left[:3])}): nessun commit, "
                              "svuota lo staging e rilancia")
    pr_att, head_att, in_attesa, att_staged = rebuild_attesa(ctx, tx, persona, {f.dest: f.data for f in fermi},
                                                             {f.dest: f.sha256 for f in fermi}, set(), None)
    if in_attesa:
        attesa_status_and_issues(ctx, tx, persona, ctx.brain_id, fermi, pr_att, head_att, in_attesa, staged_changed=att_staged)
    es.data["fermi"] = [{"path": f.src_rel, "issue": f.issue, "assegnatario": f.assignee,
                         "motivi": [_motivo(i) for i in f.incongruenze]} for f in fermi]
    first = fermo_sentence(fermi[0], "tu")
    es.emit([f"check --staged ({persona}): {len(fermi)} file tolti dallo staging e messi in attesa (travaso/attesa/{persona}); "
             f"gli altri {len(staged) - len(fermi)} procedono. fatti: {n_facts}",
             f"{len(fermi)} {'pezzo fermo' if len(fermi) == 1 else 'pezzi fermi'}: {first}" + (f" (+{len(fermi) - 1} altri)" if len(fermi) > 1 else "")])
    return 0

# ---------------------------------------------------------------------------- stato, verifica, init (par. 8.4, 14.1, 14.4, 14.17)
def _pending_packages(from_root: Path, owner: str, repo: str) -> list[Path]:
    base = from_root / kc.TRAVASO_WORKSPACE / f"{owner}-{repo}"
    if not base.is_dir():
        return []
    return sorted(d for d in base.iterdir() if d.is_dir() and (d / "verifica.json").is_file() and not (d / "verdetto.json").is_file())


def cmd_stato(a) -> int:
    ctx = open_ctx(a.root, False, a.quiet)
    lines: list[str] = []
    from_root = Path(a.from_).resolve() if a.from_ else None
    persona = a.persona or ""
    if from_root is not None:
        base = from_root / kc.TRAVASO_WORKSPACE / f"{ctx.owner}-{ctx.repo}"
        esiti = sorted(base.glob("*.json")) if base.is_dir() else []
        if esiti:
            try:
                d = json.loads(esiti[-1].read_text(encoding="utf-8-sig"))
                pa = d.get("pr_auto") or {}
                lines.append(f"Ultimo travaso {d.get('quando', '?')} (exit {d.get('exit')}): {len(d.get('inviati') or [])} inviati"
                             + (f" (PR #{pa.get('number')})" if pa else "") + f", {len(d.get('fermi') or [])} fermi, "
                             f"{len(d.get('da_verificare') or [])} da verificare, {len(d.get('esclusi') or [])} esclusi.")
            except ValueError:
                lines.append(f"Ultimo esito illeggibile: {esiti[-1].name}")
        else:
            lines.append("Nessun travaso ancora eseguito da questo brain.")
        pend = _pending_packages(from_root, ctx.owner, ctx.repo)
        if pend:
            lines[-1] += " Da verificare: " + ", ".join(p.name for p in pend) + " (`<id>-travaso verifica`)."
    online = ctx.run.git("fetch", "origin", "--quiet").returncode == 0 if not a.offline else False
    if online:
        try:
            load_travaso_yaml(ctx)
        except Stop as e:
            lines.append(f"travaso.yaml: {e.msg}")
        if persona:
            pa = pr_for_branch(ctx, BRANCH_AUTO.format(persona=persona))
            pt = pr_for_branch(ctx, BRANCH_ATTESA.format(persona=persona))
            prs = []
            if pa and str(pa.get("state")).upper() == "OPEN":
                prs.append(f"PR auto #{pa['number']} aperta (merge automatico quando brain-check e' verde)")
            if pt and str(pt.get("state")).upper() == "OPEN":
                prs.append(f"PR attesa #{pt['number']} aperta")
            lines.append("; ".join(prs) if prs else "Nessuna PR di travaso aperta.")
            issues = list_issues(ctx, [LABEL_DA_DECIDERE, f"persona/{persona}"])
            if issues:
                lines.append(f"{len(issues)} pezzi fermi: " + "; ".join(
                    f"#{i['number']} {i['title']} → @{','.join(str(x.get('login')) for x in i.get('assignees') or []) or '?'}" for i in issues[:4]))
            canon = Canon(ctx, persona)
            mine = [e for e in canon.register if str(e.get("persona")) == persona]
            if mine:
                lines.append("Decisioni sulle tue note: " + "; ".join(f"#{e.get('issue')} vale {e.get('esito')} ({e.get('path')})" for e in mine[-3:]))
    else:
        lines.append("Offline (git fetch fallito): stato di GitHub non disponibile.")
    if a.da_compilare:
        lines += _da_compilare(ctx)
    for ln in lines[: (3 if a.quiet else 8)]:
        print(mask(ln))
    return 0


def _da_compilare(ctx: Ctx) -> list[str]:
    """Fonti travasate (sul clone) da compilare (par. 14.17, #17): mai citate con `source:`; citate con impronta
    `provenienza.sha` diversa dallo sha256 del raw (anche prefisso); citate SENZA impronta = "impronta assente: da compilare"
    (nessun ripiego per data)."""
    cited: dict[str, list[tuple[str, str]]] = {}
    for n in ctx.nodes:
        for p in kc.iter_notes(n, ctx.nodes):
            try:
                fm, _ = kc.read_frontmatter(p)
            except (kc.FrontmatterError, OSError):
                continue
            pv = fm.get("provenienza") if isinstance(fm.get("provenienza"), dict) else {}
            for s in (x.strip() for x in kc.fm_str(fm.get("source")).split(";") if x.strip()):
                if s.startswith(ZONE + "/"):
                    cited.setdefault(s, []).append((n.rel_root(p), kc.fm_str(pv.get("sha"))))
    todo: list[str] = []
    for p in kc.iter_travaso_files(ctx.clone):
        rel = p.relative_to(ctx.clone).as_posix()
        if rel.endswith("/README.md"):
            continue
        sha = sha256_bytes(p.read_bytes())
        notes = cited.get(rel)
        if not notes:
            todo.append(f"{rel} (mai compilata; sha {sha[:12]})")
            continue
        stale = [nota for nota, fp in notes if fp and not sha.startswith(fp.lower())]
        missing = [nota for nota, fp in notes if not fp]
        if stale:
            todo.append(f"{rel} (cambiata: sha {sha[:12]}; note da aggiornare: {', '.join(stale)})")
        elif missing:
            todo.append(f"{rel} (impronta assente: da compilare con provenienza.sha {sha[:12]} in {', '.join(missing)})")
    return [f"Da compilare ({len(todo)}): " + ("; ".join(todo[:6]) + (" ..." if len(todo) > 6 else "") if todo else "niente")]

def cmd_verifica(a) -> int:
    if not a.from_:
        print("verifica: serve --from <radice del brain personale> (brain_sync lo passa da solo)")
        return EXIT_CONFIG
    from_root = Path(a.from_).resolve()
    owner, repo = "", ""
    cfg = kc.travaso_config(from_root)
    if cfg.get("owner") and cfg.get("repo"):
        owner, repo = cfg["owner"], cfg["repo"]
    else:
        try:
            ctx = open_ctx(a.root, False, True)
            owner, repo = ctx.owner, ctx.repo
        except Stop as e:
            print(mask(e.msg))
            return e.code
    pend = _pending_packages(from_root, owner, repo)
    if a.review_id:
        pend = [p for p in pend if p.name == a.review_id] or [package_dir(from_root, owner, repo, a.review_id)]
    if not pend or not (pend[0] / "verifica.json").is_file():
        print(f"Nessun pacchetto da verificare in {kc.TRAVASO_WORKSPACE}/{owner}-{repo}/ (l'ultimo send non ha lasciato file da verificare).")
        return 0
    d = pend[-1]
    try:
        pkg = json.loads((d / "verifica.json").read_text(encoding="utf-8-sig"))
    except ValueError:
        print(f"Pacchetto illeggibile: {d}")
        return EXIT_CONFIG
    files = list((pkg.get("files") or {}).keys())
    rel = d.relative_to(from_root).as_posix()
    print(f"Da verificare: review_id {d.name}, {len(files)} file, base {str(pkg.get('base_sha'))[:7]}: leggi {rel}/verifica.md (SOLO quello, mai il clone).")
    print("Scrivi " + rel + "/verdetto.json: {\"review_id\": \"" + d.name + "\", \"files\": {\"<path>\": {\"esito\": \"coerente\"} | "
          "{\"esito\": \"incongruente\", \"soggetto\": ..., \"chiave\": ..., \"nuovo\": ..., \"canon\": ..., \"fonte_canon\": ..., \"motivo\": ...} | "
          "{\"esito\": \"non-verificabile\", \"motivo\": ...}}}")
    print(f"Poi: brain_sync.py --travaso send --verdetto {d.name}   (file: {', '.join(files[:6])}{' ...' if len(files) > 6 else ''})")
    return 0


def cmd_init(a) -> int:
    root = Path(a.brain_root).resolve()
    clone = Path(a.clone).resolve()
    if not root.is_dir() or not git_ok(root, "rev-parse", "--show-toplevel"):
        print(f"init: --brain-root {root} non e' un repository git")
        return EXIT_CONFIG
    if not (clone / "scripts" / "travaso.py").is_file():
        print(f"init: --clone {clone} non contiene scripts/travaso.py (clona il brain aziendale)")
        return EXIT_CONFIG
    for v, what in ((a.persona, "--persona"), (a.brain, "--brain")):
        if not kc.TRAVASO_ID_RE.match(v or ""):
            print(f"init: {what} `{v}` non valido ({kc.TRAVASO_ID_RE.pattern})")
            return EXIT_CONFIG
    tdir = root / ".travaso"
    tdir.mkdir(exist_ok=True)
    ty = {}
    raw = show_main(Ctx(clone=clone, run=bs.Runner(clone)), "travaso.yaml", "HEAD")
    if raw:
        try:
            ty = yaml_mod().safe_load(raw.decode("utf-8-sig", "replace")) or {}
        except Exception:  # noqa: BLE001
            ty = {}
    owner, repo = str(ty.get("org") or ""), str(ty.get("repo") or "")
    if not owner:
        parsed = bs.parse_github(bs.remote_owner(clone)[1])
        owner, repo = parsed if parsed else ("", "")
    kc.write_text(tdir / "config.yaml", f"# travaso del brain {a.brain} (non kit): scritto da travaso.py init, gitignorato, path di macchina\n"
                                        f"owner: {owner}\nrepo: {repo}\nclone: \"{clone.as_posix()}\"\npersona: {a.persona}\n"
                                        f"brain: {a.brain}\npython: \"{Path(sys.executable).as_posix()}\"\n")
    shutil.copyfile(Path(__file__).resolve().parent / "travaso_rito.py", tdir / "rito.py")
    gi = root / ".gitignore"
    cur = gi.read_text(encoding="utf-8-sig") if gi.is_file() else ""
    add = [ln for ln in (".travaso/", "workspace/travaso/") if ln not in cur.splitlines()]
    if add:
        with open(gi, "a", encoding="utf-8", newline="\n") as f:
            f.write(("" if cur.endswith("\n") or not cur else "\n") + "\n".join(add) + "\n")
    print(f"Travaso configurato per {a.persona} (brain {a.brain}) verso {owner}/{repo}.")
    print(f"Aggiungi al rito del brain la riga:  {Path(sys.executable).as_posix()} {(tdir / 'rito.py').as_posix()}")
    print(f"Config in {tdir.as_posix()}/config.yaml (gitignorata); esiti in workspace/travaso/ (gitignorata).")
    return 0


# ---------------------------------------------------------------------------- main
def main(argv: list[str] | None = None) -> int:
    global QUIET
    kc.utf8_stdout()
    ap = argparse.ArgumentParser(description="Travaso automatico nel brain aziendale (Brain Builder v3.3).")
    sub = ap.add_subparsers(dest="cmd")

    def common(p, root=True):
        if root:
            p.add_argument("--root", default=None, help="clone del brain aziendale (default: la radice di questo motore)")
        p.add_argument("--quiet", action="store_true", help="solo le 1-3 righe di esito")
        p.add_argument("--dry-run-git", action="store_true", help="nessuna mutazione: niente push, status, issue, decisioni")
        p.add_argument("--no-ingest", action="store_true", help="salta l'ingest della zona travaso nel clone")

    s = sub.add_parser("send", help="travasa il brain personale (default)")
    common(s)
    s.add_argument("--from", dest="from_", required=True, help="radice del brain personale (repo git)")
    s.add_argument("--persona", required=True)
    s.add_argument("--brain", default=None, help="brain_id della sorgente (obbligatorio per i brain non kit)")
    s.add_argument("--verdetto", default=None, help="review_id del pacchetto verificato dall'agente")
    s.add_argument("--ferma", action="append", default=[], help="path (relativo alla sorgente) da fermare in piu'")
    s.add_argument("--motivo", action="append", default=[], help="motivo del --ferma corrispondente")
    s.add_argument("--conferma-cancellazioni", action="store_true")
    c = sub.add_parser("check", help="controllo di coerenza di una PR o dello staging del brain aziendale")
    common(c)
    g = c.add_mutually_exclusive_group(required=True)
    g.add_argument("--pr", type=int)
    g.add_argument("--staged", action="store_true")
    c.add_argument("--approvo", action="store_true", help="zona protetta: approva come membro del team code owner")
    c.add_argument("--persona", default=None)
    d = sub.add_parser("decisioni", help="applica le decisioni prese nelle issue da-decidere")
    common(d)
    d.add_argument("--scrivi", action="store_true", help="rigenera decisioni/TRAVASO.md dal registro")
    d.add_argument("--sblocca", type=int, default=None, help="issue il cui lock stantio va tolto a mano (processo morto), poi applica")
    st = sub.add_parser("stato", help="ultimo travaso, PR aperte, pezzi fermi, decisioni")
    common(st)
    st.add_argument("--from", dest="from_", default=None)
    st.add_argument("--persona", default=None)
    st.add_argument("--da-compilare", action="store_true")
    st.add_argument("--offline", action="store_true")
    v = sub.add_parser("verifica", help="pacchetti di verifica in attesa dell'agente")
    common(v)
    v.add_argument("--from", dest="from_", default=None)
    v.add_argument("--review-id", default=None)
    i = sub.add_parser("init", help="configura un brain NON kit (.travaso/config.yaml + rito.py)")
    i.add_argument("--brain-root", required=True)
    i.add_argument("--clone", required=True)
    i.add_argument("--persona", required=True)
    i.add_argument("--brain", required=True)
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return EXIT_CONFIG
    QUIET = bool(getattr(a, "quiet", False))
    if getattr(a, "ferma", None) and len(a.ferma) != len(a.motivo):
        print("ERRORE: ogni --ferma vuole il suo --motivo")
        return EXIT_CONFIG
    try:
        if a.cmd == "send":
            return cmd_send(a)
        if a.cmd == "check":
            return cmd_check(a)
        if a.cmd == "decisioni":
            return cmd_decisioni(a)
        if a.cmd == "stato":
            return cmd_stato(a)
        if a.cmd == "verifica":
            return cmd_verifica(a)
        if a.cmd == "init":
            return cmd_init(a)
    except Stop as e:
        label = {EXIT_CONFIG: "ERRORE configurazione", EXIT_STOP: "STOP", EXIT_REFUSED: "RIFIUTATO", EXIT_DEST: "DESTINAZIONE O IDENTITA' NON VALIDA",
                 EXIT_DELETIONS: "CANCELLAZIONI DA CONFERMARE", EXIT_DEFERRED: "TRAVASO RINVIATO", EXIT_VERIFY: "DA VERIFICARE"}.get(e.code, "ERRORE")
        print(mask(f"{label} (exit {e.code}): {e.msg}"))
        return e.code
    except kc.ConfigError as e:
        print(mask(f"ERRORE configurazione (exit {EXIT_CONFIG}): {e}"))
        return EXIT_CONFIG
    return EXIT_CONFIG


if __name__ == "__main__":
    sys.exit(main())
