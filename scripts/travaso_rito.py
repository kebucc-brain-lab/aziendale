"""travaso_rito -- lanciatore del travaso per i brain NON kit (Brain Builder v3.3, SPEC v3.3 par. 8.3 e 14.4).

Lo copia `travaso.py init` in `<radice del brain>/.travaso/rito.py` (cartella gitignorata) insieme a `config.yaml`
(owner, repo, clone, persona, brain, python). Il rito del brain personale aggiunge UNA riga, senza path del clone:

    <python> <radice>/.travaso/rito.py [altri argomenti di `travaso.py send`]

Questo file legge `config.yaml` accanto a se' e lancia `<clone>/scripts/travaso.py send --from <radice> --persona <p>
--brain <id>` con il python corrente: le regole restano quelle del brain aziendale, mai copiate qui. Nessun path di
macchina in questo file: stanno tutti in `config.yaml`, che non viaggia.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def _read_config(p: Path) -> dict:
    """Mappa piatta `chiave: valore` (una per riga); senza dipendenze: il brain non kit puo' non avere PyYAML."""
    out: dict[str, str] = {}
    for raw in p.read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, _, v = line.partition(":")
        v = v.strip()
        if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
            v = v[1:-1]
        out[k.strip()] = v
    return out


def main(argv: list[str] | None = None) -> int:
    here = Path(__file__).resolve().parent
    cfg_p = here / "config.yaml"
    if not cfg_p.is_file():
        print(f"TRAVASO NON CONFIGURATO: manca {cfg_p} (rilancia `travaso.py init --brain-root <radice> --clone <clone> "
              "--persona <p> --brain <id>` dal clone del brain aziendale)")
        return 3
    cfg = _read_config(cfg_p)
    clone = Path(cfg.get("clone", "")).expanduser()
    script = clone / "scripts" / "travaso.py"
    if not clone.is_dir() or not script.is_file():
        print(f"TRAVASO NON CONFIGURATO: clone aziendale assente o senza scripts/travaso.py ({clone}): clona il brain "
              "aziendale e rilancia `travaso.py init`")
        return 3
    root = here.parent
    cmd = [sys.executable, str(script), "send", "--from", str(root), "--persona", cfg.get("persona", ""),
           "--brain", cfg.get("brain", ""), *(argv if argv is not None else sys.argv[1:])]
    env = {k: v for k, v in os.environ.items() if k not in ("BRAIN_ROOT", "BRAIN_ID", "BRAIN_NODE")}
    env["PYTHONUTF8"] = "1"
    return subprocess.run(cmd, cwd=str(clone), env=env).returncode


if __name__ == "__main__":
    sys.exit(main())
