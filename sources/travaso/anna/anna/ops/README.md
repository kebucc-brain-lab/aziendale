# ops/ -- lavoro operativo del brain `anna` (nodo `.`)

Qui vive il lavoro in corso: progetti, script, piani, ricerche, consegne. Non e' il vault: le note compilate
stanno nelle cartelle del profilo. La sentinella di fine turno osserva questa cartella e segnala cio' che non
e' ancora nel vault (`anna-feed` lo compila con la fonte).

## Mappa

| Cartella | Cosa contiene |
|---|---|
| `Projects/<p>/` | un progetto per cartella, col suo `CLAUDE.md` (stato) e, quando serve, `HISTORY.md` |
| `Scripts/` | script di lavoro (non il motore del brain, che sta in `scripts/` alla radice) |
| `assets/` | immagini e materiali di supporto (la sentinella li salta) |
| `piani/` | piani di lavoro |
| `brainstorms/` | brainstorm e sessioni di idee |
| `research/` | ricerche e confronti |
| `adr/` | decisioni architetturali (ADR), una per file |
| `deliverables/` | consegne (documenti finali, offerte, presentazioni) |

## Regole

1. Ogni progetto ha `Projects/<p>/CLAUDE.md`: e' l'**unica fonte di verita' sullo stato** del progetto (si
   carica da solo quando l'agente lavora in quella cartella). Le altre copie (questo README, le note del vault,
   la memoria) lo citano e non lo contraddicono.
2. `HISTORY.md` accanto al `CLAUDE.md` quando le iterazioni si accumulano: si legge su richiesta, non sempre.
3. Le ADR stanno in `ops/adr/`, non in `docs/` (che e' una cartella compilata del vault).
4. Niente repo git annidati: il codice vero ha un repo a se' fuori dal brain; in `Projects/<p>/` resta il
   `CLAUDE.md` con lo stato e i puntatori (URL del repo, cartella locale).
5. Fuori da git cio' che e' grande, rigenerabile, privato o di terzi. Video, audio, archivi ed eseguibili mai
   (anche il `.gitignore` li esclude qui); pdf, immagini e file Office fino a 5 MB; ogni file fino a 10 MB.
   Cartelle rigenerabili (`node_modules/`, `.next/`, `dist/`, `build/`, `logs/`, `tmp/`, cache) gia' escluse.
   Su GitHub il limite dei 5 MB e' garantito dal check obbligatorio `brain-check` (`repo_check --tracked`) dove c'e' un
   ruleset, non dal push ruleset (che arriva a 10 MB).
6. Dati personali e materiale di terzi: nessun rilevatore automatico. Si escludono uno per uno nel `.gitignore`
   del brain, con una riga di motivo sopra ogni regola (es. `# contratto del cliente: riservato`).

## Commit di ops/ (separato dal vault)

`anna-sync` non committa mai `ops/`. Si committa a parte, solo i path indicati, senza lint ne' ingest:
`scripts/brain_sync.py --ops <path> [<path> ...] [-m "msg"]` col python del venv (commit `ops: <msg>`); il push e'
quello del sync (`personal` per permesso su main, `org` branch `sync/...` + PR). Un path fuori da `ops/` = exit 3.
