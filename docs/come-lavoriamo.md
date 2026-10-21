---
title: "Come lavoriamo"
summary: "Regola 1: su main non si scrive mai. Flusso issue, branch, PR, check e review (o coerenza), squash."
tags: [docs, type/asset, status/active]
status: active
created: 2026-10-21
updated: 2026-10-21
related: ""
---

# Come lavoriamo sul brain aziendale

**Regola 1: su `main` non si scrive mai.** Ogni modifica passa da una pull request con i due check obbligatori verdi (`brain-check` e `coerenza`) e il branch aggiornato con `main`: nessuna approvazione umana, vedi *Brain a coerenza* (ruleset
`main-protetto`, bypass vuota: vale anche per gli owner e per gli agenti).

## Flusso

1. **Issue** con il template "Segnalazione" (cosa succede, cosa dovrebbe succedere, impatto).
2. **Branch** dal `main` aggiornato (`git fetch` + `git status -sb` prima di crearlo): nome in kebab-case che
   descrive il lavoro, non la persona. `brain_sync` usa da solo i branch `sync/<giorno>-<login>`; il travaso i branch
   `travaso/auto/<persona>`, `travaso/attesa/<persona>`, `travaso/deciso/<issue>`.
3. **PR** verso `main` con il template (Cosa cambia / Perche' / Come si verifica / Rischio; `Closes #n`).
4. **Check**: `brain-check` (GitHub Actions) e `coerenza` (controllo applicativo di `travaso.py`) verdi e branch aggiornato con `main`; nessuna approvazione umana. Una PR che tocca una zona protetta passa con `travaso.py check --pr <n> --approvo` di un membro del team code owner.
5. **Squash and merge** (unico metodo ammesso); il branch si cancella da solo.

## Con brain_sync

`brain_sync.py` in modalita' `org` committa sul branch `sync/<giorno>-<login>`, lo pusha, apre la PR e si
ferma. Se la PR e' aperta i giri successivi la aggiornano; dopo il merge riparte da `main`.

## Regole per chi usa un agente

- Mostra il diff e aspetta l'ok prima del push; sui conflitti ti fermi e mostri i marcatori.
- Mai reset o force push su branch condivisi: si annulla con `git revert`.
- Se qualcosa fallisce ci si ferma e si spiega; si verifica sul server (`gh pr view`, `git ls-remote`).

## Brain a coerenza

Questo brain fonde le PR con `merge: coerenza` (Brain Builder v3.3). La regola 1 non cambia: su `main` non si scrive mai e
ogni modifica passa da una PR. Cambia chi la approva: nessuna persona. Il ruleset `main-protetto` chiede **0 approvazioni** e
**due check obbligatori**: `brain-check` (GitHub Actions) e `coerenza` (controllo applicativo sui fatti strutturati piu' il
verdetto dell'agente di chi manda, postato come status da `travaso.py`), con il **branch aggiornato con `main`** (strict:
se `main` avanza, il controllo va rifatto sulla base nuova); poi **auto-merge squash**. Bypass vuota: vale anche per gli
owner e per gli agenti.

- `required_review_thread_resolution` riguarda i thread di una review formale rimasti aperti: un commento generico in una PR
  non ferma il merge; una conversazione di review va risolta.
- Travaso: la PR `travaso/auto/<persona>` entra da sola; i pezzi incongruenti stanno nella PR `travaso/attesa/<persona>`
  (label `da-decidere`) con UNA issue per file fermo, assegnata al responsabile dell'area del canon contraddetto
  (`travaso.yaml`; `responsabile_default` solo se l'area e' davvero ignota).
- Decidere una issue `da-decidere`: spunta UNA casella nel corpo (`vale il nuovo` / `vale il canon` / `valgono entrambi`)
  oppure commenta `vale: nuovo|canon|entrambi` citando la versione. Possono decidere l'assegnatario, il team dell'area o
  `direzione`. Il file in attesa non deve cambiare nel frattempo: se cambia, la issue si rigenera (caselle vuote, versione +1)
  e va ridecisa. La decisione si applica al rito successivo (`brain_sync.py --travaso decisioni`): PR `travaso/deciso/<issue>`,
  registro `decisioni/travaso/<issue>.yaml`, issue chiusa con `travaso-deciso` quando quella PR risulta fusa.
- PR non create dal travaso (il sync di questo brain, una PR a mano): lo status `coerenza` lo posta `travaso.py check`
  (`--staged` prima del commit del sync, `--pr <n>` per una PR altrui). Le zone protette (`.github/`, `scripts/`, `docs/`,
  `TEAM.md`, `SECURITY.md`, `travaso.yaml`, `brain.config.yaml`, CODEOWNERS) restano ferme finche' un membro del team code
  owner non esegue `check --pr <n> --approvo`: autorizza SOLO la zona protetta, non le incongruenze di contenuto.
- `travaso.yaml` (persone, aree, responsabili, `verifica_semantica`) e' derivato da `org.yaml`: lo riallinea
  `github_org.py apply` e si committa con `brain_sync` (zona protetta).
