## Cosa cambia

<!-- Per chi usa il brain: quali note, regole o file cambiano. -->

## Perche'

<!-- La ragione (fonte, decisione, richiesta). Se chiude una segnalazione scrivi `Closes #n` (in inglese, mai "Chiude"). -->

## Come si verifica

<!-- Comandi o passi: lint verde (`brain-check`), note aperte, link controllati. -->

## Rischio

<!-- Cosa potrebbe rompersi e per chi. Basso / medio / alto. -->

### Le cinque domande prima della review

- [ ] Le note nuove hanno una fonte (`source:`) e nessun numero inventato?
- [ ] Niente `.env`, `.secrets/`, segreti, video/audio/archivi, pdf o immagini oltre 5 MB (l'originale sta fuori dal repo)?
- [ ] I link fra brain sono URL GitHub completi?
- [ ] Il branch nomina il lavoro, non la persona (o e' un `sync/` di brain_sync, o un `travaso/` del travaso)?
- [ ] I check `brain-check` e `coerenza` sono verdi e il branch e' aggiornato con main (merge a coerenza: nessuna approvazione umana; zona protetta = `check --pr <n> --approvo`)?
