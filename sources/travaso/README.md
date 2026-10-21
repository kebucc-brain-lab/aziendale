# Zona travaso del brain aziendale (https://github.com/kebucc-brain-lab/aziendale)

Qui arriva, da solo, il lavoro dei brain personali: `sources/travaso/<persona>/<brain>/<path originale>` e' la copia GREZZA
(byte-identica) di cio' che ogni persona ha nel suo brain, portata dal rito del suo brain (`travaso.py send`) con la PR
`travaso/auto/<persona>` a merge automatico quando i check `brain-check` e `coerenza` sono verdi. I pezzi incongruenti con il
canon restano nella PR `travaso/attesa/<persona>` (label `da-decidere`, UNA issue per file) finche' il responsabile dell'area
non decide; la decisione arriva qui con la PR `travaso/deciso/<issue>`.

- **Non modificare a mano: lo fa il travaso.** Una modifica qui verrebbe sovrascritta dalla riconciliazione successiva.
- Chi scrive cosa: ogni persona SOLO nella propria cartella `<persona>/`; il `README.md` di ogni `<persona>/<brain>/` lo
  scrive il primo travaso (persona, area, brain, login, data). Provenienza di un file = path + commit (trailer `Travaso-*`) + PR.
- Zona grezza (non lintata) ma ingerita nel RAG di questo brain (`zone: travaso`, con persona e brain) e inclusa in
  `brain.py ask --exact`: il brain risponde subito con il materiale travasato, la compilazione nel canon arriva dopo.
- La compilazione nel canon la fa il rito `aziendale-sync` (canon prima, hub prima): le note compilate portano
  `source: sources/travaso/<persona>/<brain>/<nota>` e `provenienza: {persona, area, brain, data}`; se due fonti si
  contraddicono si chiede quale vale, non si sceglie da soli.
- Persone, aree, responsabili e policy di verifica: `travaso.yaml` alla radice (derivato da org.yaml). Decisioni gia' prese:
  `decisioni/travaso/<issue>.yaml` e `decisioni/TRAVASO.md`.
