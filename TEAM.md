# Team del brain aziendale

Chi lavora su questo brain (https://github.com/kebucc-brain-lab/aziendale) e cosa gli serve davvero. Da qui si ricavano team e permessi in
`org.yaml`; i permessi si danno SOLO ai team (mai a persone), e si applicano con `github_org.py apply` dopo
la conferma di chi risponde del brain.

| Persona | Ruolo | Cosa serve davvero |
|---|---|---|
| (da compilare) | | |

## Zone e responsabili

Le zone protette (`.github/`, `scripts/`, `docs/`, `TEAM.md`, `SECURITY.md`, `travaso.yaml`, `brain.config.yaml`) e i team responsabili sono in `.github/CODEOWNERS`: le PR si fondono con i due check (`brain-check`, `coerenza`) senza review umana; una PR che tocca una zona protetta passa solo con `travaso.py check --pr <n> --approvo` di un membro del team. Persone, aree e responsabili del travaso: `travaso.yaml`.
