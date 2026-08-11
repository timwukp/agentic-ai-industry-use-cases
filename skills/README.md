# Skills

AgentCore Skills consumed by this repo's agents, git-sourced from **main**
(AgentCore fetches a skill at session start from the repo's default branch —
a skill on a feature branch is invisible until merged). Every `SKILL.md`
must start with YAML frontmatter (`name` + `description`) or the consuming
harness fails at session start.

| Skill | What it is | Consumed by |
|---|---|---|
| [`finance-analysis`](finance-analysis/SKILL.md) | Finance-domain analysis methodology for the trading assistant | Finance harness |
| [`theory-to-production`](theory-to-production/SKILL.md) | The research → pre-register → self-calibrate → back-test → mechanical-verdict → promote pipeline distilled from the 10-test campaign (2 promoted / 8 fast-failed) | PRISM Theory Scout ([deploy/theory-scout](../deploy/theory-scout/README.md)) + humans running theory-validation work |
