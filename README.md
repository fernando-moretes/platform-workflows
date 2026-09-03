# platform-workflows

Os workflows reutilizáveis que as pipelines de
[`fernando-moretes`](https://github.com/fernando-moretes) chamam.

Este repositório é **público por necessidade técnica**: no GitHub, um
repositório público não consegue chamar um workflow guardado num repositório
privado. Como parte do portfólio é pública, os workflows precisam estar aqui.

O orquestrador continua em `platform` (privado) — é lá que vivem os scripts de
rollout, a convenção de nomenclatura e o catálogo dos repositórios. Aqui ficam
só os arquivos que precisam ser alcançáveis de fora.

## Os workflows

| Workflow | O que faz | Bloqueia o merge? |
|---|---|---|
| `pr-lint.yml` | Título em Conventional Commits, nome do branch, tamanho do PR | sim, título e branch |
| `ci-node.yml` | lint, typecheck, testes, build — cada etapa roda mesmo se a anterior falhar | sim |
| `ci-python.yml` | sintaxe, ruff, formatação, pytest | só a sintaxe |
| `ci-generic.yml` | YAML/JSON válidos, sintaxe de shell, `tofu fmt`, links do README | YAML/JSON e shell |
| `security.yml` | gitleaks, trivy, SonarQube, envio ao DefectDojo | só segredo vazado |
| `release.yml` | calcula SemVer dos commits, cria tag e release com changelog | — |

## Como chamar

```yaml
jobs:
  ci:
    uses: fernando-moretes/platform-workflows/.github/workflows/ci-node.yml@main

  seguranca:
    permissions:
      contents: read
      security-events: write
      actions: read
    uses: fernando-moretes/platform-workflows/.github/workflows/security.yml@main
    secrets: inherit
```

## Runner

O padrão é `["self-hosted","homelab"]` — os runners próprios, cuja execução não
consome a cota mensal do GitHub. Um repositório que precise de runner hospedado
pede explicitamente:

```yaml
    with:
      runner: '["ubuntu-latest"]'
```

## Decisões que valem explicar

**Só segredo vazado barra o merge.** Uma pipeline que barra tudo é uma pipeline
que se aprende a contornar. Vulnerabilidade em dependência entra na fila do
DefectDojo e é priorizada; segredo no histórico não espera fila, porque a
credencial já vazou no instante do push.

**O gate distingue "achou segredo" de "a ferramenta quebrou".** O gitleaks sai
com código diferente de zero nos dois casos, e barrar merge por ferramenta
quebrada ensina a ignorar o gate — então o relatório decide.

**gitleaks e trivy rodam como binário, não como action.** A action do gitleaks
exige licença paga para repositório em organização, e a do trivy resolve versão
por metadados que já falharam. Ambos são binários estáticos; baixar e rodar tem
menos partes móveis.
