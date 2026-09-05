#!/usr/bin/env python3
"""Escreve o resumo da varredura de segurança no Summary do run.

Um relatório que exige abrir seis jobs para ser lido não é um relatório. Este
script junta o que cada job produziu — SARIF do gitleaks e do trivy, quality
gate do Sonar, achados abertos no DefectDojo — numa página só: a do próprio run.

**Nunca reprova.** Gate é o job `gate`; aqui é leitura. Toda consulta externa
está embrulhada: Sonar fora do ar, token vencido ou DefectDojo lento viram uma
linha dizendo o que faltou, nunca um X vermelho num run que passou.

Entrada por ambiente (todas opcionais, o que faltar vira "não sei"):
  GITHUB_STEP_SUMMARY  arquivo de saída; sem ele, escreve no stdout
  DIR_RELATORIOS       raiz dos artefatos baixados (default: relatorios)
  PRODUTO              nome do produto no Sonar/DefectDojo
  SONAR_HOST/SONAR_TOKEN, DD_HOST/DD_TOKEN
  R_SEGREDOS, R_DEPS, R_SONAR, R_DD, R_GATE   result de cada job
"""
from __future__ import annotations

import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

ORDEM = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "?"]
ICONE = {"success": "✅", "failure": "❌", "cancelled": "⚪", "skipped": "⏭️"}
METRICAS = [
    "bugs", "vulnerabilities", "security_hotspots",
    "code_smells", "coverage", "duplicated_lines_density", "ncloc",
]

env = os.environ.get


def http(url: str, token: str = "", esquema: str = "Bearer"):
    """JSON da URL, ou None. O silêncio é proposital: relatório não quebra run."""
    try:
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        if token:
            req.add_header("Authorization", f"{esquema} {token}")
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.loads(r.read().decode())
    except Exception:
        return None


def ler_sarif(caminho: pathlib.Path):
    """[(sev, regra, arquivo:linha, msg)] — ou None quando não houve relatório.

    None e [] dizem coisas diferentes, e confundir os dois é como um relatório
    de segurança mente: `[]` é "varreu e não achou nada"; `None` é "não varreu",
    que não é notícia boa nenhuma.
    """
    if not caminho.is_file() or caminho.stat().st_size == 0:
        return None
    try:
        doc = json.loads(caminho.read_text(encoding="utf-8"))
    except Exception:
        return None

    achados = []
    for run in doc.get("runs", []):
        regras = {
            r.get("id"): r
            for r in run.get("tool", {}).get("driver", {}).get("rules", [])
        }
        for res in run.get("results", []):
            rid = res.get("ruleId", "?")
            regra = regras.get(rid, {})
            props = {**regra.get("properties", {}), **res.get("properties", {})}
            # trivy grava security-severity (0-10); gitleaks não grava nada,
            # então cai no `level` do próprio resultado.
            try:
                n = float(props.get("security-severity"))
                sev = ("CRITICAL" if n >= 9 else "HIGH" if n >= 7
                       else "MEDIUM" if n >= 4 else "LOW")
            except (TypeError, ValueError):
                nivel = (res.get("level")
                         or regra.get("defaultConfiguration", {}).get("level"))
                sev = {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(nivel, "?")

            onde = ""
            for loc in res.get("locations", [])[:1]:
                fis = loc.get("physicalLocation", {})
                arq = fis.get("artifactLocation", {}).get("uri", "")
                linha = fis.get("region", {}).get("startLine", "")
                onde = f"{arq}:{linha}".rstrip(":")
            msg = (res.get("message", {}).get("text") or "").strip().replace("\n", " ")
            # O trivy poe pacote e versao no texto da mensagem, em linhas
            # "Package: x" / "Installed Version: y" / "Fixed Version: z". Sem
            # isso o relatorio diz que ha uma CVE, mas nao o que atualizar —
            # que e a unica coisa acionavel.
            det = {}
            for campo, chave in [("Package:", "pacote"),
                                 ("Installed Version:", "instalada"),
                                 ("Fixed Version:", "correcao")]:
                if campo in msg:
                    det[chave] = msg.split(campo, 1)[1].strip().split(" ")[0].rstrip(",")
            titulo = (regra.get("shortDescription", {}).get("text")
                      or regra.get("help", {}).get("text", "").split("\n")[0]
                      or msg)
            achados.append({
                "sev": sev, "regra": rid, "onde": onde,
                "msg": msg[:400], "titulo": titulo.strip()[:130],
                "pacote": det.get("pacote", ""), "instalada": det.get("instalada", ""),
                "correcao": det.get("correcao", ""),
                "url": (regra.get("helpUri") or ""),
            })
    return achados


def contar(achados):
    c = dict.fromkeys(ORDEM, 0)
    for a in achados:
        c[a["sev"] if a["sev"] in c else "?"] += 1
    return c


def main() -> int:
    destino = env("GITHUB_STEP_SUMMARY")
    saida = open(destino, "a", encoding="utf-8") if destino else sys.stdout
    w = lambda s="": print(s, file=saida)
    ic = lambda r: ICONE.get(r or "", "❔")
    raiz = pathlib.Path(env("DIR_RELATORIOS", "relatorios"))
    produto = env("PRODUTO", "")
    servidor = env("GITHUB_SERVER_URL", "https://github.com")
    repo = env("GITHUB_REPOSITORY", "")
    sha = env("GITHUB_SHA", "")

    # ------------------------------------------------------------- cabeçalho
    w(f"## 🛡️ Segurança — {produto}")
    w()
    if sha:
        w(f"`{env('GITHUB_REF_NAME','')}` · commit [`{sha[:8]}`]({servidor}/{repo}/commit/{sha})"
          f" · por **{env('GITHUB_ACTOR','')}** · evento `{env('GITHUB_EVENT_NAME','')}`")
        w()
    w("| etapa | resultado |")
    w("|---|---|")
    for nome, chave in [("segredos vazados", "R_SEGREDOS"),
                        ("dependências vulneráveis", "R_DEPS"),
                        ("qualidade (SonarQube)", "R_SONAR"),
                        ("envio ao DefectDojo", "R_DD"),
                        ("bloqueio", "R_GATE")]:
        r = env(chave, "")
        w(f"| {nome} | {ic(r)} `{r or 'não informado'}` |")
    w()

    # --------------------------------------------------------------- achados
    gl = ler_sarif(raiz / "gitleaks" / "results.sarif")
    tv = ler_sarif(raiz / "trivy" / "trivy.sarif")

    w("### Achados desta execução")
    w()
    if gl is None and tv is None:
        w("> Nenhum relatório SARIF chegou aqui. As duas varreduras falharam antes de "
          "escrever, ou os artefatos não subiram — **não** é o mesmo que estar limpo.")
    else:
        w("| varredura | CRITICAL | HIGH | MEDIUM | LOW | total |")
        w("|---|--:|--:|--:|--:|--:|")
        for nome, ach in [("gitleaks (segredos)", gl), ("trivy (deps/config)", tv)]:
            if ach is None:
                w(f"| {nome} | — | — | — | — | _sem relatório_ |")
                continue
            c = contar(ach)
            w(f"| {nome} | {c['CRITICAL']} | {c['HIGH']} | {c['MEDIUM']} | {c['LOW']} "
              f"| **{len(ach)}** |")
    w()

    if gl:
        w("> ⚠️ **Segredo detectado.** Rotacione a credencial ANTES de reescrever o "
          "histórico: o commit sai do repositório, o segredo já vazou.")
        w()

    # A lista COMPLETA, agrupada por severidade e dobrada em <details>: um
    # relatório que corta em 15 obriga a baixar o SARIF para ver o resto, e aí
    # ninguém vê. Dobrado, cabe na página sem atrapalhar quem só quer o número.
    todos = (tv or []) + (gl or [])
    if todos:
        w("### Todas as vulnerabilidades encontradas")
        w()
        for sev in ORDEM:
            grupo = [a for a in todos if a["sev"] == sev]
            if not grupo:
                continue
            marca = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else \
                    "🟡" if sev == "MEDIUM" else "⚪"
            aberto = " open" if sev in ("CRITICAL", "HIGH") else ""
            w(f"<details{aberto}><summary>{marca} <b>{sev}</b> — {len(grupo)} achado(s)</summary>")
            w()
            # Só mostra as colunas de pacote quando há pacote: em achado de
            # configuração (Terraform, Dockerfile) elas ficariam vazias e a
            # tabela viraria ruído.
            tem_pacote = any(a["pacote"] for a in grupo)
            if tem_pacote:
                w("| id | pacote | instalada | corrigida em | onde |")
                w("|---|---|---|---|---|")
            else:
                w("| id | o quê | onde |")
                w("|---|---|---|")
            for a in sorted(grupo, key=lambda x: (x["pacote"] or "", x["regra"])):
                ident = f"[`{a['regra']}`]({a['url']})" if a["url"] else f"`{a['regra']}`"
                if tem_pacote:
                    correcao = f"**{a['correcao']}**" if a["correcao"] else "_sem correção publicada_"
                    w(f"| {ident} | `{a['pacote'] or '—'}` | `{a['instalada'] or '—'}` "
                      f"| {correcao} | `{a['onde'] or '—'}` |")
                else:
                    w(f"| {ident} | {a['titulo'] or a['msg'][:110] or '—'} | `{a['onde'] or '—'}` |")
            w()
            w("</details>")
            w()

        # O que dá para resolver hoje: pacote com versão corrigida publicada.
        corrigiveis = {}
        for a in todos:
            if a["correcao"] and a["pacote"]:
                chave = (a["pacote"], a["instalada"])
                corrigiveis.setdefault(chave, set()).add(a["correcao"])
        if corrigiveis:
            w(f"**{len(corrigiveis)} pacote(s) com correção já publicada** — é o que dá "
              "para resolver hoje, subindo a versão:")
            w()
            w("| pacote | está em | subir para |")
            w("|---|---|---|")
            for (pkg, inst), versoes in sorted(corrigiveis.items()):
                w(f"| `{pkg}` | `{inst or '—'}` | `{', '.join(sorted(versoes))}` |")
            w()

    # ----------------------------------------------------------------- Sonar
    sonar_host = (env("SONAR_HOST", "") or "").rstrip("/")
    if sonar_host:
        w("### Qualidade (SonarQube)")
        w()
        chave = urllib.parse.quote(produto)
        token = env("SONAR_TOKEN", "")
        qg = http(f"{sonar_host}/api/qualitygates/project_status?projectKey={chave}", token)
        me = http(f"{sonar_host}/api/measures/component?component={chave}"
                  f"&metricKeys={','.join(METRICAS)}", token)
        if qg is None and me is None:
            w(f"> Não consegui falar com o Sonar em `{sonar_host}`. É host de rede local: "
              "só responde a runner self-hosted. Se este run foi em runner do GitHub, é "
              "esperado — não é sinal de problema no código.")
        else:
            if qg:
                st = qg.get("projectStatus", {}).get("status", "?")
                w(f"**Quality gate:** {'✅' if st == 'OK' else '❌'} `{st}`")
                falhas = [c for c in qg.get("projectStatus", {}).get("conditions", [])
                          if c.get("status") != "OK"]
                if falhas:
                    w()
                    w("| condição que reprovou | valor | limite |")
                    w("|---|--:|--:|")
                    for c in falhas:
                        w(f"| `{c.get('metricKey')}` | {c.get('actualValue')} "
                          f"| {c.get('comparator','')} {c.get('errorThreshold')} |")
                w()
            if me:
                vals = {m["metric"]: m.get("value", "—")
                        for m in me.get("component", {}).get("measures", [])}
                w("| bugs | vulnerab. | hotspots | code smells | cobertura | duplicação | linhas |")
                w("|--:|--:|--:|--:|--:|--:|--:|")
                w("| {} | {} | {} | {} | {}% | {}% | {} |".format(
                    *[vals.get(k, "—") for k in METRICAS]))
                w()
            w(f"[Abrir o projeto no SonarQube]({sonar_host}/dashboard?id={chave})")
        w()

    # ------------------------------------------------------------ DefectDojo
    dd_host = (env("DD_HOST", "") or "").rstrip("/")
    if dd_host:
        w("### Achados abertos (DefectDojo)")
        w()
        token = env("DD_TOKEN", "")
        prods = http(f"{dd_host}/api/v2/products/?name={urllib.parse.quote(produto)}",
                     token, "Token")
        pid = None
        if prods and prods.get("results"):
            pid = prods["results"][0].get("id")
        if pid is None:
            w(f"> Não consegui consultar o DefectDojo em `{dd_host}` — host de rede local, "
              "como o Sonar. O envio dos SARIF desta execução está na linha **envia ao "
              "DefectDojo** da tabela acima.")
        else:
            w("Acumulado do produto, não só deste run: é a fila que sobrou.")
            w()
            w("| severidade | abertos |")
            w("|---|--:|")
            total = 0
            for sev in ["Critical", "High", "Medium", "Low", "Info"]:
                r = http(f"{dd_host}/api/v2/findings/?test__engagement__product={pid}"
                         f"&active=true&severity={sev}&limit=1", token, "Token")
                n = (r or {}).get("count")
                if n is None:
                    w(f"| {sev} | ? |")
                    continue
                total += n
                destaque = "**" if sev in ("Critical", "High") and n else ""
                w(f"| {sev} | {destaque}{n}{destaque} |")
            w(f"| **total** | **{total}** |")
            w()
            w(f"[Abrir o produto no DefectDojo]({dd_host}/product/{pid}/finding/open)")
        w()

    # ---------------------------------------------------------------- rodapé
    w("---")
    w(f"SARIF completo nos artefatos deste run · "
      f"[Security → Code scanning]({servidor}/{repo}/security/code-scanning)")
    if saida is not sys.stdout:
        saida.close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
