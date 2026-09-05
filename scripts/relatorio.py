#!/usr/bin/env python3
"""Monta o relatorio final de um run: o que passou, o que quebrou e quanto demorou.

Le o proprio run pela API do GitHub em vez de ser instrumentado passo a passo.
A diferenca importa: instrumentar exigiria editar cada etapa de cada workflow e
manter isso sincronizado para sempre; a API ja devolve nome, desfecho, inicio e
fim de todo job e toda etapa, de graca e sem acoplamento. Um workflow novo entra
no relatorio sem ninguem tocar aqui.

Escreve duas saidas do mesmo dado:
  - markdown no GITHUB_STEP_SUMMARY, que aparece na pagina do run sem baixar nada
  - relatorio.html, artefato baixavel que sobrevive a retencao do summary

Entradas por ambiente:
  GITHUB_REPOSITORY, GITHUB_RUN_ID, GITHUB_SHA, GITHUB_REF_NAME, GITHUB_ACTOR
  GH_TOKEN            token com `actions: read`
  DIR_RELATORIOS      pasta com os artefatos de seguranca ja baixados (opcional)
  SAIDA_HTML          caminho do html (padrao: relatorio.html)

Stdlib only: o runner self-hosted do homelab nao tem pip garantido, e um
relatorio que depende de instalar dependencia e um relatorio que falha no dia
em que a rede oscila.
"""

from __future__ import annotations

import datetime as dt
import glob
import html
import json
import os
import ssl
import urllib.error
import urllib.request
import xml.etree.ElementTree as ET

API = "https://api.github.com"
REPO = os.environ.get("GITHUB_REPOSITORY", "")
RUN_ID = os.environ.get("GITHUB_RUN_ID", "")
TOKEN = os.environ.get("GH_TOKEN", "")
DIR_REL = os.environ.get("DIR_RELATORIOS", "relatorios")
SAIDA = os.environ.get("SAIDA_HTML", "relatorio.html")

# Etapas que apontam mas nao reprovam. Precisam aparecer diferente de uma falha
# de verdade, senao o relatorio ensina que vermelho nao significa nada.
NAO_BLOQUEIAM = {"lint", "typecheck", "build", "ruff", "formatação", "formatacao",
                 "links do README", "Terraform/OpenTofu formatado"}


def api(caminho: str):
    """GET na API. Devolve None em qualquer erro: relatorio nao derruba run."""
    req = urllib.request.Request(f"{API}{caminho}")
    req.add_header("Accept", "application/vnd.github+json")
    if TOKEN:
        req.add_header("Authorization", f"Bearer {TOKEN}")
    try:
        with urllib.request.urlopen(req, timeout=30,
                                    context=ssl.create_default_context()) as r:
            return json.load(r)
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"::warning::API {caminho} falhou: {e}")
        return None


def dura(inicio: str | None, fim: str | None) -> float:
    if not inicio or not fim:
        return 0.0
    fmt = "%Y-%m-%dT%H:%M:%SZ"
    try:
        return (dt.datetime.strptime(fim, fmt) - dt.datetime.strptime(inicio, fmt)).total_seconds()
    except ValueError:
        return 0.0


def humano(seg: float) -> str:
    if seg < 60:
        return f"{seg:.0f}s"
    return f"{int(seg // 60)}m{int(seg % 60):02d}s"


def icone(desfecho: str | None, nome: str) -> str:
    if desfecho == "success":
        return "✅"
    if desfecho == "skipped":
        return "⏭️"
    if desfecho in ("failure", "timed_out"):
        return "⚠️" if nome.strip() in NAO_BLOQUEIAM else "❌"
    if desfecho == "cancelled":
        return "🚫"
    return "⚪"


# --------------------------------------------------------------------------
# coleta
# --------------------------------------------------------------------------

def coleta_jobs() -> list[dict]:
    d = api(f"/repos/{REPO}/actions/runs/{RUN_ID}/jobs?per_page=100")
    return (d or {}).get("jobs", [])


def coleta_erros(jobs: list[dict]) -> list[dict]:
    """As anotacoes sao o `::error::` que cada passo emitiu — a mensagem real.

    O id do job e o mesmo do check-run, entao da para pedir as anotacoes sem
    descobrir nada a mais.
    """
    erros = []
    for j in jobs:
        if j.get("conclusion") not in ("failure", "timed_out"):
            continue
        for a in (api(f"/repos/{REPO}/check-runs/{j['id']}/annotations") or [])[:10]:
            if a.get("annotation_level") not in ("failure", "warning"):
                continue
            erros.append({
                "job": j["name"],
                "nivel": a.get("annotation_level"),
                "arquivo": a.get("path") or "",
                "linha": a.get("start_line") or "",
                "msg": (a.get("message") or "").strip().splitlines()[0][:300],
            })
    return erros


def coleta_testes() -> dict:
    """Conta testes a partir de qualquer JUnit XML que os artefatos tenham trazido.

    Nem todo repositorio emite JUnit; quando nao emite, a secao some do relatorio
    em vez de mostrar zero — zero teste e "nao medi", nao "tudo passou".
    """
    total = falhas = erros = pulados = 0
    achou = False
    for p in glob.glob(f"{DIR_REL}/**/*.xml", recursive=True):
        try:
            raiz = ET.parse(p).getroot()
        except ET.ParseError:
            continue
        suites = [raiz] if raiz.tag == "testsuite" else raiz.iter("testsuite")
        for s in suites:
            achou = True
            total += int(s.get("tests", 0))
            falhas += int(s.get("failures", 0))
            erros += int(s.get("errors", 0))
            pulados += int(s.get("skipped", 0))
    return {"achou": achou, "total": total, "falhas": falhas,
            "erros": erros, "pulados": pulados}


def coleta_seguranca() -> list[dict]:
    """Achados por severidade a partir dos SARIF que a etapa de seguranca subiu."""
    fora = []
    for p in glob.glob(f"{DIR_REL}/**/*.sarif", recursive=True):
        try:
            d = json.load(open(p))
        except (OSError, ValueError):
            continue
        for run in d.get("runs", []):
            ferramenta = run.get("tool", {}).get("driver", {}).get("name", "?")
            niveis: dict[str, int] = {}
            for r in run.get("results", []):
                niveis[r.get("level", "warning")] = niveis.get(r.get("level", "warning"), 0) + 1
            if niveis or run.get("results") is not None:
                fora.append({"ferramenta": ferramenta,
                             "total": sum(niveis.values()), "niveis": niveis})
    return fora


# --------------------------------------------------------------------------
# render
# --------------------------------------------------------------------------

def barras_svg(passos: list[tuple[str, float, str]]) -> str:
    """Grafico de barras das etapas mais lentas, em SVG inline.

    Inline porque o artefato tem de abrir sozinho no navegador, sem CDN: o
    relatorio e lido meses depois, e link externo apodrece.
    """
    passos = sorted(passos, key=lambda x: -x[1])[:14]
    if not passos:
        return ""
    maior = max(p[1] for p in passos) or 1
    alt, larg, esq = 22, 460, 230
    corpo = []
    for i, (nome, seg, desf) in enumerate(passos):
        y = i * alt
        w = max(2, seg / maior * larg)
        cor = {"success": "#2da44e", "failure": "#cf222e",
               "skipped": "#8c959f"}.get(desf, "#9a6700")
        rot = html.escape(nome[:38])
        corpo.append(
            f'<text x="{esq - 8}" y="{y + 14}" text-anchor="end" '
            f'font-size="11" fill="currentColor">{rot}</text>'
            f'<rect x="{esq}" y="{y + 4}" width="{w:.0f}" height="13" rx="2" fill="{cor}"/>'
            f'<text x="{esq + w + 6:.0f}" y="{y + 14}" font-size="10" '
            f'fill="currentColor" opacity=".7">{humano(seg)}</text>')
    return (f'<svg viewBox="0 0 {esq + larg + 60} {len(passos) * alt}" '
            f'width="100%" role="img" aria-label="duracao por etapa">'
            + "".join(corpo) + "</svg>")


def monta(jobs, erros, testes, seg) -> tuple[str, str]:
    """Devolve (markdown, html) do mesmo conteudo."""
    passos: list[tuple[str, float, str]] = []
    linhas: list[tuple[str, str, str, str, float]] = []
    for j in jobs:
        for s in j.get("steps", []):
            nome = s.get("name", "?")
            # Ruido de infraestrutura. As etapas `Post Run ...` sao limpeza que o
            # proprio Actions injeta, e `Set up job`/`Complete runner` sao o
            # runner se preparando — nada disso e etapa do projeto, e juntas
            # dobravam o tamanho da tabela. `Run x/y@v` FICA: e trabalho real
            # (o scan do Sonar sozinho leva 44s) e some-lo esconderia onde o
            # tempo do run realmente vai.
            if (nome.startswith("Post Run ")
                    or nome in ("Set up job", "Complete job", "Post job cleanup",
                                "Complete runner", "Set up runner")):
                continue
            d = dura(s.get("started_at"), s.get("completed_at"))
            desf = s.get("conclusion") or "?"
            linhas.append((j["name"], nome, desf, icone(desf, nome), d))
            passos.append((f"{nome}", d, desf))

    total_seg = sum(dura(j.get("started_at"), j.get("completed_at")) for j in jobs)
    quebrou = [l for l in linhas if l[2] in ("failure", "timed_out")
               and l[1].strip() not in NAO_BLOQUEIAM]
    alertou = [l for l in linhas if l[2] in ("failure", "timed_out")
               and l[1].strip() in NAO_BLOQUEIAM]
    veredito = "❌ reprovado" if quebrou else ("⚠️ passou com apontamentos" if alertou else "✅ verde")

    sha = os.environ.get("GITHUB_SHA", "")[:8]
    ref = os.environ.get("GITHUB_REF_NAME", "")
    ator = os.environ.get("GITHUB_ACTOR", "")
    url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{REPO}"

    # ---- markdown ----
    m = [f"## 📊 Relatório do run — {veredito}", "",
         f"**{REPO}** · `{ref}` · [`{sha}`]({url}/commit/{os.environ.get('GITHUB_SHA','')}) "
         f"· por **{ator}** · tempo total **{humano(total_seg)}**", ""]

    m += ["| job | etapa | resultado | tempo |", "|---|---|---|---|"]
    for job, etapa, desf, ic, d in linhas:
        m.append(f"| {job} | {etapa} | {ic} {desf} | {humano(d)} |")
    m.append("")

    if alertou:
        m += ["> ⚠️ **Apontamentos que não reprovam:** "
              + ", ".join(sorted({l[1] for l in alertou}))
              + ". São report-only por decisão — quem barra é teste e segredo vazado.", ""]

    if testes["achou"]:
        ok = testes["total"] - testes["falhas"] - testes["erros"] - testes["pulados"]
        m += ["### 🧪 Testes", "",
              "| total | passaram | falharam | erro | pulados |", "|---|---|---|---|---|",
              f"| {testes['total']} | {ok} | {testes['falhas']} | "
              f"{testes['erros']} | {testes['pulados']} |", ""]

    if seg:
        m += ["### 🔐 Segurança", "", "| ferramenta | achados | por severidade |",
              "|---|---|---|"]
        for f in seg:
            det = ", ".join(f"{k}: {v}" for k, v in sorted(f["niveis"].items())) or "—"
            m.append(f"| {f['ferramenta']} | {f['total']} | {det} |")
        m.append("")

    if erros:
        m += ["### 💥 Erros", ""]
        for e in erros[:25]:
            loc = f"`{e['arquivo']}:{e['linha']}` — " if e["arquivo"] else ""
            m.append(f"- **{e['job']}** · {loc}{e['msg']}")
        m.append("")

    m += ["### ⏱️ Onde o tempo foi", "", "<!-- o gráfico só existe no HTML -->", ""]
    for nome, d, _ in sorted(passos, key=lambda x: -x[1])[:8]:
        m.append(f"- `{nome}` — {humano(d)}")
    m += ["", f"_Relatório completo em HTML no artefato **relatorio** deste run._"]

    # ---- html ----
    def tab(cabecalho, corpo):
        th = "".join(f"<th>{html.escape(c)}</th>" for c in cabecalho)
        tr = "".join("<tr>" + "".join(f"<td>{c}</td>" for c in linha) + "</tr>"
                     for linha in corpo)
        return f"<table><thead><tr>{th}</tr></thead><tbody>{tr}</tbody></table>"

    h = [f"""<!doctype html><meta charset="utf-8">
<title>Relatório — {html.escape(REPO)} #{html.escape(RUN_ID)}</title>
<style>
 :root {{ color-scheme: light dark; --b:#d0d7de; --m:#57606a; }}
 body {{ font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;
        margin:0 auto; padding:2rem 1.25rem; max-width:62rem; }}
 h1 {{ font-size:1.5rem; margin:0 0 .25rem; }}
 h2 {{ font-size:1.05rem; margin:2rem 0 .6rem; }}
 .meta {{ color:var(--m); margin-bottom:1.5rem; }}
 .v {{ display:inline-block; padding:.15rem .6rem; border-radius:999px;
      border:1px solid var(--b); font-weight:600; }}
 table {{ border-collapse:collapse; width:100%; font-size:13px; }}
 th,td {{ text-align:left; padding:.4rem .6rem; border-bottom:1px solid var(--b); }}
 th {{ font-weight:600; color:var(--m); font-size:12px; text-transform:uppercase;
      letter-spacing:.03em; }}
 td:last-child, th:last-child {{ text-align:right; font-variant-numeric:tabular-nums; }}
 .wrap {{ overflow-x:auto; }}
 code {{ background:rgba(127,127,127,.14); padding:.1rem .3rem; border-radius:3px; }}
 li {{ margin:.2rem 0; }}
</style>
<h1>Relatório do run</h1>
<div class="meta"><span class="v">{html.escape(veredito)}</span>
 &nbsp;{html.escape(REPO)} · <code>{html.escape(ref)}</code> ·
 <a href="{url}/actions/runs/{html.escape(RUN_ID)}">run #{html.escape(RUN_ID)}</a> ·
 commit <code>{html.escape(sha)}</code> · por {html.escape(ator)} ·
 tempo total <strong>{humano(total_seg)}</strong></div>"""]

    h.append("<h2>⏱️ Duração por etapa</h2>" + barras_svg(passos))
    h.append("<h2>Etapas</h2><div class='wrap'>" + tab(
        ["job", "etapa", "resultado", "tempo"],
        [(html.escape(j), html.escape(e), f"{i} {d}", humano(t))
         for j, e, d, i, t in linhas]) + "</div>")

    if testes["achou"]:
        ok = testes["total"] - testes["falhas"] - testes["erros"] - testes["pulados"]
        h.append("<h2>🧪 Testes</h2>" + tab(
            ["total", "passaram", "falharam", "erro", "pulados"],
            [(testes["total"], ok, testes["falhas"], testes["erros"], testes["pulados"])]))

    if seg:
        h.append("<h2>🔐 Segurança</h2>" + tab(
            ["ferramenta", "achados", "por severidade"],
            [(html.escape(f["ferramenta"]), f["total"],
              html.escape(", ".join(f"{k}: {v}" for k, v in sorted(f["niveis"].items())) or "—"))
             for f in seg]))

    if erros:
        itens = "".join(
            f"<li><strong>{html.escape(e['job'])}</strong> · "
            + (f"<code>{html.escape(str(e['arquivo']))}:{html.escape(str(e['linha']))}</code> — "
               if e["arquivo"] else "")
            + html.escape(e["msg"]) + "</li>" for e in erros[:40])
        h.append(f"<h2>💥 Erros</h2><ul>{itens}</ul>")

    return "\n".join(m), "\n".join(h)


def main() -> int:
    jobs = coleta_jobs()
    if not jobs:
        print("::warning::não consegui ler os jobs do run — relatório vazio")
        return 0
    md, pagina = monta(jobs, coleta_erros(jobs), coleta_testes(), coleta_seguranca())

    resumo = os.environ.get("GITHUB_STEP_SUMMARY")
    if resumo:
        with open(resumo, "a", encoding="utf-8") as f:
            f.write(md + "\n")
    with open(SAIDA, "w", encoding="utf-8") as f:
        f.write(pagina + "\n")
    print(f"relatório pronto: {len(jobs)} jobs, html em {SAIDA}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
