#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""OLHO — auditor local de arquivos de texto.

Busca vários termos/domínios em uma única varredura e, opcionalmente,
assinala linhas que parecem conter credenciais expostas. Por segurança,
o relatório nunca inclui a linha encontrada, senha, CPF ou e-mail: registra
somente caminho, número da linha, termo procurado ou categoria do alerta.

Exemplos:
    python olho_melhorado.py
    python olho_melhorado.py --dir naz --terms core3.com.br,exemplo.com
    python olho_melhorado.py --dir naz --terms-file termos.txt --detectar-credenciais
    python olho_melhorado.py --dir naz --terms core3.com.br --ext .txt,.csv,.log
"""

from __future__ import annotations

import argparse
import csv
import os
import re
import sys
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

EXTENSOES_PADRAO = {
    ".txt", ".csv", ".tsv", ".log", ".json", ".xml", ".html", ".htm",
    ".md", ".yaml", ".yml", ".ini", ".conf", ".cfg", ".sql",
}

# Detectores apenas sinalizam a presença provável; nenhum valor é capturado
# ou gravado no relatório.
EMAIL_SENHA = re.compile(
    r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"
    r"\s*[:;|,\-–]\s*\S{3,}"
)
CPF_SENHA = re.compile(
    r"(?<!\d)\d{3}\.?\d{3}\.?\d{3}-?\d{2}"
    r"\s*[:;|,\-–]\s*\S{3,}"
)
CAMPO_SENHA = re.compile(
    r"(?i)\b(?:password|passwd|pwd|senha)\b\s*[:=]\s*\S{3,}"
)


def normalizar_termo(valor: str) -> str:
    """Remove espaços e esquema/parte de URL, preservando o termo de busca."""
    valor = valor.strip()
    if not valor:
        return ""
    candidato = valor if "://" in valor else "//" + valor
    try:
        partes = urlsplit(candidato)
        if partes.netloc:
            host = partes.netloc.rsplit("@", 1)[-1].split(":", 1)[0]
            if host:
                return host.removeprefix("www.").strip().lower()
    except ValueError:
        pass
    return valor.lower().strip().strip("/")


def carregar_termos(args: argparse.Namespace) -> list[str]:
    termos: list[str] = []
    if args.terms:
        termos.extend(args.terms.split(","))
    if args.terms_file:
        caminho = Path(args.terms_file)
        with caminho.open("r", encoding="utf-8-sig") as arquivo:
            termos.extend(linha.strip() for linha in arquivo if linha.strip())
    if not termos and sys.stdin.isatty():
        entrada = input("Termos/domínios (separados por vírgula; Enter para pular): ")
        termos.extend(entrada.split(","))
    # Deduplica sem diferenciar maiúsculas/minúsculas, preservando ordem.
    unicos: dict[str, str] = {}
    for bruto in termos:
        termo = normalizar_termo(bruto)
        if termo:
            unicos.setdefault(termo.casefold(), termo)
    return list(unicos.values())


def compilar_busca(termos: list[str], incluir_subdominios: bool) -> tuple[re.Pattern | None, dict[str, str]]:
    """Cria uma regex combinada para testar todos os termos por linha."""
    if not termos:
        return None, {}
    grupos: list[str] = []
    mapa: dict[str, str] = {}
    for indice, termo in enumerate(termos):
        chave = f"T{indice}"
        escapado = re.escape(termo)
        # Domínios recebem limites para evitar, por exemplo, achar
        # example.com dentro de notexample.com. Subdomínios são opcionais.
        parece_dominio = "." in termo and " " not in termo
        if parece_dominio:
            prefixo = r"(?:[A-Za-z0-9-]+\.)*" if incluir_subdominios else r"(?:www\.)?"
            expr = rf"(?<![A-Za-z0-9.-]){prefixo}{escapado}(?![A-Za-z0-9.-])"
        else:
            expr = escapado
        grupos.append(rf"(?P<{chave}>{expr})")
        mapa[chave] = termo
    return re.compile("|".join(grupos), re.IGNORECASE), mapa


def extensoes_configuradas(valor: str | None) -> set[str]:
    if not valor:
        return EXTENSOES_PADRAO
    saida = set()
    for item in valor.split(","):
        ext = item.strip().lower()
        if not ext:
            continue
        saida.add(ext if ext.startswith(".") else "." + ext)
    return saida


def listar_arquivos(base: Path, extensoes: set[str], incluir_sem_extensao: bool) -> list[Path]:
    encontrados: list[Path] = []
    for raiz, diretorios, nomes in os.walk(base, followlinks=False):
        diretorios[:] = [d for d in diretorios if not d.startswith(".")]
        for nome in nomes:
            caminho = Path(raiz) / nome
            if caminho.is_symlink() or not caminho.is_file():
                continue
            if incluir_sem_extensao or caminho.suffix.lower() in extensoes:
                encontrados.append(caminho)
    return encontrados


def ler_linhas(caminho: Path):
    """Lê linha a linha, tentando UTF-8 e depois CP1252.

    Usa readlines() na tentativa UTF-8 para garantir que todas as linhas
    sejam decodificadas antes de qualquer yield — evita duplicatas caso o
    UnicodeDecodeError ocorra no meio do arquivo (após o limite do buffer).
    """
    try:
        with caminho.open("r", encoding="utf-8-sig", errors="strict") as f:
            linhas = f.readlines()
        yield from linhas
        return
    except UnicodeDecodeError:
        pass
    with caminho.open("r", encoding="cp1252", errors="replace") as f:
        yield from f


def auditar(
    base: Path,
    termos: list[str],
    extensoes: set[str],
    incluir_sem_extensao: bool,
    incluir_subdominios: bool,
    detectar_credenciais: bool,
    relatorio: Path,
) -> tuple[int, int, int, int]:
    arquivos = listar_arquivos(base, extensoes, incluir_sem_extensao)
    regex_busca, mapa_grupos = compilar_busca(termos, incluir_subdominios)
    caminho_relatorio = relatorio.resolve()
    lidos = erros = achados = linhas_credenciais = 0
    relatorio.parent.mkdir(parents=True, exist_ok=True)

    with relatorio.open("w", encoding="utf-8-sig", newline="") as saida:
        escritor = csv.writer(saida)
        escritor.writerow(["tipo", "arquivo", "linha", "termo_ou_categoria"])
        try:
            total = len(arquivos)
            for indice, caminho in enumerate(arquivos, 1):
                if caminho.resolve() == caminho_relatorio:
                    continue
                relativo = str(caminho.relative_to(base))
                try:
                    for numero, linha in enumerate(ler_linhas(caminho), 1):
                        encontrados: set[str] = set()
                        if regex_busca:
                            for match in regex_busca.finditer(linha):
                                termo = mapa_grupos.get(match.lastgroup or "")
                                if termo:
                                    encontrados.add(termo)
                        for termo in sorted(encontrados, key=str.casefold):
                            escritor.writerow(["termo", relativo, numero, termo])
                            achados += 1

                        if detectar_credenciais:
                            categorias = []
                            if EMAIL_SENHA.search(linha):
                                categorias.append("possivel_email_senha")
                            if CPF_SENHA.search(linha):
                                categorias.append("possivel_cpf_senha")
                            if CAMPO_SENHA.search(linha):
                                categorias.append("possivel_campo_senha")
                            if categorias:
                                for categoria in categorias:
                                    escritor.writerow(["alerta", relativo, numero, categoria])
                                linhas_credenciais += 1
                except (OSError, UnicodeError):
                    erros += 1
                lidos += 1
                if total:
                    print(f"\rVarredura: {indice}/{total} arquivos | {achados} ocorrência(s)", end="", flush=True)
                saida.flush()
        except KeyboardInterrupt:
            print("\nInterrompido; o relatório parcial foi preservado.")

    if arquivos:
        print()
    return lidos, erros, achados, linhas_credenciais


def criar_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Busca vários termos numa varredura local e gera relatório sem conteúdo sensível."
    )
    parser.add_argument("--dir", default="naz", help="Pasta a analisar (padrão: naz).")
    parser.add_argument("--terms", help="Termos/domínios separados por vírgula.")
    parser.add_argument("--terms-file", help="Arquivo UTF-8 com um termo/domínio por linha.")
    parser.add_argument("--ext", help="Extensões permitidas, separadas por vírgula (ex.: .txt,.csv,.log).")
    parser.add_argument("--todos-arquivos", action="store_true", help="Inclui arquivos sem extensão conhecida; use apenas se apropriado.")
    parser.add_argument("--subdominios", action="store_true", help="Considera subdomínios ao buscar domínios.")
    parser.add_argument("--detectar-credenciais", action="store_true", help="Registra somente alertas mascarados de possíveis credenciais; nunca salva seus valores.")
    parser.add_argument("--report", help="Caminho do CSV de saída (por padrão, nome único no diretório atual).")
    return parser


def main() -> int:
    args = criar_parser().parse_args()
    base = Path(args.dir).expanduser().resolve()
    if not base.exists() or not base.is_dir():
        print(f"Erro: a pasta não existe ou não é diretório: {base}", file=sys.stderr)
        return 2

    termos = carregar_termos(args)
    if not termos and not args.detectar_credenciais:
        print("Informe ao menos um termo/domínio ou use --detectar-credenciais.", file=sys.stderr)
        return 2

    if args.report:
        relatorio = Path(args.report).expanduser().resolve()
    else:
        carimbo = datetime.now().strftime("%Y%m%d_%H%M%S")
        relatorio = Path.cwd() / f"relatorio_olho_{carimbo}.csv"

    extensoes = extensoes_configuradas(args.ext)
    print(f"Pasta: {base}")
    print(f"Termos: {', '.join(termos) if termos else '(nenhum)'}")
    print(f"Extensões: {'todos os arquivos' if args.todos_arquivos else ', '.join(sorted(extensoes))}")
    print("O relatório não contém linhas encontradas, senhas, CPFs ou e-mails.")

    lidos, erros, achados, alertas = auditar(
        base=base,
        termos=termos,
        extensoes=extensoes,
        incluir_sem_extensao=args.todos_arquivos,
        incluir_subdominios=args.subdominios,
        detectar_credenciais=args.detectar_credenciais,
        relatorio=relatorio,
    )
    print(f"Arquivos processados: {lidos}; falhas de leitura: {erros}")
    print(f"Ocorrências de termos: {achados}; linhas com alerta de credencial possível: {alertas}")
    print(f"Relatório: {relatorio}")
    if erros:
        print("Nota: alguns arquivos não puderam ser lidos; confira permissões e formatos.")
    if args.detectar_credenciais:
        print("Os alertas são heurísticos e precisam de revisão autorizada; não incluem os valores encontrados.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        print("\nEncerrado pelo usuário.", file=sys.stderr)
        raise SystemExit(130)
