#!/usr/bin/env bash
# bash completion for `osint`.
# Install:
#   source <(osint completion bash)              # ad-hoc
#   osint completion bash > /etc/bash_completion.d/osint   # system-wide
_osint() {
    local cur prev opts
    COMPREPLY=()
    cur="${COMP_WORDS[COMP_CWORD]}"
    prev="${COMP_WORDS[COMP_CWORD-1]}"

    # Subcommands
    local subs="config mcp watch diff self-update opsec-check cert-watch cache serve completion"
    # Top-level flags
    local flags="--kind --all --format --out --no-color --no-banner --list-modules --list-stats --list-profiles --version --interactive --debug --per-source --banner --profile --enable --disable --min-severity --bulk --bulk-format --opsec --tui --html --md --help"
    # Value choices
    local kinds="username email phone telegram whatsapp ip domain password hash"
    local formats="plain json jsonl csv"
    local severities="info low medium high critical"
    local profiles="quick deep person domain-recon red-team blue-team ioc creds leak-hunt default all"

    case "$prev" in
        --kind)        COMPREPLY=($(compgen -W "$kinds" -- "$cur"));     return 0;;
        --format)      COMPREPLY=($(compgen -W "$formats" -- "$cur"));   return 0;;
        --min-severity)COMPREPLY=($(compgen -W "$severities" -- "$cur"));return 0;;
        --profile)     COMPREPLY=($(compgen -W "$profiles" -- "$cur"));  return 0;;
        --bulk-format) COMPREPLY=($(compgen -W "plain jsonl" -- "$cur"));return 0;;
        --bulk|--out|--html|--md)
                       COMPREPLY=($(compgen -f -- "$cur"));              return 0;;
        cache)         COMPREPLY=($(compgen -W "stats clear clear-expired" -- "$cur")); return 0;;
        completion)    COMPREPLY=($(compgen -W "bash zsh fish" -- "$cur"));return 0;;
    esac

    if [ "$COMP_CWORD" -eq 1 ]; then
        # First word: subcommand or option
        COMPREPLY=($(compgen -W "$subs $flags" -- "$cur"))
    else
        # Subsequent: just flags
        COMPREPLY=($(compgen -W "$flags" -- "$cur"))
    fi
}
complete -F _osint osint
