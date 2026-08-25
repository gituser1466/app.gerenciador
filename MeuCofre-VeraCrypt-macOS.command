#!/bin/zsh
set -u

# Meu Cofre - Helper VeraCrypt macOS v1.5.0
# Este helper chama o VeraCrypt oficial. Ele nao recebe senhas pela linha de comando;
# operacoes sensiveis permanecem interativas dentro do VeraCrypt.

find_veracrypt() {
  local candidates=(
    "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt"
    "/Applications/VeraCrypt_FUSE-T.app/Contents/MacOS/VeraCrypt"
    "/opt/homebrew/bin/veracrypt"
    "/usr/local/bin/veracrypt"
  )
  local c
  for c in "${candidates[@]}"; do
    if [[ -x "$c" ]]; then print -r -- "$c"; return 0; fi
  done
  if command -v veracrypt >/dev/null 2>&1; then command -v veracrypt; return 0; fi
  return 1
}

VC="$(find_veracrypt || true)"
if [[ -z "$VC" ]]; then
  print "VeraCrypt nao encontrado. Instale/abra o VeraCrypt oficial e execute novamente."
  print "Caminhos verificados: /Applications/VeraCrypt.app e PATH."
  exit 1
fi

pause() { print; read -r "?Pressione Enter para continuar..."; }
ask_path() { local prompt="$1"; local value; read -r "?${prompt}: " value; print -r -- "$value"; }

run_interactive() {
  print
  print "Executando: VeraCrypt (modo texto/interativo)"
  "$VC" -t "$@"
  local rc=$?
  print "Codigo de saida: $rc"
  return $rc
}

while true; do
  clear
  print "Meu Cofre - VeraCrypt macOS helper v1.5.0"
  print "Binario: $VC"
  print
  print " 1) Abrir interface grafica do VeraCrypt"
  print " 2) Criar novo volume (assistente oficial)"
  print " 3) Montar volume"
  print " 4) Montar volume somente leitura"
  print " 5) Desmontar volume"
  print " 6) Desmontar todos"
  print " 7) Listar volumes montados"
  print " 8) Propriedades de volume montado"
  print " 9) Alterar senha / PIM / keyfiles / KDF"
  print "10) Backup oficial dos headers"
  print "11) Restaurar headers"
  print "12) Criar keyfile aleatorio oficial"
  print "13) Listar keyfiles de token/smart card"
  print "14) Importar keyfile para token/smart card"
  print "15) Exportar keyfile de token/smart card"
  print "16) Excluir keyfiles de token/smart card"
  print "17) Auto-montar favoritos"
  print "18) Teste criptografico interno do VeraCrypt"
  print "19) Versao e ajuda completa"
  print " 0) Sair"
  print
  read -r "?Opcao: " opt
  case "$opt" in
    1) open -a VeraCrypt 2>/dev/null || open "$VC"; pause ;;
    2) run_interactive --create; pause ;;
    3)
      vol="$(ask_path 'Caminho do volume')"
      [[ -n "$vol" ]] && run_interactive --mount "$vol"
      pause ;;
    4)
      vol="$(ask_path 'Caminho do volume')"
      [[ -n "$vol" ]] && run_interactive --mount-options=readonly --mount "$vol"
      pause ;;
    5)
      vol="$(ask_path 'Volume/caminho/ponto montado (vazio = escolher interativamente)')"
      if [[ -n "$vol" ]]; then run_interactive --unmount "$vol"; else run_interactive --unmount; fi
      pause ;;
    6) run_interactive --unmount; pause ;;
    7) run_interactive --verbose --list; pause ;;
    8)
      vol="$(ask_path 'Volume montado (caminho, dispositivo virtual ou ponto de montagem)')"
      [[ -n "$vol" ]] && run_interactive --volume-properties "$vol"
      pause ;;
    9)
      vol="$(ask_path 'Caminho do volume')"
      [[ -n "$vol" ]] && run_interactive --change "$vol"
      pause ;;
    10)
      vol="$(ask_path 'Caminho do volume')"
      [[ -n "$vol" ]] && run_interactive --backup-headers "$vol"
      pause ;;
    11)
      vol="$(ask_path 'Caminho do volume')"
      [[ -n "$vol" ]] && run_interactive --restore-headers "$vol"
      pause ;;
    12)
      out="$(ask_path 'Caminho do novo keyfile')"
      [[ -n "$out" ]] && run_interactive --create-keyfile "$out"
      pause ;;
    13) run_interactive --list-token-keyfiles; pause ;;
    14) run_interactive --import-token-keyfiles; pause ;;
    15) run_interactive --export-token-keyfile; pause ;;
    16) run_interactive --delete-token-keyfiles; pause ;;
    17) run_interactive --auto-mount=favorites; pause ;;
    18) run_interactive --test; pause ;;
    19) "$VC" -t --version; print; "$VC" -t --help | less; ;;
    0) exit 0 ;;
    *) print "Opcao invalida."; pause ;;
  esac
done
