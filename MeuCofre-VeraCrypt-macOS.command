#!/bin/zsh
set -eu

# Meu Cofre - VeraCrypt macOS bridge v1.7.0
# Instala um helper local que recebe SOMENTE pacotes .vcmount cifrados para a
# chave publica deste Mac. A senha VeraCrypt e enviada ao VeraCrypt oficial por
# stdin; keyfiles sao recriados em um RAM disk e removidos apos a montagem.

APP_VERSION="1.7.0"
SUPPORT="$HOME/Library/Application Support/MeuCofreVeraCrypt"
PRIVATE_KEY="$SUPPORT/helper-private.pem"
PUBLIC_KEY="$SUPPORT/helper-public.pem"
HANDLER="$SUPPORT/bridge-handler.zsh"
PROFILES_DIR="$SUPPORT/profiles"
KEYCHAIN_SERVICE="MeuCofre VeraCrypt Helper Private Key"
PAIR_FILE="$HOME/Downloads/MeuCofre-VeraCrypt-macOS.mcpair"
HELPER_APP="$HOME/Applications/MeuCofre VeraCrypt Helper.app"
URL_SCHEME="meucofre-veracrypt"

mkdir -p "$SUPPORT" "$PROFILES_DIR" "$HOME/Applications" "$HOME/Downloads"
chmod 700 "$SUPPORT" "$PROFILES_DIR"

find_openssl() {
  local c
  for c in \
    "/opt/homebrew/opt/openssl@3/bin/openssl" \
    "/opt/homebrew/bin/openssl" \
    "/usr/local/opt/openssl@3/bin/openssl" \
    "/usr/local/bin/openssl" \
    "/usr/bin/openssl"; do
    [[ -x "$c" ]] && { print -r -- "$c"; return 0; }
  done
  command -v openssl 2>/dev/null || return 1
}

find_veracrypt() {
  local c
  for c in \
    "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt" \
    "/Applications/VeraCrypt_FUSE-T.app/Contents/MacOS/VeraCrypt" \
    "/opt/homebrew/bin/veracrypt" \
    "/usr/local/bin/veracrypt"; do
    [[ -x "$c" ]] && { print -r -- "$c"; return 0; }
  done
  command -v veracrypt 2>/dev/null || return 1
}

OPENSSL="$(find_openssl || true)"
if [[ -z "$OPENSSL" ]]; then
  print "OpenSSL nao encontrado. Instale OpenSSL 3 pelo Homebrew e execute novamente."
  exit 1
fi

install_keys() {
  if [[ -s "$PRIVATE_KEY" && -s "$PUBLIC_KEY" ]]; then
    return 0
  fi
  print "== Gerando chave RSA-4096 exclusiva deste Mac =="
  local pass
  pass="$($OPENSSL rand -hex 32)"
  /usr/bin/security add-generic-password -a "$USER" -s "$KEYCHAIN_SERVICE" -w "$pass" -U >/dev/null
  "$OPENSSL" genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 2>/dev/null \
    | "$OPENSSL" pkey -aes-256-cbc -passout fd:3 -out "$PRIVATE_KEY" 3<<<"$pass"
  chmod 600 "$PRIVATE_KEY"
  "$OPENSSL" pkey -in "$PRIVATE_KEY" -passin fd:3 -pubout -out "$PUBLIC_KEY" 3<<<"$pass" >/dev/null 2>&1
  chmod 644 "$PUBLIC_KEY"
  pass=""
}

install_handler() {
  cat > "$HANDLER" <<'HANDLER_EOF'
#!/bin/zsh
set -eu
setopt NULL_GLOB

APP_VERSION="1.7.0"
SUPPORT="$HOME/Library/Application Support/MeuCofreVeraCrypt"
PRIVATE_KEY="$SUPPORT/helper-private.pem"
PUBLIC_KEY="$SUPPORT/helper-public.pem"
PROFILES_DIR="$SUPPORT/profiles"
KEYCHAIN_SERVICE="MeuCofre VeraCrypt Helper Private Key"
LOG="$SUPPORT/bridge.log"

mkdir -p "$SUPPORT" "$PROFILES_DIR"
chmod 700 "$SUPPORT" "$PROFILES_DIR"
touch "$LOG"; chmod 600 "$LOG"
exec 2>>"$LOG"

find_openssl() {
  local c
  for c in "/opt/homebrew/opt/openssl@3/bin/openssl" "/opt/homebrew/bin/openssl" "/usr/local/opt/openssl@3/bin/openssl" "/usr/local/bin/openssl" "/usr/bin/openssl"; do
    [[ -x "$c" ]] && { print -r -- "$c"; return 0; }
  done
  command -v openssl 2>/dev/null || return 1
}
find_veracrypt() {
  local c
  for c in "/Applications/VeraCrypt.app/Contents/MacOS/VeraCrypt" "/Applications/VeraCrypt_FUSE-T.app/Contents/MacOS/VeraCrypt" "/opt/homebrew/bin/veracrypt" "/usr/local/bin/veracrypt"; do
    [[ -x "$c" ]] && { print -r -- "$c"; return 0; }
  done
  command -v veracrypt 2>/dev/null || return 1
}
alert() {
  local msg="$1"
  /usr/bin/osascript -e 'on run argv' -e 'display dialog (item 1 of argv) buttons {"OK"} default button "OK" with icon caution' -e 'end run' "$msg" >/dev/null 2>&1 || true
}
notify_ok() {
  local msg="$1"
  /usr/bin/osascript -e 'on run argv' -e 'display notification (item 1 of argv) with title "Meu Cofre + VeraCrypt"' -e 'end run' "$msg" >/dev/null 2>&1 || true
}
choose_package() {
  /usr/bin/osascript -e 'POSIX path of (choose file with prompt "Selecione o pacote .vcmount gerado pelo Meu Cofre")' 2>/dev/null || true
}
choose_volume() {
  /usr/bin/osascript -e 'POSIX path of (choose file with prompt "Selecione o container VeraCrypt correspondente a este perfil")' 2>/dev/null || true
}
latest_package() {
  local files=("$HOME/Downloads"/*.vcmount "$HOME/Desktop"/*.vcmount)
  if (( ${#files[@]} == 0 )); then print -r -- ""; return 0; fi
  /bin/ls -t "${files[@]}" 2>/dev/null | /usr/bin/head -n 1
}
extract() {
  /usr/bin/plutil -extract "$2" raw -o - "$1" 2>/dev/null
}
base64_decode_to() {
  print -rn -- "$1" | /usr/bin/base64 -D > "$2"
}
file_size() { /usr/bin/stat -f%z "$1"; }
container_fingerprint() {
  local volume="$1" hidden="$2" size
  size="$(file_size "$volume")"
  if [[ "$hidden" == "true" ]]; then
    { /bin/dd if="$volume" bs=512 skip=128 count=1 2>/dev/null; printf '\0%s' "$size"; } | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
  else
    { /bin/dd if="$volume" bs=512 count=1 2>/dev/null; printf '\0%s' "$size"; } | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}'
  fi
}

OPENSSL="$(find_openssl || true)"
VC="$(find_veracrypt || true)"
[[ -n "$OPENSSL" ]] || { alert "OpenSSL nao encontrado."; exit 1; }
[[ -n "$VC" ]] || { alert "VeraCrypt oficial nao encontrado em /Applications nem no PATH."; exit 1; }
[[ -s "$PRIVATE_KEY" && -s "$PUBLIC_KEY" ]] || { alert "Chaves do helper ausentes. Execute novamente o instalador MeuCofre-VeraCrypt-macOS.command."; exit 1; }

PACKAGE=""
if [[ "${1:-}" == "--latest" ]]; then
  PACKAGE="$(latest_package)"
elif [[ -n "${1:-}" && -f "${1:-}" ]]; then
  PACKAGE="$1"
fi
[[ -n "$PACKAGE" && -f "$PACKAGE" ]] || PACKAGE="$(choose_package)"
[[ -n "$PACKAGE" && -f "$PACKAGE" ]] || exit 0

FORMAT="$(extract "$PACKAGE" format || true)"
VERSION="$(extract "$PACKAGE" version || true)"
PROFILE_ID="$(extract "$PACKAGE" profileId || true)"
EXPECTED_FP="$(extract "$PACKAGE" headerFingerprint || true)"
EXPECTED_SIZE="$(extract "$PACKAGE" containerSize || true)"
EXPIRES="$(extract "$PACKAGE" expiresUnix || true)"
ITER="$(extract "$PACKAGE" kdfIterations || true)"
SALT_B64="$(extract "$PACKAGE" salt || true)"
ENCSECRET_B64="$(extract "$PACKAGE" encryptedSecret || true)"
CIPHERTEXT_B64="$(extract "$PACKAGE" ciphertext || true)"
MAC_B64="$(extract "$PACKAGE" mac || true)"
HELPER_FP="$(extract "$PACKAGE" helperFingerprint || true)"

if [[ "$FORMAT" != "meucofre-veracrypt-macos-mount-v1" || "$VERSION" != "1" ]]; then alert "Pacote .vcmount invalido ou de versao desconhecida."; exit 1; fi
if [[ ! "$PROFILE_ID" =~ '^[0-9A-Za-z._-]+$' ]]; then alert "Identificador de perfil invalido."; exit 1; fi
NOW="$(date +%s)"
if [[ -z "$EXPIRES" || "$EXPIRES" -lt "$NOW" ]]; then alert "Este pacote de montagem expirou. Gere outro no Meu Cofre usando a YubiKey."; exit 1; fi
if [[ "$ITER" != "200000" ]]; then alert "KDF do bridge nao reconhecido."; exit 1; fi

PRIVPASS="$(/usr/bin/security find-generic-password -a "$USER" -s "$KEYCHAIN_SERVICE" -w 2>/dev/null || true)"
[[ -n "$PRIVPASS" ]] || { alert "Nao foi possivel ler a chave do helper no Keychain."; exit 1; }
LOCAL_FP="$("$OPENSSL" pkey -pubin -in "$PUBLIC_KEY" -outform DER 2>/dev/null | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
if [[ "$HELPER_FP" != "$LOCAL_FP" ]]; then alert "O pacote foi cifrado para outro Mac/helper. Importe novamente o .mcpair deste Mac no Meu Cofre."; exit 1; fi

RAMDEV=""
RAMVOL=""
cleanup() {
  local rc=$?
  PASSWORD=""; SECRET_HEX=""; PRIVPASS=""; MACKEY_HEX=""
  if [[ -n "$RAMDEV" ]]; then /usr/bin/hdiutil detach "$RAMDEV" -force >/dev/null 2>&1 || true; fi
  exit $rc
}
trap cleanup EXIT INT TERM

RAMDEV="$(/usr/bin/hdiutil attach -nomount ram://65536 | /usr/bin/head -n 1 | /usr/bin/awk '{print $1}')"
[[ -n "$RAMDEV" ]] || { alert "Falha ao criar RAM disk temporario."; exit 1; }
RAMNAME="MCVCRAM-$$"
/usr/sbin/diskutil eraseVolume HFS+ "$RAMNAME" "$RAMDEV" >/dev/null
RAMVOL="/Volumes/$RAMNAME"
chmod 700 "$RAMVOL" 2>/dev/null || true

base64_decode_to "$ENCSECRET_B64" "$RAMVOL/secret.rsa"
base64_decode_to "$CIPHERTEXT_B64" "$RAMVOL/payload.enc"
SECRET_HEX="$("$OPENSSL" pkeyutl -decrypt -inkey "$PRIVATE_KEY" -passin fd:3 -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256 -pkeyopt rsa_mgf1_md:sha256 -in "$RAMVOL/secret.rsa" 3<<<"$PRIVPASS" 2>/dev/null || true)"
if [[ ! "$SECRET_HEX" =~ '^[0-9a-fA-F]{64}$' ]]; then alert "Nao foi possivel descriptografar o pacote com a chave privada deste Mac."; exit 1; fi

MACKEY_HEX="$(printf 'MeuCofreVeraCryptBridge-MAC-v1\0%s' "$SECRET_HEX" | "$OPENSSL" dgst -sha256 -binary | /usr/bin/xxd -p -c 256)"
printf '%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s' \
  "$FORMAT" "$VERSION" "$PROFILE_ID" "$EXPECTED_FP" "$EXPECTED_SIZE" "$EXPIRES" "$ITER" "$SALT_B64" "$ENCSECRET_B64" "$CIPHERTEXT_B64" > "$RAMVOL/canonical.txt"
CALC_MAC="$("$OPENSSL" dgst -sha256 -mac HMAC -macopt "hexkey:$MACKEY_HEX" -binary "$RAMVOL/canonical.txt" | /usr/bin/base64 | /usr/bin/tr -d '\n')"
if [[ "$CALC_MAC" != "$MAC_B64" ]]; then alert "Pacote .vcmount adulterado ou corrompido."; exit 1; fi

print -rn -- "$SALT_B64" | /usr/bin/base64 -D > "$RAMVOL/salt.bin"
SALT_HEX="$(/usr/bin/xxd -p -c 256 "$RAMVOL/salt.bin")"
printf '%s' "$SECRET_HEX" | "$OPENSSL" enc -d -aes-256-cbc -pbkdf2 -iter "$ITER" -md sha256 -S "$SALT_HEX" -pass stdin -in "$RAMVOL/payload.enc" -out "$RAMVOL/payload.json" 2>/dev/null || { alert "Falha ao abrir o pacote de credenciais."; exit 1; }
chmod 600 "$RAMVOL/payload.json"

PFORMAT="$(extract "$RAMVOL/payload.json" format || true)"
PVER="$(extract "$RAMVOL/payload.json" version || true)"
PPROFILE="$(extract "$RAMVOL/payload.json" profileId || true)"
[[ "$PFORMAT" == "meucofre-veracrypt-mount-credentials-v1" && "$PVER" == "1" && "$PPROFILE" == "$PROFILE_ID" ]] || { alert "Conteudo interno do pacote invalido."; exit 1; }
PASSWORD="$(extract "$RAMVOL/payload.json" password || true)"
PIM="$(extract "$RAMVOL/payload.json" pim || true)"; [[ -n "$PIM" ]] || PIM=0
HASH="$(extract "$RAMVOL/payload.json" hash || true)"; [[ -n "$HASH" ]] || HASH=auto
HIDDEN="$(extract "$RAMVOL/payload.json" hidden || true)"; [[ -n "$HIDDEN" ]] || HIDDEN=false
KEYCOUNT="$(extract "$RAMVOL/payload.json" keyfileCount || true)"; [[ -n "$KEYCOUNT" ]] || KEYCOUNT=0
if [[ "$KEYCOUNT" -lt 0 || "$KEYCOUNT" -gt 32 ]]; then alert "Quantidade de keyfiles invalida."; exit 1; fi

KEYPATHS=()
if (( KEYCOUNT > 0 )); then
  local_i=0
  while (( local_i < KEYCOUNT )); do
    DATA="$(extract "$RAMVOL/payload.json" "keyfiles.${local_i}.data" || true)"
    KF="$RAMVOL/keyfile-$((local_i+1)).bin"
    base64_decode_to "$DATA" "$KF"
    chmod 600 "$KF"
    KEYPATHS+=("$KF")
    DATA=""
    local_i=$((local_i+1))
  done
fi

MAPFILE="$PROFILES_DIR/$PROFILE_ID.path"
VOLUME=""
if [[ -s "$MAPFILE" ]]; then VOLUME="$(cat "$MAPFILE")"; fi
verify_volume() {
  local v="$1" size fp
  [[ -f "$v" ]] || return 1
  size="$(file_size "$v")"; [[ "$size" == "$EXPECTED_SIZE" ]] || return 1
  fp="$(container_fingerprint "$v" "$HIDDEN")"; [[ "$fp" == "$EXPECTED_FP" ]]
}
if ! verify_volume "$VOLUME"; then
  VOLUME="$(choose_volume)"
  [[ -n "$VOLUME" ]] || exit 0
  if ! verify_volume "$VOLUME"; then alert "O arquivo selecionado nao corresponde ao vault vinculado (tamanho/fingerprint do header divergentes)."; exit 1; fi
  print -rn -- "$VOLUME" > "$MAPFILE"; chmod 600 "$MAPFILE"
fi

# UX v1.7: montar novamente um vault que ja esta aberto nao e erro.
# O --list aceita o caminho do volume montado e nao envolve credenciais.
set +e
MOUNTED_INFO="$("$VC" -t --list "$VOLUME" 2>&1)"
MOUNTED_RC=$?
set -e
if [[ $MOUNTED_RC -eq 0 && -n "$MOUNTED_INFO" ]]; then
  print "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] already-mounted profile=$PROFILE_ID volume=$VOLUME" >> "$LOG"
  rm -f "$PACKAGE" 2>/dev/null || true
  notify_ok "Este vault ja esta montado no Finder."
  /usr/bin/open /Volumes >/dev/null 2>&1 || true
  exit 0
fi
MOUNTED_INFO=""

ARGS=(-t --non-interactive --stdin "--pim=$PIM" --protect-hidden=no)
if [[ "$HASH" != "auto" ]]; then ARGS+=("--hash=$HASH"); fi
if [[ "$HIDDEN" == "true" ]]; then ARGS+=(--volume-type=hidden); fi
if (( ${#KEYPATHS[@]} > 0 )); then
  KEYCSV="${(j:,:)KEYPATHS}"
  ARGS+=(-k "$KEYCSV")
fi
ARGS+=(--mount "$VOLUME")

print "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] mount profile=$PROFILE_ID volume=$VOLUME" >> "$LOG"
VC_OUT="$RAMVOL/veracrypt-output.txt"
set +e
printf '%s\n' "$PASSWORD" | "$VC" "${ARGS[@]}" >"$VC_OUT" 2>&1
RC=$?
set -e
cat "$VC_OUT" >>"$LOG" 2>/dev/null || true
PASSWORD=""; SECRET_HEX=""; PRIVPASS=""; MACKEY_HEX=""
if [[ $RC -ne 0 ]]; then
  if /usr/bin/grep -qi "already mounted" "$VC_OUT" 2>/dev/null; then
    print "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] already-mounted-after-attempt profile=$PROFILE_ID volume=$VOLUME" >> "$LOG"
    rm -f "$PACKAGE" 2>/dev/null || true
    notify_ok "Este vault ja esta montado no Finder."
    /usr/bin/open /Volumes >/dev/null 2>&1 || true
    exit 0
  fi
  alert "O VeraCrypt nao conseguiu montar o vault. Consulte $LOG. O pacote .vcmount foi mantido para diagnostico."
  exit $RC
fi
rm -f "$PACKAGE" 2>/dev/null || true
notify_ok "Vault montado no Finder."
/usr/bin/open /Volumes >/dev/null 2>&1 || true
exit 0
HANDLER_EOF
  chmod 700 "$HANDLER"
}

install_app() {
  local src="$SUPPORT/helper.applescript"
  cat > "$src" <<APPLESCRIPT_EOF
on run
  do shell script "/bin/zsh " & quoted form of "$HANDLER" & " --latest >/dev/null 2>&1 &"
end run

on open droppedItems
  repeat with anItem in droppedItems
    set p to POSIX path of anItem
    do shell script "/bin/zsh " & quoted form of "$HANDLER" & " " & quoted form of p & " >/dev/null 2>&1 &"
  end repeat
end open

on open location theURL
  do shell script "/bin/zsh " & quoted form of "$HANDLER" & " --latest >/dev/null 2>&1 &"
end open location
APPLESCRIPT_EOF
  rm -rf "$HELPER_APP"
  /usr/bin/osacompile -o "$HELPER_APP" "$src" >/dev/null
  local plist="$HELPER_APP/Contents/Info.plist"
  /usr/libexec/PlistBuddy -c "Set :CFBundleIdentifier com.meucofre.veracrypthelper" "$plist" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Delete :CFBundleURLTypes" "$plist" >/dev/null 2>&1 || true
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes array" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0 dict" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLName string com.meucofre.veracrypthelper" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes array" "$plist"
  /usr/libexec/PlistBuddy -c "Add :CFBundleURLTypes:0:CFBundleURLSchemes:0 string $URL_SCHEME" "$plist"
  /usr/bin/codesign --force --deep --sign - "$HELPER_APP" >/dev/null 2>&1 || true
  local lsreg="/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister"
  [[ -x "$lsreg" ]] && "$lsreg" -f "$HELPER_APP" >/dev/null 2>&1 || true
}

install_keys
install_handler
install_app
cp "$PUBLIC_KEY" "$PAIR_FILE"
chmod 644 "$PAIR_FILE"

VC="$(find_veracrypt || true)"
clear
print "Meu Cofre - VeraCrypt macOS bridge v$APP_VERSION"
print
print "Helper instalado em:"
print "  $HELPER_APP"
print
print "Arquivo de pareamento (CHAVE PUBLICA, nao e segredo):"
print "  $PAIR_FILE"
print
if [[ -z "$VC" ]]; then
  print "ATENCAO: VeraCrypt oficial nao foi encontrado. Instale-o antes de montar."
else
  print "VeraCrypt: $VC"
fi
print
print "Agora, no Meu Cofre:"
print "  Vault VeraCrypt -> Integracao macOS -> Importar pareamento .mcpair"
print "Depois use 'Montar no Finder' no vault vinculado."
print
if [[ "${1:-}" == "--install-only" ]]; then
  print "Instalacao/atualizacao concluida."
  exit 0
fi
print "Opcoes:"
print "  1) Montar agora o pacote .vcmount mais recente"
print "  2) Escolher um pacote .vcmount"
print "  3) Abrir VeraCrypt oficial"
print "  4) Mostrar pasta do helper"
print "  0) Sair"
print
read -r "?Opcao: " opt
case "$opt" in
  1) /bin/zsh "$HANDLER" --latest ;;
  2) /bin/zsh "$HANDLER" ;;
  3) /usr/bin/open -a VeraCrypt 2>/dev/null || [[ -n "$VC" ]] && /usr/bin/open "$VC" ;;
  4) /usr/bin/open "$SUPPORT" ;;
  *) ;;
esac
