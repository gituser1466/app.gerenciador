# Changelog

## 1.0.0 — 2026-08-17

- KDBX 4.1 como formato canônico.
- três modos de proteção: senha, YubiKey, senha + YubiKey.
- recuperação por key file binária de 32 bytes.
- múltiplas YubiKeys/passkeys com WebAuthn PRF.
- AES-KDF calibrado por dispositivo (~1 s).
- AES-256-CBC externo e ChaCha20 para valores protegidos.
- verificação integral de cabeçalho e blocos HMAC.
- importação KDBX AES-KDF e GZip quando suportado pelo navegador.
- migração direta do envelope `.mcvault` v0.2.x.
- CSP endurecida e remoção de dependências remotas/inline.
- bloqueio imediato em segundo plano como padrão para novos cofres.
- Service Worker com hashes SHA-256 da release e atualização confirmada.
- limites defensivos de tamanho/custo na leitura de KDBX.
- documentação de ameaça, limitações, migração e testes.

## 0.2.2

- correção da barra inferior fixa no iPhone.

## 0.2.1

- correção do fluxo de atualização/cache no iOS.

## 0.2.0

- políticas YubiKey, múltiplos métodos e dois fatores no formato legado.
