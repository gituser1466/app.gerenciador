# Segurança — Meu Cofre 1.0.0

## Modelo de ameaça

A 1.0 tenta proteger contra:

- perda/roubo do arquivo KDBX sem os componentes corretos da chave;
- corrupção/adulteração do KDBX;
- leitura casual dos dados armazenados no IndexedDB;
- tentativa offline de senha, limitada pelo KDF configurado;
- uso do componente YubiKey sem a credencial WebAuthn correspondente;
- atualização parcial/corrompida dos arquivos do PWA;
- XSS acidental pela interface do cofre;
- permanência desnecessária do cofre aberto quando o app vai para segundo plano.

Não consegue proteger completamente contra:

- iPhone comprometido/jailbroken, navegador ou sistema operacional malicioso;
- extensões/perfis MDM maliciosos capazes de observar o aparelho;
- comprometimento da conta GitHub/origem HTTPS que permita substituir todo o código do PWA;
- captura de tela/câmera física enquanto um segredo está visível;
- coerção do usuário;
- falhas desconhecidas do Safari/WebAuthn/WebCrypto;
- retenção de strings sensíveis pelo garbage collector do JavaScript.

## Controles implementados

### KDBX

- KDBX 4.1.
- hash SHA-256 do cabeçalho verificado antes da abertura.
- HMAC-SHA-256 do cabeçalho com chave derivada do master key.
- HMAC-SHA-256 por bloco do conteúdo cifrado.
- AES-256-CBC via WebCrypto para o conteúdo externo.
- ChaCha20 para valores protegidos internos.
- nova seed/IV/chave interna aleatória em cada regravação.
- limites para tamanho do arquivo, XML, campos do cabeçalho, quantidade de slots e custo AES-KDF importado.
- rejeição de cabeçalhos/VariantDictionary truncados, duplicados ou com dados extras.
- rejeição de DTD/ENTITY no XML importado.

### Chaves

- `crypto.getRandomValues` para aleatoriedade.
- senha KeePass convertida em SHA-256 conforme composição KDBX.
- YubiKey/WebAuthn PRF retorna um segredo usado por HKDF-SHA-256.
- componente KDBX protegido por AES-256-GCM com nonce aleatório e AAD vinculada ao slot.
- `userVerification: required` no WebAuthn.
- `attestation: none`, evitando coletar atestado identificável sem necessidade.
- múltiplas YubiKeys possíveis.
- chave de recuperação independente de 32 bytes para modos YubiKey.

### Aplicação web

- HTTPS/contexto seguro obrigatório.
- recusa execução em iframe.
- Content Security Policy restritiva.
- sem JavaScript inline.
- sem CDN, bibliotecas remotas, analytics, WebSocket ou `sendBeacon`.
- UI usa `textContent`/`value`, não `innerHTML`.
- apenas URLs HTTP/HTTPS podem ser abertas e em nova janela com `noopener,noreferrer`.
- bloqueio imediato ao ir para segundo plano por padrão.
- temporizador de inatividade.
- limpeza best-effort da área de transferência.
- o IndexedDB guarda o envelope KDBX cifrado, não o cofre aberto.

### Atualizações

- Service Worker não ativa uma versão nova automaticamente durante atualização normal.
- arquivos críticos da release são verificados por SHA-256 no `install` do novo Service Worker.
- se um arquivo faltar ou tiver hash diferente, a instalação do novo shell falha e a versão anterior permanece.
- `version.json` é consultado sem cache.

## Observação sobre memória

JavaScript não oferece garantia de `mlock`, zeroização de strings ou controle total do garbage collector. Arrays `Uint8Array` sensíveis são sobrescritos quando possível, mas senhas convertidas em strings/DOM podem permanecer na memória do processo por tempo indeterminado. Isso é uma limitação estrutural da plataforma web.

## KDF

A 1.0 escreve AES-KDF, um KDF oficial do KDBX, calibrado para cerca de 1 segundo no dispositivo e limitado a 2.000.000 de rodadas para evitar travamentos/DoS na importação.

Argon2id é mais resistente a hardware altamente paralelo e é preferível para bancos puramente protegidos por senha. Esta release não inclui Argon2id porque não foi incluída uma implementação auditada/vendorada para o navegador; ela recusa esses bancos em vez de tentar uma implementação caseira. Para máxima proteção, o modo **Senha + YubiKey** adiciona um segundo componente aleatório independente da senha.
