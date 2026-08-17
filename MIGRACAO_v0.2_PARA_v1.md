# Migração v0.2.2 -> v1.0.0 KDBX

## Antes de atualizar o GitHub

1. Abra a v0.2.2 pelo ícone do iPhone.
2. Desbloqueie normalmente.
3. Em Segurança, exporte o backup `.mcvault`.
4. Confirme no app Arquivos que o arquivo realmente existe.
5. Não limpe os dados do Safari/PWA e não remova o ícone.

## Atualizar os arquivos

1. Extraia `MeuCofre_GitHubPages_v1.0.0.zip`.
2. No mesmo repositório GitHub Pages, envie todos os arquivos para a raiz.
3. Mantenha exatamente o mesmo usuário, repositório e endereço HTTPS.
4. Aguarde o Pages concluir o deploy.
5. Abra o PWA com internet e aceite o banner de atualização.

Manter a origem é importante porque o IndexedDB legado e as credenciais WebAuthn existentes pertencem à origem atual.

## Migrar o cofre

1. Desbloqueie o formato legado com o método atual.
2. Abra **Segurança > Migração obrigatória**.
3. Escolha:
   - `YubiKey`: uso diário sem senha; recuperação pelo `.key` de 32 bytes.
   - `Senha + YubiKey`: exige os dois fatores; recuperação/interoperabilidade exige a senha + `.key`.
   - `Senha`: somente se você realmente desejar dispensar YubiKey.
4. Se usar YubiKey, escolha a credencial já cadastrada e toque na chave quando solicitado.
5. Aguarde a geração do KDBX. Em iPhone o AES-KDF é calibrado para aproximadamente 1 segundo no aparelho.
6. O aplicativo baixa automaticamente:
   - uma cópia `.mcvault` do estado antigo;
   - o novo `.kdbx`;
   - e, se aplicável, a chave `.key` de recuperação.

## Validação obrigatória

Antes de apagar qualquer backup antigo:

1. Bloqueie o cofre.
2. Abra com a YubiKey.
3. Repita o processo três vezes.
4. Confirme uma senha de teste e um TOTP de teste.
5. Exporte um novo `.kdbx`.
6. Teste **Recuperação com arquivo de chave**:
   - YubiKey: `.key` sozinho;
   - Senha + YubiKey: senha + `.key`.
7. Ative modo avião, feche e abra o PWA e confirme o funcionamento offline.
8. Volte à internet e confirme que nenhuma atualização é ativada sem sua confirmação.

## Depois da migração

- Mantenha o `.kdbx` em pelo menos dois locais seguros.
- Guarde a `.key` separadamente do `.kdbx` sempre que possível.
- Cadastre uma segunda YubiKey como reserva.
- Não mantenha a única `.key` somente no mesmo iPhone.
