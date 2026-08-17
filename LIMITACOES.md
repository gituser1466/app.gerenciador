# Limitações conhecidas — 1.0.0

1. **Argon2d/Argon2id:** detectados, porém não abertos nesta release. O escritor usa AES-KDF oficial do KDBX.
2. **Cifrador externo:** somente AES-256-CBC. KDBX com ChaCha20 como cifrador externo não é aberto.
3. **Proteção interna:** somente ChaCha20 (algoritmo interno 3). KDBX antigos com Salsa20 protegido internamente são recusados.
4. **Key files externas:** a interface aceita somente key file binária de exatamente 32 bytes. XML key files do KeePass ainda não são interpretadas.
5. **Anexos/binaries KDBX:** a 1.0 gerencia credenciais, TOTP, notas, tags e favoritos. Anexos do KDBX importado não são apresentados e não devem ser regravados pelo Meu Cofre se você precisar preservá-los.
6. **Hierarquia de grupos:** grupos importados são percorridos, mas a UI 1.0 apresenta os itens em uma lista e não preserva a organização completa de grupos ao regravar.
7. **Campos customizados:** somente os campos usados pelo Meu Cofre e os principais campos KeePass são preservados pela UI. Não use esta release para editar um KDBX complexo se campos arbitrários forem importantes.
8. **AutoFill do iOS:** PWA não é uma extensão nativa de Credential Provider; portanto não oferece o mesmo AutoFill sistêmico de um app nativo.
9. **Memória:** não há garantia de zeroização de strings em JavaScript.
10. **Origem web:** controle malicioso da origem GitHub Pages pode substituir o próprio aplicativo. Use uma conta/repositório altamente protegidos.
11. **Auditoria:** não houve auditoria externa independente do código.
12. **Teste real 1.0:** YubiKey já funcionou nas versões 0.2.x no aparelho do usuário, mas o fluxo KDBX 1.0 precisa ser validado no mesmo iPhone antes de uso como único cofre.
