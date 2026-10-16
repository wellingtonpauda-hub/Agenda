# Agenda Nuvem v0.3

React + Vite + Cloudflare Worker + D1. Login e cadastro de usuários com permissões de administrador.

## Publicação
1. Execute `migrations/0002_sessoes.sql` no Console D1, **um comando por vez** se necessário.
2. Substitua os arquivos no repositório GitHub pelos arquivos deste pacote (preserve as pastas). O Cloudflare faz deploy com `npm run build` e `npx wrangler deploy`.
3. **Antes do primeiro login**, em um computador com Node.js 18+, execute `node scripts/gerar-admin.mjs`. Digite os dados de administrador localmente. A senha ficará visível no terminal durante a digitação: use um local privado e não grave a sessão. Copie o comando `INSERT` produzido e execute **somente** no Console do D1. Não coloque esse SQL no GitHub nem compartilhe seu resultado, pois contém um hash de senha.
4. Acesse `/` e faça login com os dados do administrador.
5. Abra Usuários e cadastre contas adicionais.

## Segurança e limites desta versão
- Senhas PBKDF2-SHA256, 210.000 iterações, salt aleatório; cookies HttpOnly, Secure, SameSite=Strict; sessões de 7 dias no D1, com tokens aleatórios armazenados como SHA-256.
- API `/api/usuarios` é restrita a ADMIN; `/api/me` exige sessão; `/api/health` é pública.
- **Não recomendado para produção com dados sensíveis ainda**: adicionar rate limiting ao login, proteção CSRF adicional, recuperação/troca de senha, revogação de sessões, logs/auditoria e testes de segurança. A API aplica verificação básica de Origin; chamadas sem Origin (clientes não-browser) dependem da autenticação.
- A agenda ainda é **temporária, apenas em memória**, e será conectada ao D1 na próxima versão. A interface está protegida por login, mas os arquivos estáticos são públicos, como é normal em SPAs.
- O gerador do primeiro administrador é para uso local e não cria rota pública de bootstrap.
