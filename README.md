# Agenda Nuvem — Protótipo 0.1

Interface inicial responsiva de um sistema de agenda, com menu lateral, dashboard e inclusão/exclusão de compromissos em memória.

## Requisitos
- Node.js 20.19+ ou 22.12+
- npm

## Executar localmente
```bash
npm install
npm run dev
```
Abra o endereço exibido no terminal (normalmente http://localhost:5173).

## Gerar versão de produção
```bash
npm run build
```
O resultado será gerado em `dist/`.

## Publicar gratuitamente no Cloudflare Pages
1. Crie um repositório GitHub e envie os arquivos deste projeto (não envie `node_modules`).
2. No Cloudflare, crie um projeto Pages conectado ao repositório GitHub.
3. Configure **Build command:** `npm run build` e **Build output directory:** `dist`.
4. Publique e abra a URL gerada `*.pages.dev`.

**ATENÇÃO:** esta versão é apenas um protótipo de interface. Os compromissos são mantidos em memória e somem ao recarregar a página. Não há autenticação real, banco de dados, API ou PWA instalável ainda. Não cadastre dados sensíveis. A implementação do Cloudflare D1 e autenticação será a próxima etapa.
