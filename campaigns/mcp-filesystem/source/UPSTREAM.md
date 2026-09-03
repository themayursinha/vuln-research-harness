# Upstream pin

Official Filesystem MCP Server from the Model Context Protocol reference
servers repository.

- Repository: https://github.com/modelcontextprotocol/servers
- Path: `src/filesystem`
- Commit: `d73f99efbfd40c3aa1b61e88728b3d49fb52608f` (2026-09-02)
- npm: `@modelcontextprotocol/server-filesystem`
- License: MCP mixed MIT / Apache-2.0 (see `LICENSE` in this directory)

Vendored files are the upstream TypeScript sources at that commit.
`tsconfig.json` is a standalone copy of the monorepo compiler options so the
fixture can build without the rest of `servers/`. `package.json` is
unmodified; the image install uses `npm install --ignore-scripts` so
upstream `prepare` does not run.

Synthetic fixture files (not upstream): `sandbox/public.txt`,
`outside/secret.txt`.
