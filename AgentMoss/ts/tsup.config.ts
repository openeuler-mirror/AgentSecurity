import { defineConfig } from 'tsup';

export default defineConfig({
  // cli.ts is the CLI binary; server.ts + coordinator.ts are the programmatic
  // library entries (importable via the `exports` map in package.json) so
  // consumers can start the HTTP server in-process without spawning a child.
  entry: ['src/cli.ts', 'src/server.ts', 'src/engine/coordinator.ts'],
  format: ['esm'],
  target: 'node18',
  bundle: true,
  splitting: false,
  sourcemap: true,
  clean: true,
  dts: true,
  platform: 'node',
  shims: true,
  // Shebang handled by npm global install wrapper (package.json "bin" field)
});
