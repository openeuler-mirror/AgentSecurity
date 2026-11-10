/**
 * Single source of truth for the package version.
 * Read from package.json at runtime using createRequire — works in both ESM and bundled environments.
 */
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
// Resolve relative to this source file's location → ts/package.json
const pkg = require('../package.json');

/** Version string from package.json — the ONLY place version is defined */
export const version: string = pkg.version;
