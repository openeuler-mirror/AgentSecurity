/**
 * Script-engine language backends.
 * Mirrors Python agent_moss/engine/script_engine/backends/.
 */

import type { ScriptIR } from '../ir';

export interface LanguageBackend {
  language: string;
  /** Parse script content into IR. entryArgs may be null (no entry params). */
  parse(content: string, entryArgs: string[] | null): ScriptIR;
}

export * from './shell-backend';
export { ShellBackend } from './shell-backend';
export { PythonBackend } from './python-backend';