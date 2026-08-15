/**
 * The adapter registry. `herkos init` detects which harnesses are installed and
 * wires each — so the user writes one policy and every installed harness obeys
 * it. Adding a harness is adding an entry here plus its adapter module.
 */
import type { HarnessAdapter } from "./types.js";
import { claudeCodeAdapter } from "./claude-code.js";
import { codexAdapter } from "./codex.js";

export const ADAPTERS: HarnessAdapter[] = [claudeCodeAdapter, codexAdapter];

export function detectInstalled(): HarnessAdapter[] {
  return ADAPTERS.filter((a) => a.detect().installed);
}
