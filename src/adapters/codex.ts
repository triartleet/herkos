/**
 * Codex CLI adapter (config surface verified against codex-cli 0.146.0 on
 * 2026-08-15). Codex enforces MORE of the never-list than a coarse sandbox:
 *
 * - Credential reads → a permission profile with OS-enforced filesystem `deny`
 *   entries (Seatbelt/Landlock). This is seamless (no trust step) and is
 *   verified to block reads of denied paths/globs. Arguably stronger than a hook.
 * - Fetched-code execution → the same self-contained shell hook the Claude Code
 *   adapter uses, wired into Codex's PreToolUse (identical payload + exit-2-block
 *   protocol). HONEST CAVEAT: non-managed Codex hooks do not fire until the user
 *   trusts them once via `/hooks` in the Codex TUI — so herkos installs it and
 *   tells the user that one step is required to activate fetched-code blocking.
 *
 * Requires Codex >= 0.146 (the permission-profile system). This is a fast-moving
 * surface — execpolicy/permissions churn is expected; re-verify per release.
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
import { spawnSync } from "node:child_process";
import { collectCodexDeny, loadEffectivePolicy, compile } from "../policy.js";
import type { CompiledPolicy } from "../policy.js";
import type {
  HarnessAdapter,
  DetectResult,
  WireResult,
  VerifyResult,
} from "./types.js";
import { generateHook, hookPath } from "./claude-code.js";

const PROFILE = "herkos";
const BEGIN = "# >>> herkos managed (do not edit between markers) >>>";
const END = "# <<< herkos managed <<<";
const MIN_MAJOR = 0;
const MIN_MINOR = 146;

function codexHome(): string {
  return process.env.CODEX_HOME ?? path.join(os.homedir(), ".codex");
}
const configPath = (): string => path.join(codexHome(), "config.toml");
const hooksJsonPath = (): string => path.join(codexHome(), "hooks.json");

function parseVersion(
  out: string,
): { major: number; minor: number; raw: string } | null {
  const m = out.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return null;
  return { major: Number(m[1]), minor: Number(m[2]), raw: m[0] };
}

function buildManagedBlock(): { block: string; hasDeny: boolean } {
  const { paths, globs } = collectCodexDeny(loadEffectivePolicy());
  const lines = [
    BEGIN,
    "# herkos never-list for Codex — credential reads denied (OS-enforced via the",
    "# permission profile). Fetched-code blocking is delivered by the herkos hook",
    "# (see hooks.json); run /hooks in Codex once to trust it. 'herkos uninstall' removes this.",
    `default_permissions = "${PROFILE}"`,
    `[permissions.${PROFILE}]`,
    `description = "herkos never-list: credential reads denied"`,
    `extends = ":workspace"`,
    `[permissions.${PROFILE}.filesystem]`,
    ...paths.map((p) => `"${p}" = "deny"`),
    `[permissions.${PROFILE}.filesystem.":workspace_roots"]`,
    ...globs.map((g) => `"${g}" = "deny"`),
    END,
  ];
  return { block: lines.join("\n"), hasDeny: paths.length + globs.length > 0 };
}

function upsertBlock(content: string, block: string): string {
  const re = new RegExp(`${BEGIN}[\\s\\S]*?${END}\\n?`, "m");
  if (re.test(content)) return content.replace(re, block + "\n");
  return `${content}${content && !content.endsWith("\n") ? "\n" : ""}${block}\n`;
}

// Wire the shared hook into Codex's hooks.json (root wrapper key "hooks").
function wireHook(): void {
  const p = hooksJsonPath();
  let doc: { hooks?: Record<string, unknown[]> } = {};
  if (fs.existsSync(p)) {
    doc = JSON.parse(fs.readFileSync(p, "utf8")) as typeof doc;
    const bak = `${p}.herkos-bak`;
    if (!fs.existsSync(bak)) fs.copyFileSync(p, bak);
  }
  const hooks = doc.hooks ?? {};
  const cmd = `sh "${hookPath()}"`;
  const isOurs = (e: unknown): boolean =>
    JSON.stringify(e ?? "").includes(hookPath());
  const pre = ((hooks["PreToolUse"] as unknown[]) ?? []).filter(
    (e) => !isOurs(e),
  );
  pre.push({ matcher: "^Bash$", hooks: [{ type: "command", command: cmd }] });
  hooks["PreToolUse"] = pre;
  doc.hooks = hooks;
  fs.mkdirSync(codexHome(), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(doc, null, 2) + "\n");
}

export const codexAdapter: HarnessAdapter = {
  id: "codex",
  name: "Codex CLI",

  detect(): DetectResult {
    const r = spawnSync("codex", ["--version"], {
      encoding: "utf8",
      timeout: 15_000,
    });
    if (r.status !== 0 || r.error)
      return { installed: false, detail: "codex not found on PATH" };
    const raw = (r.stdout ?? "").trim().split("\n")[0] ?? "";
    const v = parseVersion(raw);
    if (
      v &&
      (v.major < MIN_MAJOR || (v.major === MIN_MAJOR && v.minor < MIN_MINOR))
    ) {
      return {
        installed: true,
        version: v.raw,
        configDir: codexHome(),
        detail: `${v.raw} — below the ${MIN_MAJOR}.${MIN_MINOR} minimum for the permission-profile system; upgrade Codex for credential enforcement`,
      };
    }
    return {
      installed: true,
      version: v?.raw ?? raw,
      configDir: codexHome(),
      detail: `${v?.raw ?? raw} · config at ${configPath()}`,
    };
  },

  // The compiled policy is used for the shared hook; the filesystem-deny profile
  // is built from the effective policy's codexDeny targets.
  wire(policy: CompiledPolicy): WireResult {
    const changed: string[] = [];
    const p = configPath();
    fs.mkdirSync(codexHome(), { recursive: true });

    // 1. credential-read → permission-profile deny (config.toml managed block)
    let content = "";
    if (fs.existsSync(p)) {
      content = fs.readFileSync(p, "utf8");
      const bak = `${p}.herkos-bak`;
      if (!fs.existsSync(bak)) {
        fs.copyFileSync(p, bak);
        changed.push(bak);
      }
    }
    // Refuse to clobber a user's own default_permissions set OUTSIDE our block.
    const outside = content.replace(
      new RegExp(`${BEGIN}[\\s\\S]*?${END}`, "m"),
      "",
    );
    const conflict = /^\s*default_permissions\s*=/m.test(outside);
    const { block } = buildManagedBlock();
    fs.writeFileSync(p, upsertBlock(content, block));
    changed.push(p);

    // 2. fetched-exec → shared hook, wired into hooks.json (needs /hooks trust)
    fs.mkdirSync(path.dirname(hookPath()), { recursive: true });
    fs.writeFileSync(hookPath(), generateHook(policy), { mode: 0o755 });
    wireHook();
    changed.push(hookPath(), hooksJsonPath());

    const trustNote =
      "Run '/hooks' in Codex ONCE to trust the herkos hook — until then, fetched-code blocking is inactive (credential denies are already live).";
    const conflictNote = conflict
      ? " NOTE: you already set default_permissions outside herkos's block — point it at \"herkos\" or merge, or the credential profile won't be the active one."
      : "";
    return {
      changed,
      detail: `credential reads denied via the '${PROFILE}' permission profile (OS-enforced). ${trustNote}${conflictNote}`,
    };
  },

  unwire(): WireResult {
    const changed: string[] = [];
    const p = configPath();
    if (fs.existsSync(p)) {
      const c = fs.readFileSync(p, "utf8");
      const re = new RegExp(`\\n?${BEGIN}[\\s\\S]*?${END}\\n?`, "m");
      if (re.test(c)) {
        fs.writeFileSync(p, c.replace(re, "\n"));
        changed.push(p);
      }
    }
    const hp = hooksJsonPath();
    if (fs.existsSync(hp)) {
      const doc = JSON.parse(fs.readFileSync(hp, "utf8")) as {
        hooks?: Record<string, unknown[]>;
      };
      const pre = doc.hooks?.["PreToolUse"];
      if (Array.isArray(pre)) {
        const kept = pre.filter(
          (e) => !JSON.stringify(e ?? "").includes(hookPath()),
        );
        if (kept.length !== pre.length) {
          doc.hooks!["PreToolUse"] = kept;
          fs.writeFileSync(hp, JSON.stringify(doc, null, 2) + "\n");
          changed.push(hp);
        }
      }
    }
    return {
      changed,
      detail: changed.length
        ? "herkos Codex wiring removed"
        : "nothing to remove",
    };
  },

  verify(): VerifyResult {
    const p = configPath();
    if (!fs.existsSync(p) || !fs.readFileSync(p, "utf8").includes(BEGIN)) {
      return {
        ok: false,
        detail: "credential-deny profile not present — run 'herkos init'",
      };
    }
    const hookWired =
      fs.existsSync(hooksJsonPath()) &&
      fs.readFileSync(hooksJsonPath(), "utf8").includes(hookPath());
    return {
      ok: true,
      detail: `credential-deny profile present (OS-enforced)${hookWired ? "; fetched-code hook wired (needs '/hooks' trust in Codex to be active)" : "; fetched-code hook NOT wired"}`,
    };
  },
};

/** For live validation: the config block herkos would write (used by the canary test). */
export function previewManagedBlock(): string {
  void compile(loadEffectivePolicy());
  return buildManagedBlock().block;
}
