/**
 * The policy model: what an agent must never do on this machine.
 *
 * Two rule classes in v0.1, both about removing the payoff of a hijacked agent:
 * - "credential-read": reading files that hold live secret values.
 * - "fetched-exec": piping just-downloaded content straight into a shell.
 *
 * The BASELINE below is the curated, high-confidence never-list every install
 * gets by default — generic conventions only (nothing machine-specific may ever
 * appear here). A user policy file extends it with their own paths and can
 * disable individual baseline rules by id; disabling is per-rule and explicit,
 * never "turn the guard off".
 */
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

export type RuleClass = "credential-read" | "fetched-exec";

export interface Rule {
  id: string;
  class: RuleClass;
  description: string;
  /** Path fragments matched as substrings against file paths AND command text (credential-read). */
  paths?: string[];
  /** Extended regexes matched against command text (fetched-exec / command-shaped rules). */
  commandPatterns?: string[];
  /**
   * Concrete deny targets for OS-level filesystem-deny adapters (Codex permission
   * profiles). Home/absolute paths ("~/.ssh", "/etc/x") go in the filesystem
   * table; glob entries (containing "*", e.g. "**\/.env*") go under
   * :workspace_roots. Absent → this rule isn't expressible as a filesystem deny
   * (e.g. fetched-exec rules), and that adapter falls back to its hook.
   */
  codexDeny?: string[];
}

export interface UserPolicy {
  /** Extra rules, same shape as baseline rules. */
  rules?: Rule[];
  /** Baseline rule ids to disable (per-rule, auditable). */
  disable?: string[];
}

export interface EffectivePolicy {
  rules: Rule[];
  disabled: string[];
  userPolicyPath: string;
  userPolicyLoaded: boolean;
}

/**
 * The baseline never-list. Curation bar: near-universally never-legitimate for
 * an agent session; a false positive in a default rule teaches users to disable
 * the guard, which is worse than no guard. Grow this list slowly.
 */
export const BASELINE: Rule[] = [
  {
    id: "ssh-private-keys",
    class: "credential-read",
    description: "SSH private keys",
    paths: [".ssh/id_"],
    codexDeny: ["~/.ssh"],
  },
  {
    id: "cloud-credentials",
    class: "credential-read",
    description: "Cloud provider credential files (AWS, GCP, Azure)",
    paths: [
      ".aws/credentials",
      ".config/gcloud/",
      ".azure/accessTokens",
      ".azure/msal_token_cache",
    ],
    codexDeny: ["~/.aws/credentials", "~/.config/gcloud", "~/.azure"],
  },
  {
    id: "kube-config",
    class: "credential-read",
    description: "Kubernetes cluster credentials",
    paths: [".kube/config"],
    codexDeny: ["~/.kube/config"],
  },
  {
    id: "dotenv-files",
    class: "credential-read",
    description:
      "Environment files that conventionally hold secrets (.env and variants)",
    // Matched as path fragments: covers .env, .env.local, .env.production, etc.
    paths: ["/.env"],
    codexDeny: ["**/.env", "**/.env.*"],
  },
  {
    id: "token-rc-files",
    class: "credential-read",
    description: "Per-user token files (.netrc, .npmrc, .pypirc)",
    paths: [".netrc", ".npmrc", ".pypirc"],
    codexDeny: ["~/.netrc", "~/.npmrc", "~/.pypirc"],
  },
  {
    id: "gnupg-private",
    class: "credential-read",
    description: "GnuPG private keyring",
    paths: [".gnupg/private-keys"],
    codexDeny: ["~/.gnupg"],
  },
  {
    id: "docker-auth",
    class: "credential-read",
    description: "Docker registry auth file",
    paths: [".docker/config.json"],
    codexDeny: ["~/.docker/config.json"],
  },
  {
    id: "macos-keychain",
    class: "fetched-exec",
    description: "macOS keychain credential dumps (holds OS-level secrets)",
    commandPatterns: [
      "security[[:space:]]+(dump-keychain|find-generic-password|find-internet-password|export)",
    ],
  },
  {
    id: "curl-pipe-shell",
    class: "fetched-exec",
    description: "Piping downloaded content directly into a shell",
    commandPatterns: [
      "(curl|wget)[^|]*\\|[[:space:]]*(env[[:space:]]+)?(ba|z|da)?sh([[:space:]]|$|[[:space:]]*-)",
      "eval[[:space:]]+.?\\$\\((curl|wget)",
    ],
  },
];

export function userPolicyPath(): string {
  const base =
    process.env.HERKOS_CONFIG ?? path.join(os.homedir(), ".config", "herkos");
  return path.join(base, "policy.json");
}

export function loadEffectivePolicy(): EffectivePolicy {
  const p = userPolicyPath();
  let user: UserPolicy = {};
  let loaded = false;
  if (fs.existsSync(p)) {
    try {
      user = JSON.parse(fs.readFileSync(p, "utf8")) as UserPolicy;
      loaded = true;
    } catch (e) {
      throw new Error(`user policy at ${p} is not valid JSON: ${String(e)}`);
    }
  }
  const disabled = user.disable ?? [];
  const rules = [
    ...BASELINE.filter((r) => !disabled.includes(r.id)),
    ...(user.rules ?? []),
  ];
  return { rules, disabled, userPolicyPath: p, userPolicyLoaded: loaded };
}

/** The compiled matchers a hook needs: one path-fragment regex + command regexes. */
export interface CompiledPolicy {
  /** POSIX extended regex alternation of escaped path fragments ("" if none). */
  pathRegex: string;
  /** POSIX extended regexes for command-shaped rules. */
  commandRegexes: string[];
  ruleCount: number;
}

// Escape a literal path fragment for use inside a POSIX extended regex.
function escapeERE(s: string): string {
  return s.replace(/[.[\]()*+?{}|^$\\]/g, "\\$&");
}

export interface CodexDeny {
  /** Home/absolute path deny entries → [permissions.<p>.filesystem]. */
  paths: string[];
  /** Glob deny entries → [permissions.<p>.filesystem.":workspace_roots"]. */
  globs: string[];
  /** Rules that could NOT be expressed as a filesystem deny (fetched-exec) — the Codex adapter covers these via its hook. */
  fetchedExecRules: Rule[];
}

/** Split the effective policy into Codex's filesystem-deny targets + the rules it can't express that way. */
export function collectCodexDeny(policy: EffectivePolicy): CodexDeny {
  const paths: string[] = [];
  const globs: string[] = [];
  const fetchedExecRules: Rule[] = [];
  for (const r of policy.rules) {
    if (r.codexDeny && r.codexDeny.length) {
      for (const d of r.codexDeny) (d.includes("*") ? globs : paths).push(d);
    } else if (r.class === "fetched-exec") {
      fetchedExecRules.push(r);
    }
  }
  return { paths, globs, fetchedExecRules };
}

export function compile(policy: EffectivePolicy): CompiledPolicy {
  const fragments: string[] = [];
  const commandRegexes: string[] = [];
  for (const r of policy.rules) {
    for (const p of r.paths ?? []) fragments.push(escapeERE(p));
    for (const c of r.commandPatterns ?? []) commandRegexes.push(c);
  }
  return {
    pathRegex: fragments.join("|"),
    commandRegexes,
    ruleCount: policy.rules.length,
  };
}
