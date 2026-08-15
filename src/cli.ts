import { Command } from "commander";
import pc from "picocolors";
import {
  loadEffectivePolicy,
  compile,
  BASELINE,
  userPolicyPath,
} from "./policy.js";
import { ADAPTERS, detectInstalled } from "./adapters/index.js";
import { runSelfCheck } from "./selfcheck.js";

function initCmd(opts: { dryRun?: boolean }): void {
  const policy = compile(loadEffectivePolicy());
  const installed = detectInstalled();
  process.stdout.write(
    `herkos — compiling ${policy.ruleCount} rules into installed harnesses\n`,
  );
  if (installed.length === 0) {
    process.stdout.write("  no supported harness detected on this machine\n");
    process.exit(1);
  }
  for (const a of installed) {
    const d = a.detect();
    if (opts.dryRun) {
      process.stdout.write(
        `  ${pc.dim("would wire")} ${a.name} (${d.version ?? "?"})\n`,
      );
      continue;
    }
    const r = a.wire(policy);
    process.stdout.write(`  ${pc.green("wired")} ${a.name}: ${r.detail}\n`);
  }
  if (!opts.dryRun)
    process.stdout.write(
      `\nRun ${pc.bold("herkos check")} to verify enforcement, ${pc.bold("herkos status")} to see wiring.\n`,
    );
}

function statusCmd(): void {
  const eff = loadEffectivePolicy();
  process.stdout.write(
    `policy: ${eff.rules.length} rules (${eff.userPolicyLoaded ? "baseline + user" : "baseline only"}); user policy ${eff.userPolicyLoaded ? "at" : "would be at"} ${userPolicyPath()}\n`,
  );
  if (eff.disabled.length)
    process.stdout.write(
      `  disabled baseline rules: ${eff.disabled.join(", ")}\n`,
    );
  for (const a of ADAPTERS) {
    const d = a.detect();
    if (!d.installed) {
      process.stdout.write(`  ${pc.dim(a.name + ": not installed")}\n`);
      continue;
    }
    const v = a.verify();
    process.stdout.write(
      `  ${v.ok ? pc.green(a.name + ": protected") : pc.yellow(a.name + ": NOT wired")} — ${v.detail}\n`,
    );
  }
}

function checkCmd(): void {
  const s = runSelfCheck();
  process.stdout.write(
    `herkos check — ${s.results.length} enforcement cases${s.jq ? "" : pc.yellow(" (warning: jq not installed — the live hook degrades to allow)")}\n`,
  );
  for (const r of s.results) {
    process.stdout.write(
      `  ${r.ok ? pc.green("ok  ") : pc.red("FAIL")} ${r.name}${r.ok ? "" : ` (want exit ${r.wantExit}, got ${r.gotExit})`}\n`,
    );
  }
  for (const a of ADAPTERS) {
    const d = a.detect();
    if (d.installed) {
      const v = a.verify();
      process.stdout.write(
        `  ${v.ok ? pc.green("ok  ") : pc.yellow("warn")} ${a.name} wiring: ${v.detail}\n`,
      );
    }
  }
  process.stdout.write(
    s.ok
      ? pc.green("\nPASS — the never-list is enforced\n")
      : pc.red("\nFAIL — enforcement did not behave as expected\n"),
  );
  process.exit(s.ok ? 0 : 1);
}

function rulesCmd(): void {
  const eff = loadEffectivePolicy();
  for (const r of eff.rules) {
    const src = BASELINE.some((b) => b.id === r.id)
      ? pc.dim("[baseline]")
      : pc.cyan("[user]");
    process.stdout.write(
      `  ${src} ${pc.bold(r.id)} (${r.class}) — ${r.description}\n`,
    );
  }
  if (eff.disabled.length)
    process.stdout.write(
      `  ${pc.yellow("disabled:")} ${eff.disabled.join(", ")}\n`,
    );
}

function uninstallCmd(): void {
  for (const a of detectInstalled()) {
    const r = a.unwire();
    process.stdout.write(`  ${a.name}: ${r.detail}\n`);
  }
}

const program = new Command();
program
  .name("herkos")
  .description(
    "Your never-list, enforced across every agent harness on this machine.",
  );
program
  .command("init")
  .description("compile the policy into every installed harness")
  .option("--dry-run", "show what would change")
  .action(initCmd);
program
  .command("status")
  .description("show policy + which harnesses are protected")
  .action(statusCmd);
program
  .command("check")
  .description(
    "prove the never-list is enforced (synthetic payloads) + verify wiring",
  )
  .action(checkCmd);
program
  .command("rules")
  .description("list the effective rules (baseline + user)")
  .action(rulesCmd);
program
  .command("uninstall")
  .description("remove herkos wiring from installed harnesses")
  .action(uninstallCmd);
program.parse();
