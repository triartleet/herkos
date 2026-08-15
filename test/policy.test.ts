import { describe, it, expect } from "vitest";
import { BASELINE, compile, loadEffectivePolicy } from "../src/policy.js";
import { runSelfCheck } from "../src/selfcheck.js";
import { generateHook } from "../src/adapters/claude-code.js";

describe("baseline policy", () => {
  it("covers both rule classes", () => {
    const classes = new Set(BASELINE.map((r) => r.class));
    expect(classes.has("credential-read")).toBe(true);
    expect(classes.has("fetched-exec")).toBe(true);
  });
  it("compiles to a path regex and command regexes", () => {
    const c = compile(loadEffectivePolicy());
    expect(c.pathRegex.length).toBeGreaterThan(0);
    expect(c.commandRegexes.length).toBeGreaterThan(0);
    expect(c.ruleCount).toBe(BASELINE.length);
  });
});

describe("generated hook", () => {
  it("bakes the rules and carries the marker", () => {
    const hook = generateHook(compile(loadEffectivePolicy()));
    expect(hook).toContain("herkos-hook");
    expect(hook).toContain("PATH_RE=");
  });
});

describe("self-check (runs the real generated hook)", () => {
  const { results, ok } = runSelfCheck();
  for (const r of results) {
    it(`${r.name} → exit ${r.wantExit}`, () => {
      expect(r.gotExit).toBe(r.wantExit);
    });
  }
  it("overall passes", () => {
    expect(ok).toBe(true);
  });
});
