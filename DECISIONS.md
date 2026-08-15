# Decisions

Append-only. Each entry records a decision, why it went that way, and what it
forecloses. Supersede an entry with a new one; never rewrite its substance.

### D-001 — One policy, compiled into each harness's native wiring

**Scope:** repo · **Decided:** 2026-08-15

The user declares one never-list; per-harness adapters compile it into each
installed harness's native enforcement mechanism. The policy is harness-agnostic;
adapters own all harness-specific knowledge.

**Why:** there is no universal, OS-level point where a tool can intercept every
harness's actions, so enforcement must go through each harness's own extension
point. Keeping the policy independent of those mechanisms means one rule set
protects every harness, and adding a harness is a new adapter rather than a
redesign.

**Consequences:** coverage differs by harness (a harness that exposes no
per-call hook cannot enforce the fine-grained list); the tool must state that
difference honestly rather than imply a uniform guarantee.

### D-002 — The enforcement path depends on nothing

**Scope:** repo · **Decided:** 2026-08-15

The deployed enforcement (for a harness with a hook, a self-contained shell
script) requires no network and no other tool to run. Verification and update
machinery live outside the enforcement path.

**Why:** a security control that stops working when a dependency is missing is
worse than none. Keeping enforcement dependency-free means a fresh install
protects out of the box and keeps protecting regardless of what else is present.

**Consequences:** the enforcing hook cannot rely on this package at runtime;
richer checking is delivered separately and degrades to absence gracefully.

### D-003 — A curated, default-on baseline; user rules extend, never replace

**Scope:** repo · **Decided:** 2026-08-15

Every install ships a curated never-list on by default (credential reads,
fetched-code execution). A user policy file adds rules and can disable baseline
rules by id — per-rule and explicit, never "turn the guard off".

**Why:** a security tool that ships empty protects nobody on install day, and
"configure it first" is the friction that kills adoption. The baseline must be
high-confidence: a false positive in a default rule trains users to disable the
guard, which is worse than no guard.

**Consequences:** the baseline grows slowly and only with near-universally
never-legitimate rules; anything project-specific belongs in the user's policy.

### D-004 — Degrade loudly, never fail closed silently

**Scope:** repo · **Decided:** 2026-08-15

When the enforcement hook cannot parse its input it announces that enforcement is
off for that call and allows it; it never silently permits a matched action.

**Why:** hard-blocking on every unparseable call bricks the session, and silently
allowing a matched never-list action defeats the tool. Announcing the degraded
state keeps the user informed without breaking their work.

**Consequences:** a missing parser dependency reduces coverage visibly rather
than failing open in silence or closed in a way that halts the session.
