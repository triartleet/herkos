export {
  BASELINE,
  loadEffectivePolicy,
  compile,
  userPolicyPath,
} from "./policy.js";
export type {
  Rule,
  RuleClass,
  UserPolicy,
  EffectivePolicy,
  CompiledPolicy,
} from "./policy.js";
export { ADAPTERS, detectInstalled } from "./adapters/index.js";
export type {
  HarnessAdapter,
  DetectResult,
  WireResult,
  VerifyResult,
} from "./adapters/types.js";
export { generateHook } from "./adapters/claude-code.js";
export { runSelfCheck, CASES } from "./selfcheck.js";
export type { CheckResult, CheckCase } from "./selfcheck.js";
