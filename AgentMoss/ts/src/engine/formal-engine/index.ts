/**
 * Formal engine (Formal Engine) — agent behavior formal verification module.
 * Mirrors Python agent_moss/engine/formal_engine/ package.
 *
 * Layered architecture:
 * - IR (ir.ts): ActionNode / BehaviorEdge / SessionGraph / MultiSessionGraph
 * - Builder (builder.ts): build behavior graphs from action histories
 * - Verification (engine.ts + properties.ts): FormalEngine verifies properties
 *   (cross-session chains, sensitive data flow) → compliance proof or counter-example.
 */

export { FormalEngine } from './engine';
export * from './ir';
export { buildMultiSessionGraph, buildSessionGraph, extractResources } from './builder';
export { ALL_PROPERTIES, checkCrossSessionChain, checkSensitiveDataFlow } from './properties';
export type { Property } from './properties';
export { StatefulChainTracker } from './stateful';
export type { StateNode, PendingPrefix, ChainMatch, AdvanceResult, JudgmentLike } from './stateful';
export { ChainStateStore } from './chain_state';
