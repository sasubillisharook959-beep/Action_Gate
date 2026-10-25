package com.actiongate.policy;

/**
 * Per-agent integration settings.
 * @param enabled whether requests from this agent are evaluated (disabled agents are denied, never bypassed)
 * @param explicitAllowLowRisk if true the adapter answers LOW-risk commands with an explicit "allow" (which can
 *        skip the agent's own permission prompt); if false it answers "no opinion" so the agent's own rules still apply
 */
public record AgentSettings(boolean enabled, boolean explicitAllowLowRisk) {}
