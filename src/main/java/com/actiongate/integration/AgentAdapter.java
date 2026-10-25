package com.actiongate.integration;

import com.actiongate.model.CommandRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.policy.SecurityPolicy;
import java.util.Optional;

/** Translates one specific agent's hook protocol to and from ActionGate's model. */
public interface AgentAdapter {
    String agentId();

    /**
     * @return the command to evaluate, or empty if the payload is valid but is not a shell command (e.g. another tool)
     * @throws com.actiongate.model.InvalidRequestException if the payload is malformed
     */
    Optional<CommandRequest> parse(String body);

    /** Response sent to the agent when the operation is permitted (only called after authorization was consumed). */
    String allowResponse(EnforcementDecision decision, SecurityPolicy policy);

    String denyResponse(String reason);

    /** Response for payloads ActionGate does not evaluate: "no opinion", the agent's own rules continue to apply. */
    String noOpinionResponse();
}
