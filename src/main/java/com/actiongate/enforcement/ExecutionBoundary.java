package com.actiongate.enforcement;

import com.actiongate.model.CommandRequest;

/**
 * The point where a permitted operation is released to the agent (production: the hook's "allow" response;
 * tests: a recording fake). ActionGate itself never runs commands. Blocked operations never reach this method.
 */
public interface ExecutionBoundary {
    void release(CommandRequest request, AuthorizedOperation authorization);
}
