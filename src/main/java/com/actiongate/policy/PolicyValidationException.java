package com.actiongate.policy;

import java.util.List;

public class PolicyValidationException extends IllegalArgumentException {
    private final List<String> problems;

    public PolicyValidationException(List<String> problems) {
        super("Invalid policy: " + String.join("; ", problems));
        this.problems = List.copyOf(problems);
    }

    public List<String> problems() { return problems; }
}
