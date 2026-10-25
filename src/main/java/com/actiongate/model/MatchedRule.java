package com.actiongate.model;

/** A risk rule that fired. {@code category} is what policies can block on. */
public record MatchedRule(String id, String category, RiskLevel level, String description) {
    @Override
    public String toString() {
        return id + "[" + level + "]";
    }
}
