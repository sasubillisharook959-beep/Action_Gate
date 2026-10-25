package com.actiongate.model;

public enum RiskLevel {
    LOW, MEDIUM, HIGH, CRITICAL;

    public static RiskLevel max(RiskLevel a, RiskLevel b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    public boolean atLeast(RiskLevel other) {
        return ordinal() >= other.ordinal();
    }
}
