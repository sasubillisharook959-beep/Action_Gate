package com.actiongate.audit;

import java.util.List;

public record VerificationResult(boolean valid, int eventsChecked, List<String> problems) {
    public VerificationResult {
        problems = List.copyOf(problems);
    }

    @Override
    public String toString() {
        return valid ? "Audit chain intact (" + eventsChecked + " events)"
                : "AUDIT INTEGRITY FAILURE: " + String.join("; ", problems);
    }
}
