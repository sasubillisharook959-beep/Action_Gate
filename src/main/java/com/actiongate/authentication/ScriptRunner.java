package com.actiongate.authentication;

import java.io.IOException;
import java.time.Duration;

/** Runs the bundled Windows Hello bridge script. Abstracted so output parsing is testable off-Windows. */
public interface ScriptRunner {
    /** @return the process's standard output */
    String run(String mode, String prompt, Duration timeout) throws IOException, InterruptedException;
}
