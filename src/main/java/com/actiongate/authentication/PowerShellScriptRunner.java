package com.actiongate.authentication;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.concurrent.TimeUnit;

public final class PowerShellScriptRunner implements ScriptRunner {

    static final String SCRIPT = String.join("\n",
            "$ErrorActionPreference = 'Stop'",
            "try {",
            "  Add-Type -AssemblyName System.Runtime.WindowsRuntime",
            "  [void][Windows.Security.Credentials.UI.UserConsentVerifier, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]",
            "  [void][Windows.Security.Credentials.UI.UserConsentVerifierAvailability, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]",
            "  [void][Windows.Security.Credentials.UI.UserConsentVerificationResult, Windows.Security.Credentials.UI, ContentType = WindowsRuntime]",
            "  $asTask = ([System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object {",
            "    $_.Name -eq 'AsTask' -and $_.GetParameters().Count -eq 1 -and $_.GetParameters()[0].ParameterType.Name -eq 'IAsyncOperation`1' })[0]",
            "  function Await($op, $type) { $t = $asTask.MakeGenericMethod($type).Invoke($null, @($op)); [void]$t.Wait(-1); $t.Result }",
            "  if ($env:ACTIONGATE_MODE -eq 'check') {",
            "    $r = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::CheckAvailabilityAsync()) ([Windows.Security.Credentials.UI.UserConsentVerifierAvailability])",
            "    Write-Output ('ACTIONGATE_AVAILABILITY=' + $r)",
            "  } else {",
            "    $r = Await ([Windows.Security.Credentials.UI.UserConsentVerifier]::RequestVerificationAsync($env:ACTIONGATE_PROMPT)) ([Windows.Security.Credentials.UI.UserConsentVerificationResult])",
            "    Write-Output ('ACTIONGATE_RESULT=' + $r)",
            "  }",
            "} catch {",
            "  Write-Output ('ACTIONGATE_ERROR=' + $_.Exception.ToString())",
            "}",
            "exit",
            "");

    private static final int MAX_OUTPUT = 64 * 1024;

    @Override
    public String run(String mode, String prompt, Duration timeout)
            throws IOException, InterruptedException {

        String encodedScript = Base64.getEncoder().encodeToString(
                SCRIPT.getBytes(StandardCharsets.UTF_16LE)
        );

        ProcessBuilder pb = new ProcessBuilder(
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-EncodedCommand",
                encodedScript
        );

        pb.environment().put("ACTIONGATE_MODE", mode);
        pb.environment().put("ACTIONGATE_PROMPT", prompt);

        pb.redirectErrorStream(true);

        Process p = pb.start();

        ByteArrayOutputStream out = new ByteArrayOutputStream();

        Thread reader = new Thread(() -> {
            try (InputStream is = p.getInputStream()) {

                byte[] buffer = new byte[4096];
                int n;

                while ((n = is.read(buffer)) > 0) {
                    synchronized (out) {
                        if (out.size() < MAX_OUTPUT) {
                            out.write(
                                    buffer,
                                    0,
                                    Math.min(n, MAX_OUTPUT - out.size())
                            );
                        }
                    }
                }

            } catch (IOException ignored) {
                // Process ended.
            }
        }, "actiongate-hello-reader");

        reader.setDaemon(true);
        reader.start();

        if (!p.waitFor(timeout.toMillis(), TimeUnit.MILLISECONDS)) {
            p.destroyForcibly();

            throw new java.util.concurrent.CancellationException(
                    "Windows Hello verification timed out"
            );
        }

        reader.join(2000);

        synchronized (out) {
            return out.toString(StandardCharsets.UTF_8);
        }
    }
}