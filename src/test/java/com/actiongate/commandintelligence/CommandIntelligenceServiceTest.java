package com.actiongate.commandintelligence;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.actiongate.ui.DecisionRow;
import org.junit.jupiter.api.Test;

class CommandIntelligenceServiceTest {
private final CommandIntelligenceService service = new CommandIntelligenceService();


CommandIntelligenceServiceTest() throws Exception {}

@Test
void loadsAllCommandEntriesAndRequiredInformation() {
    assertEquals(397, service.size());
    var removeItem = service.findCommand("Remove-Item C:\\Project -Recurse -Force").orElseThrow();
    assertEquals("File Management", removeItem.category());
    assertEquals("Deletes specified files or directories.", removeItem.description());
    assertEquals("HIGH", removeItem.suggestedRisk());
    assertEquals("Microsoft PowerShell Documentation", removeItem.source());
}

@Test
void matchesPowerShellCommandsAndAliasesCaseInsensitively() {
    assertEquals("Get-Process", service.findCommand("get-process").orElseThrow().command());
    assertEquals("Remove-Item", service.findCommand("RM test.txt -Force").orElseThrow().command());
}

@Test
void matchesGitAndNpmCommandsBeforeTheirArguments() {
    assertEquals("git push", service.findCommand("git push origin main").orElseThrow().command());
   assertEquals("echo", service.findCommand("Write-Output done; npm install express").orElseThrow().command());
    assertEquals("npm audit fix", service.findCommand("npm audit fix --force").orElseThrow().command());
    assertEquals("npm uninstall", service.findCommand("npm remove express").orElseThrow().command());
    assertEquals("sfc /scannow", service.findCommand("sfc /scannow").orElseThrow().command());
    assertEquals("git push --force", service.findCommand("git push --force origin main").orElseThrow().command());
    assertEquals("docker compose down", service.findCommand("docker compose down --volumes").orElseThrow().command());
    assertEquals("security find-generic-password",
            service.findCommand("security find-generic-password -s account").orElseThrow().command());
    assertEquals("nmap", service.findCommand("NMAP 192.0.2.1").orElseThrow().command());
    assertEquals("Remove-Item", service.findCommand("rmdir old-folder").orElseThrow().command());
    assertEquals("Get-ChildItem", service.findCommand("GCI .").orElseThrow().command());
    assertEquals("env", service.findCommand("printenv").orElseThrow().command());
    assertEquals("source", service.findCommand(". ./local-config").orElseThrow().command());
}

@Test
void onlyMatchesCommandHeadsAndRealShellSegments() {
    assertEquals(
            "echo",
            service.findCommand("Write-Output 'Remove-Item test.txt -Force'")
                    .orElseThrow().command());

    assertTrue(service.findCommand("'git push' origin main").isEmpty());
    assertTrue(service.findCommand("C:\\Tools\\git push").isEmpty());

   assertEquals("echo", service.findCommand("Write-Output done; npm install express").orElseThrow().command());
}

@Test
void unknownCommandsAreNotInvented() {
    assertFalse(service.findCommand("some-unknown-command --help").isPresent());
    assertEquals(
            "Command not found in the Command Intelligence Database. Its behaviour requires further analysis.",
            CommandIntelligenceService.NOT_FOUND_MESSAGE);
}

@Test
void decisionRowPreservesTheCompleteCommandForTheDialog() {
    String command = "Remove-Item " + "project-file.txt ".repeat(20) + "-Recurse -Force";
    DecisionRow row = DecisionRow.of("agent", command, "HIGH", "DENY", "reason");

    assertTrue(row.command().length() < command.length());
    assertEquals(command, row.originalCommand());
}


}
