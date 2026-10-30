package com.actiongate.commandintelligence;

import com.actiongate.risk.ShellParser;
import com.actiongate.util.Json;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/** Loads informational command descriptions independently of command risk assessment. */
public final class CommandIntelligenceService {
    public static final String NOT_FOUND_MESSAGE =
            "Command not found in the Command Intelligence Database. Its behaviour requires further analysis.";

    private static final String RESOURCE = "/command-intelligence/commands.json";
    private final List<CommandInfo> commands;

    public CommandIntelligenceService() throws IOException {
        this(loadCommands());
    }

    private CommandIntelligenceService(List<CommandInfo> commands) {
        this.commands = List.copyOf(commands);
    }

    public int size() {
        return commands.size();
    }

    public Optional<CommandInfo> findCommand(String originalCommand) {
        if (originalCommand == null || originalCommand.isBlank()) return Optional.empty();

        ShellParser.Parsed parsed = ShellParser.parse(originalCommand);
        if (parsed.malformed()) return Optional.empty();

        for (ShellParser.Segment segment : parsed.segments()) {
            List<ShellParser.Word> words = segment.words();
            if (words.isEmpty()) continue;
            ShellParser.Word executable = words.get(0);
            if (executable.quoted() || executable.substitution() || executable.variable() || executable.obfuscated()) continue;

            CommandInfo bestMatch = null;
            int bestLength = -1;
            for (CommandInfo candidate : commands) {
                int commandLength = matchingLength(candidate.command(), words);
                if (commandLength > bestLength) {
                    bestMatch = commandLength > 0 ? candidate : bestMatch;
                    bestLength = commandLength;
                }
                for (String alias : candidate.aliases()) {
                    int aliasLength = matchingLength(alias, words);
                    if (aliasLength > bestLength) {
                        bestMatch = aliasLength > 0 ? candidate : bestMatch;
                        bestLength = aliasLength;
                    }
                }
            }
            if (bestMatch != null) return Optional.of(bestMatch);
        }
        return Optional.empty();
    }

    private static int matchingLength(String name, List<ShellParser.Word> words) {
        String[] parts = name.trim().split("\\s+");
        if (parts.length > words.size()) return -1;
        for (int i = 0; i < parts.length; i++) {
            ShellParser.Word word = words.get(i);
            if (word.quoted() || word.substitution() || word.variable() || word.obfuscated()
                    || !parts[i].equalsIgnoreCase(word.text())) return -1;
        }
        return parts.length;
    }

    private static List<CommandInfo> loadCommands() throws IOException {
        InputStream resource = CommandIntelligenceService.class.getResourceAsStream(RESOURCE);
        if (resource == null) throw new IOException("Command intelligence resource is missing: " + RESOURCE);

        Object parsed;
        try (InputStream input = resource) {
            parsed = Json.parse(new String(input.readAllBytes(), StandardCharsets.UTF_8));
        }
        List<Object> entries = Json.asArray(parsed);
        if (entries == null) throw new IllegalArgumentException("Command intelligence JSON must contain an array.");

        List<CommandInfo> commands = new ArrayList<>(entries.size());
        for (int i = 0; i < entries.size(); i++) {
            Map<String, Object> entry = Json.asObject(entries.get(i));
            if (entry == null) throw invalidEntry(i, "must be an object");
            List<Object> rawAliases = Json.asArray(entry.get("aliases"));
            if (rawAliases == null) throw invalidEntry(i, "aliases must be an array");

            List<String> aliases = new ArrayList<>(rawAliases.size());
            for (Object alias : rawAliases) {
                String value = Json.asString(alias);
                if (value == null || value.isBlank()) throw invalidEntry(i, "aliases must contain non-empty strings");
                aliases.add(value);
            }
            commands.add(new CommandInfo(
                    requiredString(entry, "id", i),
                    requiredString(entry, "command", i),
                    aliases,
                    requiredString(entry, "category", i),
                    requiredString(entry, "description", i),
                    requiredString(entry, "impact", i),
                    requiredString(entry, "riskReason", i),
                    requiredString(entry, "suggestedRisk", i),
                    requiredString(entry, "source", i)));
        }
        return commands;
    }

    private static String requiredString(Map<String, Object> entry, String key, int index) {
        String value = Json.asString(entry.get(key));
        if (value == null || value.isBlank()) throw invalidEntry(index, key + " must be a non-empty string");
        return value;
    }

    private static IllegalArgumentException invalidEntry(int index, String reason) {
        return new IllegalArgumentException("Invalid command intelligence entry at index " + index + ": " + reason);
    }

    public record CommandInfo(
            String id,
            String command,
            List<String> aliases,
            String category,
            String description,
            String impact,
            String riskReason,
            String suggestedRisk,
            String source) {
        public CommandInfo {
            aliases = List.copyOf(aliases);
        }
    }
}
