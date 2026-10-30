package com.actiongate.ui;

import java.time.LocalTime;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public record DecisionRow(String time, String agent, String command, String level, String verdict, String reason,
                          String originalCommand) {
    private static final DateTimeFormatter F = DateTimeFormatter.ofPattern("HH:mm:ss");

    public DecisionRow(String time, String agent, String command, String level, String verdict, String reason) {
        this(time, agent, command, level, verdict, reason, command);
    }

    public static DecisionRow of(String agent, String command, String level, String verdict, String reason) {
        String c = command.replace('\n', ' ');
        if (c.length() > 160) c = c.substring(0, 160) + "…";
        String r = reason == null ? "" : reason;
        if (r.length() > 200) r = r.substring(0, 200) + "…";
        return new DecisionRow(LocalTime.now(ZoneId.systemDefault()).format(F), agent, c, level, verdict, r, command);
    }
}
