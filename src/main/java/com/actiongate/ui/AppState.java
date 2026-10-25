package com.actiongate.ui;

import com.actiongate.enforcement.ApprovalRequest;
import com.actiongate.model.EnforcementDecision;
import com.actiongate.model.RiskLevel;
import java.util.EnumMap;
import java.util.Map;
import javafx.beans.property.IntegerProperty;
import javafx.beans.property.SimpleIntegerProperty;
import javafx.beans.property.SimpleStringProperty;
import javafx.beans.property.StringProperty;
import javafx.collections.FXCollections;
import javafx.collections.ObservableList;

/** Observable UI state. All mutations happen on the JavaFX thread. */
public final class AppState {
    public final ObservableList<DecisionRow> recent = FXCollections.observableArrayList();
    public final ObservableList<ApprovalRequest> pending = FXCollections.observableArrayList();
    public final Map<RiskLevel, IntegerProperty> riskCounts = new EnumMap<>(RiskLevel.class);
    public final IntegerProperty allowed = new SimpleIntegerProperty();
    public final IntegerProperty denied = new SimpleIntegerProperty();
    public final StringProperty lastAgentActivity = new SimpleStringProperty("No agent has connected yet");

    public AppState() {
        for (RiskLevel l : RiskLevel.values()) riskCounts.put(l, new SimpleIntegerProperty());
    }

    public void record(EnforcementDecision d, String agent, String command) {
        RiskLevel lv = d.assessment() == null ? RiskLevel.HIGH : d.assessment().level();
        DecisionRow row = DecisionRow.of(agent, command, lv.name(), d.verdict().name(), d.reason());
        recent.add(0, row);
        while (recent.size() > 300) recent.remove(recent.size() - 1);
        riskCounts.get(lv).set(riskCounts.get(lv).get() + 1);
        if (d.allowed()) allowed.set(allowed.get() + 1);
        else denied.set(denied.get() + 1);
        lastAgentActivity.set("Last request from " + agent + " at " + row.time());
    }
}
