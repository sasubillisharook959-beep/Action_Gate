package com.actiongate.ui;

import com.actiongate.AppContext;
import com.actiongate.audit.AuditEvent;
import com.actiongate.audit.VerificationResult;
import com.actiongate.authentication.Availability;
import com.actiongate.integration.CopilotAdapter;
import com.actiongate.integration.HookSettingsGenerator;
import com.actiongate.model.RiskLevel;
import com.actiongate.policy.AgentSettings;
import com.actiongate.policy.BiometricUnavailableBehavior;
import com.actiongate.policy.LevelRule;
import com.actiongate.policy.PolicyValidationException;
import com.actiongate.policy.SecurityPolicy;
import com.actiongate.util.AppPaths;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.EnumMap;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import javafx.application.Application;
import javafx.application.Platform;
import javafx.collections.transformation.FilteredList;
import javafx.geometry.Insets;
import javafx.geometry.Pos;
import javafx.scene.Node;
import javafx.scene.Scene;
import javafx.scene.chart.BarChart;
import javafx.scene.chart.CategoryAxis;
import javafx.scene.chart.NumberAxis;
import javafx.scene.chart.XYChart;
import javafx.scene.control.Alert;
import javafx.scene.control.Button;
import javafx.scene.control.CheckBox;
import javafx.scene.control.ComboBox;
import javafx.scene.control.Label;
import javafx.scene.control.Spinner;
import javafx.scene.control.Tab;
import javafx.scene.control.TabPane;
import javafx.scene.control.TableColumn;
import javafx.scene.control.TableView;
import javafx.scene.control.TextArea;
import javafx.scene.input.Clipboard;
import javafx.scene.input.ClipboardContent;
import javafx.scene.layout.BorderPane;
import javafx.scene.layout.FlowPane;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Stage;

/** ActionGate dashboard. Works with or without a connected agent. */
public final class MainApp extends Application {
    private AppContext ctx;
    private final AppState state = new AppState();
    private String css;

    @Override
    public void start(Stage stage) {
        css = getClass().getResource("/css/actiongate.css").toExternalForm();
        try {
            ctx = AppContext.start(AppPaths.defaultPaths());
        } catch (Exception e) {
            Alert a = new Alert(Alert.AlertType.ERROR, "ActionGate could not start its protection layer, so it is NOT protecting this machine:\n\n"
                    + e.getMessage(), javafx.scene.control.ButtonType.CLOSE);
            a.setTitle("ActionGate – startup failure");
            a.showAndWait();
            Platform.exit();
            return;
        }
        ctx.setApprovalService(new FxApprovalService(state, ctx.auth, css));
        ctx.enforcement.addRequestListener(r -> pendingCommands.put(r.requestId(), new String[]{r.agentId(), r.command()}));
        ctx.enforcement.addListener(d -> {
            String[] info = pendingCommands.remove(d.requestId());
            String agent = info == null ? "agent" : info[0];
            String cmd = info == null ? "" : info[1];
            Platform.runLater(() -> state.record(d, agent, cmd));
        });

        TabPane tabs = new TabPane(
                tab("Dashboard", dashboard()),
                tab("Pending approvals", pendingTab()),
                tab("Blocked commands", blockedTab()),
                tab("Audit history", auditTab()),
                tab("Security policy", policyTab()),
                tab("Agent integration", agentTab()));
        tabs.setTabClosingPolicy(TabPane.TabClosingPolicy.UNAVAILABLE);

        Label title = new Label("ActionGate");
        title.getStyleClass().add("app-title");
        Label badge = new Label("● PROTECTION ACTIVE – 127.0.0.1:" + ctx.server.port());
        badge.getStyleClass().addAll("badge", "badge-ok");
        HBox header = new HBox(18, title, badge);
        header.setAlignment(Pos.CENTER_LEFT);
        header.setPadding(new Insets(14, 18, 14, 18));
        header.getStyleClass().add("header");

        BorderPane root = new BorderPane(tabs);
        root.setTop(header);
        Scene scene = new Scene(root, 1180, 780);
        scene.getStylesheets().add(css);
        stage.setTitle("ActionGate – AI agent command protection");
        stage.setScene(scene);
        stage.setOnCloseRequest(e -> {
            if (!state.pending.isEmpty()) {
                Alert a = new Alert(Alert.AlertType.CONFIRMATION, "Closing ActionGate stops protection: agent commands will be blocked (fail closed) until it runs again. Close anyway?");
                if (a.showAndWait().orElse(javafx.scene.control.ButtonType.CANCEL) != javafx.scene.control.ButtonType.OK) e.consume();
            }
        });
        stage.show();
    }

    private final Map<String, String[]> pendingCommands = new java.util.concurrent.ConcurrentHashMap<>();

    @Override
    public void stop() {
        if (ctx != null) ctx.close();
    }

    private static Tab tab(String t, Node n) {
        Tab tab = new Tab(t, n);
        return tab;
    }

    // ------------------------------------------------------------------ dashboard

    private Node dashboard() {
        FlowPane cards = new FlowPane(14, 14);
        cards.getChildren().addAll(
                card("Protection status", "ACTIVE", "Pre-execution enforcement is running", "ok"),
                card("Hook endpoint", "127.0.0.1:" + ctx.server.port(), "Loopback only, token-authenticated", "ok"),
                card("Authentication", authLabel(), ctx.auth.name(), authOk() ? "ok" : "warn"),
                dynamicCard("Agent connection", state.lastAgentActivity));

        CategoryAxis x = new CategoryAxis();
        NumberAxis y = new NumberAxis();
        y.setMinorTickVisible(false);
        y.setTickUnit(1);
        BarChart<String, Number> chart = new BarChart<>(x, y);
        chart.setLegendVisible(false);
        chart.setAnimated(false);
        chart.setTitle("Risk distribution (this session)");
        chart.setPrefHeight(260);
        XYChart.Series<String, Number> series = new XYChart.Series<>();
        for (RiskLevel l : RiskLevel.values()) {
            XYChart.Data<String, Number> d = new XYChart.Data<>(l.name(), 0);
            d.YValueProperty().bind(state.riskCounts.get(l));
            series.getData().add(d);
        }
        chart.getData().add(series);

        Label totals = new Label();
        totals.textProperty().bind(javafx.beans.binding.Bindings.concat("Allowed: ", state.allowed, "     Denied: ", state.denied,
                "     Waiting for approval: ", javafx.beans.binding.Bindings.size(state.pending)));
        totals.getStyleClass().add("totals");

        TableView<DecisionRow> table = decisionTable(state.recent);
        VBox.setVgrow(table, Priority.ALWAYS);
        Label h = new Label("Recent command requests");
        h.getStyleClass().add("section");
        VBox box = new VBox(14, cards, chart, totals, h, table);
        box.setPadding(new Insets(16));
        return box;
    }

    private boolean authOk() {
        return ctx.auth.checkAvailability() == Availability.AVAILABLE;
    }

    private String authLabel() {
        Availability a = ctx.auth.checkAvailability();
        return a == Availability.AVAILABLE ? "Windows Hello ready" : "Unavailable: " + a;
    }

    private VBox card(String title, String value, String sub, String kind) {
        Label t = new Label(title);
        t.getStyleClass().add("card-title");
        Label v = new Label(value);
        v.getStyleClass().addAll("card-value", "kind-" + kind);
        Label s = new Label(sub);
        s.getStyleClass().add("card-sub");
        s.setWrapText(true);
        VBox b = new VBox(4, t, v, s);
        b.getStyleClass().add("card");
        b.setPrefWidth(270);
        return b;
    }

    private VBox dynamicCard(String title, javafx.beans.value.ObservableValue<String> text) {
        VBox b = card(title, "", "", "ok");
        Label sub = (Label) b.getChildren().get(2);
        sub.textProperty().bind(text);
        Label v = (Label) b.getChildren().get(1);
        v.setText("Optional");
        return b;
    }

    private static TableView<DecisionRow> decisionTable(javafx.collections.ObservableList<DecisionRow> items) {
        TableView<DecisionRow> t = new TableView<>(items);
        t.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        t.getColumns().add(col("Time", 80, DecisionRow::time));
        t.getColumns().add(col("Risk", 90, DecisionRow::level));
        t.getColumns().add(col("Decision", 90, DecisionRow::verdict));
        t.getColumns().add(col("Command", 420, DecisionRow::command));
        t.getColumns().add(col("Reason", 420, DecisionRow::reason));
        t.setPlaceholder(new Label("No commands evaluated yet. ActionGate stays usable without a connected agent."));
        return t;
    }

    private static <S> TableColumn<S, String> col(String name, double w, java.util.function.Function<S, String> f) {
        TableColumn<S, String> c = new TableColumn<>(name);
        c.setPrefWidth(w);
        c.setCellValueFactory(cd -> new javafx.beans.property.SimpleStringProperty(f.apply(cd.getValue())));
        return c;
    }

    // ------------------------------------------------------------------ pending / blocked

    private Node pendingTab() {
        TableView<com.actiongate.enforcement.ApprovalRequest> t = new TableView<>(state.pending);
        t.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        t.getColumns().add(col("Risk", 90, r -> r.assessment().level().name()));
        t.getColumns().add(col("Agent", 110, r -> r.request().agentId()));
        t.getColumns().add(col("Directory", 260, r -> r.request().workingDirectory()));
        t.getColumns().add(col("Command", 520, r -> r.request().command().replace('\n', ' ')));
        t.getColumns().add(col("Windows Hello", 120, r -> r.biometricRequired() ? "required" : "no"));
        t.setPlaceholder(new Label("Nothing is waiting for approval. Approval dialogs open automatically when needed."));
        Label hint = new Label("Each request opens its own approval dialog. Closing a dialog denies the request.");
        hint.getStyleClass().add("card-sub");
        VBox b = new VBox(10, hint, t);
        VBox.setVgrow(t, Priority.ALWAYS);
        b.setPadding(new Insets(16));
        return b;
    }

    private Node blockedTab() {
        FilteredList<DecisionRow> blocked = new FilteredList<>(state.recent, r -> r.verdict().equals("DENY"));
        TableView<DecisionRow> t = decisionTable(blocked);
        t.setPlaceholder(new Label("No commands have been blocked in this session."));
        VBox b = new VBox(10, t);
        VBox.setVgrow(t, Priority.ALWAYS);
        b.setPadding(new Insets(16));
        return b;
    }

    // ------------------------------------------------------------------ audit

    private Node auditTab() {
        TableView<AuditEvent> t = new TableView<>();
        t.setColumnResizePolicy(TableView.CONSTRAINED_RESIZE_POLICY);
        t.getColumns().add(col("#", 50, e -> String.valueOf(e.seq())));
        t.getColumns().add(col("Time (UTC)", 190, e -> e.timestamp().toString()));
        t.getColumns().add(col("Type", 130, AuditEvent::eventType));
        t.getColumns().add(col("Agent", 90, AuditEvent::agentId));
        t.getColumns().add(col("Risk", 80, AuditEvent::riskLevel));
        t.getColumns().add(col("Decision", 80, AuditEvent::decision));
        t.getColumns().add(col("Approval", 110, AuditEvent::approvalStatus));
        t.getColumns().add(col("Biometric", 150, AuditEvent::biometricResult));
        t.getColumns().add(col("Rules", 200, AuditEvent::matchedRules));
        t.getColumns().add(col("Command", 400, e -> e.command().replace('\n', ' ')));
        t.getColumns().add(col("Hash", 160, e -> e.hash().substring(0, 16) + "…"));
        Label result = new Label("Integrity not verified yet");
        Button refresh = new Button("Refresh");
        Button verify = new Button("Verify integrity");
        Runnable load = () -> {
            try {
                t.getItems().setAll(ctx.audit.recent(500));
            } catch (Exception e) {
                result.setText("Cannot read audit log: " + e.getMessage());
            }
        };
        refresh.setOnAction(e -> load.run());
        verify.setOnAction(e -> {
            VerificationResult v = ctx.audit.verify();
            result.setText(v.toString());
            result.getStyleClass().removeAll("kind-ok", "kind-bad");
            result.getStyleClass().add(v.valid() ? "kind-ok" : "kind-bad");
        });
        load.run();
        HBox bar = new HBox(10, refresh, verify, result);
        bar.setAlignment(Pos.CENTER_LEFT);
        VBox b = new VBox(10, bar, t);
        VBox.setVgrow(t, Priority.ALWAYS);
        b.setPadding(new Insets(16));
        return b;
    }

    // ------------------------------------------------------------------ policy

    private Node policyTab() {
        SecurityPolicy p = ctx.policy.base();
        GridPane levels = new GridPane();
        levels.setHgap(18);
        levels.setVgap(8);
        levels.add(bold("Risk level"), 0, 0);
        levels.add(bold("Require approval"), 1, 0);
        levels.add(bold("Require Windows Hello"), 2, 0);
        levels.add(bold("Block"), 3, 0);
        Map<RiskLevel, CheckBox[]> boxes = new EnumMap<>(RiskLevel.class);
        int r = 1;
        for (RiskLevel l : RiskLevel.values()) {
            LevelRule lr = p.levelRule(l);
            CheckBox a = new CheckBox();
            a.setSelected(lr.approval());
            CheckBox bi = new CheckBox();
            bi.setSelected(lr.biometric());
            CheckBox bl = new CheckBox();
            bl.setSelected(lr.block());
            if (l == RiskLevel.CRITICAL) {
                bl.setSelected(true);
                bl.setDisable(true);
            }
            levels.add(new Label(l.name()), 0, r);
            levels.add(a, 1, r);
            levels.add(bi, 2, r);
            levels.add(bl, 3, r);
            boxes.put(l, new CheckBox[]{a, bi, bl});
            r++;
        }
        Label crit = new Label("CRITICAL commands are always blocked and this cannot be changed. Pre-execution enforcement itself cannot be disabled.");
        crit.getStyleClass().add("card-sub");
        crit.setWrapText(true);

        TextArea blocked = area(p.blockedCategories(), 5);
        TextArea prot = area(p.protectedPaths(), 6);
        TextArea allowed = area(p.allowedWorkingDirectories(), 3);
        TextArea trusted = area(p.trustedExecutables(), 3);
        ComboBox<BiometricUnavailableBehavior> bub = new ComboBox<>();
        bub.getItems().setAll(BiometricUnavailableBehavior.values());
        bub.setValue(p.biometricUnavailable());
        Spinner<Integer> timeout = new Spinner<>(10, 600, p.approvalTimeoutSeconds());
        timeout.setEditable(true);
        Spinner<Integer> validity = new Spinner<>(5, 300, p.approvalValiditySeconds());
        validity.setEditable(true);
        Spinner<Integer> port = new Spinner<>(SecurityPolicy.MIN_PORT, SecurityPolicy.MAX_PORT, p.port());
        port.setEditable(true);

        Label status = new Label();
        status.setWrapText(true);
        Button save = new Button("Validate and apply");
        save.setOnAction(e -> {
            try {
                EnumMap<RiskLevel, LevelRule> lv = new EnumMap<>(RiskLevel.class);
                for (RiskLevel l : RiskLevel.values()) {
                    CheckBox[] c = boxes.get(l);
                    lv.put(l, new LevelRule(c[0].isSelected(), c[1].isSelected(), c[2].isSelected()));
                }
                SecurityPolicy np = new SecurityPolicy(lv, new LinkedHashSet<>(lines(blocked)), lines(allowed), lines(prot),
                        new LinkedHashSet<>(lines(trusted)), bub.getValue(), timeout.getValue(), validity.getValue(), port.getValue(),
                        ctx.policy.base().agents());
                ctx.config.apply(np, "dashboard");
                status.getStyleClass().removeAll("kind-bad");
                status.getStyleClass().add("kind-ok");
                status.setText("Policy applied and the change was written to the audit log."
                        + (np.port() != ctx.server.port() ? " Port changes take effect after restarting ActionGate." : ""));
            } catch (PolicyValidationException ex) {
                status.getStyleClass().removeAll("kind-ok");
                status.getStyleClass().add("kind-bad");
                status.setText("Rejected: " + String.join("; ", ex.problems()));
            } catch (Exception ex) {
                status.getStyleClass().add("kind-bad");
                status.setText("Could not apply policy: " + ex.getMessage());
            }
        });

        GridPane form = new GridPane();
        form.setHgap(14);
        form.setVgap(10);
        int i = 0;
        form.add(bold("Blocked categories (one per line)"), 0, i);
        form.add(blocked, 1, i++);
        form.add(bold("Protected paths"), 0, i);
        form.add(prot, 1, i++);
        form.add(bold("Allowed working directories (empty = any)"), 0, i);
        form.add(allowed, 1, i++);
        form.add(bold("Trusted executables (treated as LOW)"), 0, i);
        form.add(trusted, 1, i++);
        form.add(bold("If Windows Hello is unavailable"), 0, i);
        form.add(bub, 1, i++);
        form.add(bold("Approval timeout (s)"), 0, i);
        form.add(timeout, 1, i++);
        form.add(bold("Approval validity (s)"), 0, i);
        form.add(validity, 1, i++);
        form.add(bold("Loopback port"), 0, i);
        form.add(port, 1, i++);

        VBox b = new VBox(14, bold("Risk level requirements"), levels, crit, form, save, status);
        b.setPadding(new Insets(16));
        javafx.scene.control.ScrollPane sp = new javafx.scene.control.ScrollPane(b);
        sp.setFitToWidth(true);
        return sp;
    }

    private static Label bold(String t) {
        Label l = new Label(t);
        l.getStyleClass().add("field-label");
        return l;
    }

    private static TextArea area(java.util.Collection<String> lines, int rows) {
        TextArea a = new TextArea(String.join("\n", lines));
        a.setPrefRowCount(rows);
        a.setPrefColumnCount(60);
        return a;
    }

    private static List<String> lines(TextArea a) {
        return Arrays.stream(a.getText().split("\\R")).map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toCollection(ArrayList::new));
    }

    // ------------------------------------------------------------------ agents

    private Node agentTab() {
        SecurityPolicy p = ctx.policy.base();
        AgentSettings cc = p.agent("claude-code");
        AgentSettings copilot = p.agent(CopilotAdapter.ID);
        CheckBox enabled = new CheckBox("Enable Claude Code integration");
        enabled.setSelected(cc.enabled());
        CheckBox lowAllow = new CheckBox("Answer LOW-risk commands with an explicit \"allow\" (skips Claude Code's own prompt for them)");
        lowAllow.setSelected(cc.explicitAllowLowRisk());
        CheckBox copilotEnabled = new CheckBox("Enable GitHub Copilot integration");
        copilotEnabled.setSelected(copilot.enabled());
        CheckBox copilotLowAllow = new CheckBox("Answer LOW-risk Copilot commands with an explicit \"allow\"");
        copilotLowAllow.setSelected(copilot.explicitAllowLowRisk());
        Button apply = new Button("Apply");
        Label status = new Label();
        apply.setOnAction(e -> {
            try {
                Map<String, AgentSettings> ag = new LinkedHashMap<>(ctx.policy.base().agents());
                ag.put("claude-code", new AgentSettings(enabled.isSelected(), lowAllow.isSelected()));
                ag.put(CopilotAdapter.ID, new AgentSettings(copilotEnabled.isSelected(), copilotLowAllow.isSelected()));
                SecurityPolicy b = ctx.policy.base();
                ctx.config.apply(new SecurityPolicy(b.levels(), b.blockedCategories(), b.allowedWorkingDirectories(), b.protectedPaths(),
                        b.trustedExecutables(), b.biometricUnavailable(), b.approvalTimeoutSeconds(), b.approvalValiditySeconds(), b.port(), ag), "agent settings");
                status.setText("Applied and audited.");
            } catch (Exception ex) {
                status.setText("Could not apply: " + ex.getMessage());
            }
        });
        Path hookJar = HookSettingsGenerator.locateHookJar();
        String snippet = HookSettingsGenerator.snippet(hookJar, p.approvalTimeoutSeconds());
        String copilotSnippet = HookSettingsGenerator.copilotSnippet(hookJar, p.approvalTimeoutSeconds());
        TextArea snip = new TextArea(snippet);
        snip.setEditable(false);
        snip.setPrefRowCount(16);
        snip.getStyleClass().add("mono");
        Button copy = new Button("Copy settings snippet");
        copy.setOnAction(e -> {
            ClipboardContent c = new ClipboardContent();
            c.putString(snippet);
            Clipboard.getSystemClipboard().setContent(c);
        });
        TextArea copilotSnip = new TextArea(copilotSnippet);
        copilotSnip.setEditable(false);
        copilotSnip.setPrefRowCount(10);
        copilotSnip.getStyleClass().add("mono");
        Button copyCopilot = new Button("Copy Copilot hook file");
        copyCopilot.setOnAction(e -> {
            ClipboardContent c = new ClipboardContent();
            c.putString(copilotSnippet);
            Clipboard.getSystemClipboard().setContent(c);
        });
        Path userSettings = Path.of(System.getProperty("user.home"), ".claude", "settings.json");
        String found;
        try {
            found = Files.exists(userSettings) && Files.readString(userSettings).toLowerCase().contains("actiongate")
                    ? "An ActionGate hook entry was found in " + userSettings
                    : "No ActionGate hook entry found in " + userSettings + " (add the snippet below; project-level or managed settings also work)";
        } catch (Exception ex) {
            found = "Could not inspect " + userSettings;
        }
        Label hookState = new Label(found);
        hookState.setWrapText(true);
        Label info = new Label("Endpoint: http://127.0.0.1:" + ctx.server.port() + "/v1/evaluate/claude-code\nEndpoint file (port + token, owner-only): "
                + ctx.paths.ipcFile() + "\nData directory: " + ctx.paths.home() + "\nHook jar (build with: mvn package): " + hookJar
                + "\n\nActionGate cannot see whether an agent actually loaded its hook. Confirm with the agent's hook listing, then run a harmless command."
                + "\nCopilot personal hook location: " + Path.of(System.getProperty("user.home"), ".copilot", "hooks", "actiongate.json")
                + "\nCopilot preToolUse timeout is " + (p.approvalTimeoutSeconds() + 90)
                + " seconds. VS Code documents that hook timeouts fall through to normal permission handling; this timeout is not a fail-closed guarantee.");
        info.setWrapText(true);
        VBox b = new VBox(12, enabled, lowAllow, copilotEnabled, copilotLowAllow, apply, status, bold("Claude Code hook status"), hookState, info,
                bold("Claude Code settings snippet"), snip, copy, bold("Copilot personal hook file (.copilot/hooks/actiongate.json)"), copilotSnip, copyCopilot);
        b.setPadding(new Insets(16));
        javafx.scene.control.ScrollPane sp = new javafx.scene.control.ScrollPane(b);
        sp.setFitToWidth(true);
        return sp;
    }
}
