package com.actiongate.ui;

import com.actiongate.authentication.AuthenticationProvider;
import com.actiongate.authentication.Availability;
import com.actiongate.enforcement.ApprovalRequest;
import com.actiongate.enforcement.ApprovalResult;
import com.actiongate.enforcement.ApprovalService;
import com.actiongate.model.ApprovalStatus;
import com.actiongate.model.MatchedRule;
import com.actiongate.model.RiskLevel;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.locks.ReentrantLock;
import javafx.application.Platform;
import javafx.geometry.Insets;
import javafx.scene.Scene;
import javafx.scene.control.Button;
import javafx.scene.control.Label;
import javafx.scene.control.TextArea;
import javafx.scene.layout.ColumnConstraints;
import javafx.scene.layout.GridPane;
import javafx.scene.layout.HBox;
import javafx.scene.layout.Priority;
import javafx.scene.layout.VBox;
import javafx.stage.Modality;
import javafx.stage.Stage;

/** Operation-specific approval dialog. One dialog at a time; closing the window counts as Deny. */
public final class FxApprovalService implements ApprovalService {
    private final AppState state;
    private final AuthenticationProvider auth;
    private final String stylesheet;
    private final ReentrantLock promptLock = new ReentrantLock(true);

    public FxApprovalService(AppState state, AuthenticationProvider auth, String stylesheet) {
        this.state = state;
        this.auth = auth;
        this.stylesheet = stylesheet;
    }

    @Override
    public ApprovalResult requestApproval(ApprovalRequest r) {
        long deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(r.timeoutSeconds());
        Platform.runLater(() -> state.pending.add(r));
        try {
            if (!promptLock.tryLock(r.timeoutSeconds(), TimeUnit.SECONDS)) return ApprovalResult.timedOut();
            try {
                String bio = biometricStatusText(r);
                CompletableFuture<ApprovalResult> result = new CompletableFuture<>();
                Stage[] stageRef = new Stage[1];
                Platform.runLater(() -> stageRef[0] = show(r, bio, result));
                long remaining = Math.max(1, deadline - System.nanoTime());
                try {
                    return result.get(remaining, TimeUnit.NANOSECONDS);
                } catch (TimeoutException e) {
                    result.complete(ApprovalResult.timedOut());
                    Platform.runLater(() -> {
                        if (stageRef[0] != null) stageRef[0].close();
                    });
                    return ApprovalResult.timedOut();
                }
            } finally {
                promptLock.unlock();
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            return new ApprovalResult(ApprovalStatus.ERROR, null);
        } catch (Exception e) {
            return new ApprovalResult(ApprovalStatus.ERROR, null);
        } finally {
            Platform.runLater(() -> state.pending.remove(r));
        }
    }

    private String biometricStatusText(ApprovalRequest r) {
        if (!r.biometricRequired()) return "Not required for this risk level";
        Availability av = auth.checkAvailability();
        if (av == Availability.AVAILABLE) return "Required: Windows Hello will prompt after you click Approve (" + auth.name() + ")";
        return "Required, but Windows Hello is currently unavailable (" + av + "). The policy decides whether this is denied.";
    }

    private Stage show(ApprovalRequest r, String bioText, CompletableFuture<ApprovalResult> result) {
        Stage st = new Stage();
        st.setTitle("ActionGate – approval required");
        st.initModality(Modality.APPLICATION_MODAL);
        st.setAlwaysOnTop(true);

        Label head = new Label(r.assessment().level() + " RISK – " + "approve this exact operation?");
        head.getStyleClass().addAll("dialog-head", "risk-" + r.assessment().level().name().toLowerCase());

        GridPane g = new GridPane();
        g.setHgap(12);
        g.setVgap(8);
        ColumnConstraints c0 = new ColumnConstraints();
        c0.setMinWidth(170);
        ColumnConstraints c1 = new ColumnConstraints();
        c1.setHgrow(Priority.ALWAYS);
        g.getColumnConstraints().addAll(c0, c1);
        int row = 0;
        row = addRow(g, row, "Agent", r.request().agentId() + " (" + r.request().toolName() + ")");
        TextArea cmd = new TextArea(r.request().command());
        cmd.setEditable(false);
        cmd.setWrapText(true);
        cmd.setPrefRowCount(5);
        cmd.getStyleClass().add("mono");
        g.add(label("Proposed command"), 0, row);
        g.add(cmd, 1, row++);
        row = addRow(g, row, "Working directory", r.request().workingDirectory());
        row = addRow(g, row, "Risk level", r.assessment().level().toString());
        row = addRow(g, row, "Why", r.assessment().explanation());
        StringBuilder rules = new StringBuilder();
        for (MatchedRule m : r.assessment().matchedRules()) {
            if (m.level() == RiskLevel.LOW) continue;
            rules.append("• ").append(m.id()).append(" [").append(m.level()).append("] ").append(m.description()).append('\n');
        }
        row = addRow(g, row, "Matched policy rules", rules.length() == 0 ? "(none above LOW)" : rules.toString().trim());
        row = addRow(g, row, "Requested permissions", permissions(r));
        row = addRow(g, row, "Biometric verification", bioText);
        row = addRow(g, row, "Operation fingerprint", r.digest().substring(0, 16) + "… (approval applies only to this exact command and directory, once)");

        Button approve = new Button("Approve");
        approve.getStyleClass().add("btn-approve");
        Button deny = new Button("Deny");
        deny.setDefaultButton(true);
        deny.getStyleClass().add("btn-deny");
        approve.setDisable(true);
        approve.setOnAction(e -> {
            result.complete(ApprovalResult.approved(r.digest()));
            st.close();
        });
        deny.setOnAction(e -> {
            result.complete(ApprovalResult.denied());
            st.close();
        });
        st.setOnHidden(e -> result.complete(ApprovalResult.denied()));
        // short delay so a stray Enter/click cannot approve instantly
        new Thread(() -> {
            try { Thread.sleep(1200); } catch (InterruptedException ignored) { Thread.currentThread().interrupt(); }
            Platform.runLater(() -> approve.setDisable(false));
        }, "approve-delay").start();

        HBox buttons = new HBox(12, approve, deny);
        buttons.setPadding(new Insets(8, 0, 0, 0));
        VBox root = new VBox(14, head, g, buttons);
        root.setPadding(new Insets(18));
        root.getStyleClass().add("dialog-root");
        Scene sc = new Scene(root, 760, 560);
        if (stylesheet != null) sc.getStylesheets().add(stylesheet);
        st.setScene(sc);
        st.show();
        st.toFront();
        return st;
    }

    private static String permissions(ApprovalRequest r) {
        Set<String> p = new LinkedHashSet<>();
        p.add("Run this one command once in the directory above");
        for (MatchedRule m : r.assessment().matchedRules()) {
            switch (m.category()) {
                case "FILESYSTEM_DESTRUCTION": p.add("Delete or overwrite files"); break;
                case "NETWORK_ACCESS": p.add("Use the network"); break;
                case "PACKAGE_CHANGE": p.add("Install or change software dependencies"); break;
                case "PRIVILEGE_ESCALATION": p.add("Run with elevated privileges"); break;
                case "CREDENTIAL_EXPOSURE": p.add("Read or expose credentials/secrets"); break;
                case "FILESYSTEM_WRITE": p.add("Write files outside the project"); break;
                case "SECURITY_TAMPER": p.add("Change security settings"); break;
                case "UNKNOWN_COMMAND": p.add("Run a program or script whose behaviour is not analysed"); break;
                default: break;
            }
        }
        return String.join("\n", p);
    }

    private static Label label(String t) {
        Label l = new Label(t);
        l.getStyleClass().add("field-label");
        l.setMinWidth(170);
        return l;
    }

    private static int addRow(GridPane g, int row, String k, String v) {
        Label val = new Label(v);
        val.setWrapText(true);
        val.setMaxWidth(560);
        g.add(label(k), 0, row);
        g.add(val, 1, row);
        return row + 1;
    }
}
