package com.actiongate;

import com.actiongate.ui.MainApp;
import com.actiongate.util.AppPaths;
import javafx.application.Application;

/** Entry point. Not a JavaFX Application subclass so it also starts when JavaFX is on the module path. */
public final class App {
    private App() {}

    public static void main(String[] args) throws Exception {
        for (String a : args) {
            if (a.equals("--headless")) {
                runHeadless();
                return;
            }
        }
        Application.launch(MainApp.class, args);
    }

    /** Enforcement endpoint without a UI: anything needing approval is denied. Useful for CI and diagnostics. */
    private static void runHeadless() throws Exception {
        AppContext ctx = AppContext.start(AppPaths.defaultPaths());
        System.out.println("ActionGate headless: listening on 127.0.0.1:" + ctx.server.port()
                + " (approvals are denied automatically). Press Ctrl+C to stop.");
        Runtime.getRuntime().addShutdownHook(new Thread(ctx::close));
        Thread.currentThread().join();
    }
}
