package com.actiongate.storage;

import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.List;

/** Single SQLite connection (via JDBC) guarded by a lock. All access is parameterised. */
public final class Database implements AutoCloseable {
    static {
        try {
            Class.forName("org.sqlite.JDBC"); // explicit registration (works in plain classpath and packaged setups)
        } catch (ClassNotFoundException e) {
            throw new ExceptionInInitializerError("SQLite JDBC driver (org.xerial:sqlite-jdbc) is missing from the classpath");
        }
    }

    private final Connection conn;
    private final Object lock = new Object();

    @FunctionalInterface
    public interface RowMapper<T> {
        T map(ResultSet rs) throws SQLException;
    }

    @FunctionalInterface
    public interface SqlWork<T> {
        T run(Database db) throws SQLException;
    }

    public Database(Path file) throws SQLException {
        this("jdbc:sqlite:" + file.toAbsolutePath());
    }

    private Database(String url) throws SQLException {
        this.conn = DriverManager.getConnection(url);
        try (Statement s = conn.createStatement()) {
            s.execute("PRAGMA foreign_keys=ON");
            s.execute("PRAGMA synchronous=FULL");
            s.execute("CREATE TABLE IF NOT EXISTS audit_events ("
                    + "seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                    + "event_id TEXT NOT NULL UNIQUE,"
                    + "ts TEXT NOT NULL,"
                    + "event_type TEXT NOT NULL,"
                    + "agent_id TEXT NOT NULL,"
                    + "command TEXT NOT NULL,"
                    + "working_dir TEXT NOT NULL,"
                    + "risk_level TEXT NOT NULL,"
                    + "matched_rules TEXT NOT NULL,"
                    + "decision TEXT NOT NULL,"
                    + "approval_status TEXT NOT NULL,"
                    + "biometric_result TEXT NOT NULL,"
                    + "execution_result TEXT NOT NULL,"
                    + "prev_hash TEXT NOT NULL,"
                    + "hash TEXT NOT NULL)");
        }
    }

    public static Database inMemory() throws SQLException {
        return new Database("jdbc:sqlite::memory:");
    }

    public <T> T inTransaction(SqlWork<T> work) throws SQLException {
        synchronized (lock) {
            boolean old = conn.getAutoCommit();
            conn.setAutoCommit(false);
            try {
                T r = work.run(this);
                conn.commit();
                return r;
            } catch (SQLException | RuntimeException e) {
                conn.rollback();
                throw e;
            } finally {
                conn.setAutoCommit(old);
            }
        }
    }

    public int update(String sql, Object... params) throws SQLException {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                bind(ps, params);
                return ps.executeUpdate();
            }
        }
    }

    public <T> List<T> query(String sql, RowMapper<T> mapper, Object... params) throws SQLException {
        synchronized (lock) {
            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                bind(ps, params);
                try (ResultSet rs = ps.executeQuery()) {
                    List<T> out = new ArrayList<>();
                    while (rs.next()) out.add(mapper.map(rs));
                    return out;
                }
            }
        }
    }

    private static void bind(PreparedStatement ps, Object[] params) throws SQLException {
        for (int i = 0; i < params.length; i++) ps.setObject(i + 1, params[i]);
    }

    @Override
    public void close() {
        synchronized (lock) {
            try {
                conn.close();
            } catch (SQLException ignored) {
                // nothing useful to do
            }
        }
    }
}
