package org.example.util;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DbConnect {

    private static final String DB_URL = "jdbc:postgresql://localhost:5432/PromoOTP";
    private static final String USERNAME = "AntonDB";
    private static final String PASSWORD = "AntonDBPass";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, USERNAME, PASSWORD);
    }
}
