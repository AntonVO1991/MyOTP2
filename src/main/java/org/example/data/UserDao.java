package org.example.data;

import org.example.model.User;
import org.example.util.DbConnect;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class UserDao {

    private Connection connection;

    public UserDao() {
        try {
            connection = DbConnect.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<User> findAllUsers() {
        List<User> users = new ArrayList<>();
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE role = ?");

            stmt.setString(1, "USER");

            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {

                // Создаем объект User с преобразованной ролью
                User user = new User(
                        rs.getLong("id"),          // ID пользователя
                        rs.getString("username"),  // Имя пользователя
                        rs.getString("password_hash"), // Хэш пароля
                        rs.getString("role")
                );
                users.add(user);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return users;
    }

    public List<User> findAllAdmins() {
        List<User> users = new ArrayList<>();
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE role = ?");

            stmt.setString(1, "ADMIN");

            ResultSet rs = stmt.executeQuery();

            while (rs.next()) {

                // Создаем объект User с преобразованной ролью
                User user = new User(
                        rs.getLong("id"),          // ID пользователя
                        rs.getString("username"),  // Имя пользователя
                        rs.getString("password_hash"), // Хэш пароля
                        rs.getString("role")
                );
                users.add(user);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return users;
    }

    public User findUserByUsername(String username) {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {

                return new User(
                        rs.getLong("id"),
                        rs.getString("username"),
                        rs.getString("password_hash"),
                        rs.getString("role")
                );
            }
            return null; // Возвращаем null, если пользователь не найден
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean saveUser(User user) {
        try {
            PreparedStatement stmt = connection.prepareStatement("INSERT INTO users(username, password_hash, role) VALUES (?, ?, ?)");
            stmt.setString(1, user.getUsername());
            stmt.setString(2, user.getPasswordHash());
            stmt.setString(3, user.getRole());
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean updateUser(User user) {
        try {
            PreparedStatement stmt = connection.prepareStatement("UPDATE users SET password_hash = ?, role = ? WHERE username = ?");
            stmt.setString(1, user.getPasswordHash());
            stmt.setString(2, user.getRole());
            stmt.setString(3, user.getUsername());
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public boolean deleteUser(long id) {
        try {
            PreparedStatement stmt = connection.prepareStatement("DELETE FROM users WHERE id = ?");
            stmt.setLong(1, id);
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public String getRole(String username) {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT role FROM users WHERE username = ?");
            stmt.setString(1, username);
            ResultSet rs = stmt.executeQuery();
            if (rs.next()) {
                return rs.getString("role");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return null; // Возвращаем null, если роль не найдена
    }

}