package org.example.data;

import org.example.model.OtpCode;
import org.example.util.DbConnect;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.List;

public class OtpDao {

    private Connection connection;

    public OtpDao() {
        try {
            connection = DbConnect.getConnection();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public List<OtpCode> findAllOtpCodes() {
        List<OtpCode> otpCodes = new ArrayList<>();
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM otp_codes");
            ResultSet rs = stmt.executeQuery();
            while (rs.next()) {
                OtpCode otpCode = new OtpCode(
                        rs.getLong("id"),
                        rs.getLong("user_id"),
                        rs.getLong("operation_id"),
                        rs.getString("otp_code"),
                        rs.getString("status"),
                        rs.getTimestamp("created_at").toLocalDateTime(),
                        rs.getTimestamp("expires_at") != null ? rs.getTimestamp("expires_at").toLocalDateTime() : null,
                        rs.getString("description")
                );
                otpCodes.add(otpCode);
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
        return otpCodes;
    }

    public int getCodeLength() {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT codelength FROM otp_config");
            ResultSet resultSet = stmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getInt("codelength");
            } else {
                throw new RuntimeException("Не удалось получить длину кода.");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public int getLifeTimeInMinutes() {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT lifetimeinminutes FROM otp_config");
            ResultSet resultSet = stmt.executeQuery();

            if (resultSet.next()) {
                return resultSet.getInt("lifetimeinminutes");
            } else {
                throw new RuntimeException("Не удалось получить длину кода.");
            }
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }


    public boolean saveOtpCode(OtpCode otpCode) {
        try {
            PreparedStatement stmt = connection.prepareStatement("INSERT INTO otp_codes(user_id, operation_id, otp_code, status, created_at, expires_at, description) VALUES (?, ?, ?, ?, ?, ?, ?)");
            stmt.setLong(1, otpCode.getUser_id());
            stmt.setLong(2, otpCode.getOperationId());
            stmt.setString(3, otpCode.getCode());
            stmt.setString(4, otpCode.getStatus());
            stmt.setObject(5, otpCode.getCreationTime());
            stmt.setObject(6, otpCode.getExpirationTime());
            stmt.setString(7, otpCode.getDescription_operation());
            int rowsAffected = stmt.executeUpdate();
            return rowsAffected > 0;
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void updateOtpCodeStatus(OtpCode otpCode) {
        try {
            PreparedStatement stmt = connection.prepareStatement("UPDATE otp_codes SET status = ? WHERE id = ?");
            stmt.setString(1, otpCode.getStatus());
            stmt.setLong(2, otpCode.getId());
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void updateOtpCodeStatusUsed(String code, String status) {
        try {
            PreparedStatement stmt = connection.prepareStatement("UPDATE otp_codes SET status = ? WHERE otp_code = ?");
            stmt.setString(1, status);
            stmt.setString(2, code);
            stmt.executeUpdate();
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }

    public void changeOtpConfig(int otpCodeLength, int otpLifetimeInMinutes) {
        try {
            PreparedStatement stmt = connection.prepareStatement("UPDATE otp_config SET codelength = ?, lifetimeinminutes = ? WHERE id = 1");
            stmt.setInt(1, otpCodeLength);
            stmt.setInt(2, otpLifetimeInMinutes);
            int rowsUpdated = stmt.executeUpdate();
            if (rowsUpdated > 0) {
                System.out.println("Конфигурация успешно обновлена.");
            } else {
                System.out.println("Не удалось обновить конфигурацию.");
            }
        } catch (SQLException e) {
            System.err.println("Ошибка при обновлении конфигурации: " + e.getMessage());
        }
    }

    public boolean getOtpCode(String id) {
        try {
            PreparedStatement stmt = connection.prepareStatement("SELECT * FROM otp_codes WHERE otp_code = ?");
            stmt.setString(1, id);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                // Проверяем статус OTP-кода
                String status = rs.getString("status");
                if ("ACTIVE".equalsIgnoreCase(status)) {
                    return true; // OTP-код активен
                } else {
                    return false; // OTP-код неактивен или просрочен
                }
            }
            return false; // OTP-код не найден
        } catch (SQLException e) {
            throw new RuntimeException(e);
        }
    }
}
