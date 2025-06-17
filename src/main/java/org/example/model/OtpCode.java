package org.example.model;

import java.time.LocalDateTime;

public class OtpCode {

    private long id;
    private long user_id;
    private long operationId; // Новое поле для operation_id
    private String code;
    private String status;
    private LocalDateTime creationTime;
    private LocalDateTime expirationTime;
    private String description_operation;

    // Конструктор для вставки новых записей
    public OtpCode(long user_id, long operationId, String code, String status, LocalDateTime creationTime, LocalDateTime expirationTime, String description_operation) {
        this.user_id = user_id;
        this.operationId = operationId;
        this.code = code;
        this.status = status;
        this.creationTime = creationTime;
        this.expirationTime = expirationTime;
        this.description_operation = description_operation;
    }

    // Конструктор для получения существующих записей
    public OtpCode(long id, long user_id, long operationId, String code, String status, LocalDateTime creationTime, LocalDateTime expirationTime, String description_operation) {
        this.id = id;
        this.user_id = user_id;
        this.operationId = operationId;
        this.code = code;
        this.status = status;
        this.creationTime = creationTime;
        this.expirationTime = expirationTime;
        this.description_operation = description_operation;
    }

    // Геттеры и сеттеры
    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public long getUser_id() {
        return user_id;
    }

    public long getOperationId() {
        return operationId;
    }

    public String getDescription_operation() {
        return description_operation;
    }

    public void setOperationId(long operationId) {
        this.operationId = operationId;
    }

    public String getCode() {
        return code;
    }

    public void setCode(String code) {
        this.code = code;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public LocalDateTime getCreationTime() {
        return creationTime;
    }

    public void setCreationTime(LocalDateTime creationTime) {
        this.creationTime = creationTime;
    }

    public LocalDateTime getExpirationTime() {
        return expirationTime;
    }

    public void setExpirationTime(LocalDateTime expirationTime) {
        this.expirationTime = expirationTime;
    }

    // Переопределённый метод toString для удобного вывода
    @Override
    public String toString() {
        return "OtpCode{" +
                "id=" + id +
                "user_id=" + user_id +
                ", operation_id=" + operationId + // Включаем operationId в вывод
                ", otp_code='" + code + '\'' +
                ", status=" + status +
                ", created_at=" + creationTime +
                ", expires_at=" + expirationTime +
                ", description_operation=" + description_operation +
                '}';
    }
}