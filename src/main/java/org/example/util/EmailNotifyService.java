package org.example.util;

import javax.mail.*;
import javax.mail.internet.InternetAddress;
import javax.mail.internet.MimeMessage;
import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;


public class EmailNotifyService {

    private final String username;
    private final String password;
    private final String fromEmail;
    private final Session session;

    public EmailNotifyService() {
        // Загружаем конфигурацию из файла email.properties
        Properties config = loadConfig();

        // Установка параметров
        this.username = config.getProperty("email.username");
        this.password = config.getProperty("email.password");
        this.fromEmail = config.getProperty("email.from");

        // Создание сессии для отправки писем
        this.session = createSession(config);
    }

    private Properties loadConfig() {
        try {
            Properties props = new Properties();
            InputStream inputStream = EmailNotifyService.class.getClassLoader()
                    .getResourceAsStream("email.properties");
            if (inputStream != null) {
                props.load(inputStream);
            } else {
                throw new IOException("Configuration file 'email.properties' not found!");
            }

            // Параметры для подключения к SMTP-серверу Rambler
            props.put("mail.smtp.host", "smtp.rambler.ru");
            props.put("mail.smtp.port", "465");
            props.put("mail.smtp.auth", "true");
            props.put("mail.smtp.starttls.enable", "true");
            props.put("mail.smtp.socketFactory.port", "465");
            props.put("mail.smtp.socketFactory.class", "javax.net.ssl.SSLSocketFactory");
            props.put("mail.smtp.socketFactory.fallback", "false");
            props.put("mail.debug", "true");

            validateRequiredProperties(props);
            return props;
        } catch (IOException e) {
            throw new RuntimeException("Failed to load email configuration", e);
        }
    }

    private void validateRequiredProperties(Properties properties) {
        String[] requiredKeys = {"email.username", "email.password", "email.from"};
        for (String key : requiredKeys) {
            if (!properties.containsKey(key)) {
                throw new IllegalArgumentException("Missing required property: " + key);
            }
        }
    }

    private Session createSession(Properties config) {
        return Session.getInstance(config, new Authenticator() {
            @Override
            protected PasswordAuthentication getPasswordAuthentication() {
                return new PasswordAuthentication(username, password);
            }
        });
    }

    // Метод для отправки письма с кодом подтверждения
    public void sendCode(String toEmail, String code) throws MessagingException {
        Message message = prepareMimeMessage(toEmail, code);
        Transport.send(message);
    }

    private Message prepareMimeMessage(String toEmail, String code) throws MessagingException {
        Message message = new MimeMessage(session);
        message.setFrom(new InternetAddress(fromEmail));
        message.addRecipient(Message.RecipientType.TO, new InternetAddress(toEmail));
        message.setSubject("Ваш код подтверждения");
        message.setContent("Ваш код подтверждения: " + code, "text/plain");
        return message;
    }

    public static void main(String[] args) {
        try {

            EmailNotifyService service = new EmailNotifyService();

            // Адрес получателя и код подтверждения
            String recipientEmail = "chtobnezabut@rambler.ru";
            String confirmationCode = "ABCDEF";

            // Отправка письма с кодом подтверждения
            service.sendCode(recipientEmail, confirmationCode);

            System.out.println("Письмо с кодом подтверждения успешно отправлено!");
        } catch (MessagingException e) {
            e.printStackTrace();
            System.err.println("Ошибка при отправке письма: " + e.getMessage());
        }
    }
}
