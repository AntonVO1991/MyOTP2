package org.example.api;

import com.sun.net.httpserver.Headers;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.example.data.OtpDao;
import org.example.data.UserDao;
import org.example.model.OtpCode;
import org.example.services.Otp;
import org.example.services.User;
import org.example.util.EmailNotifyService;
import org.example.util.SmppClient;
import org.example.util.TGBot;
import org.json.JSONObject;
import org.mindrot.jbcrypt.BCrypt;

import java.io.*;
import java.net.InetSocketAddress;
import java.time.LocalDateTime;

public class UserApi {

    private static final int PORT = 9000;
    private static final String SECRET_KEY = "mySecretKey";

    private final User user;
    private final Otp otp;
    private String token;

    public UserApi(User user, Otp otp) {
        this.user = user;
        this.otp = otp;
    }

    public void startServer() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/register", new RegisterHandler());
        server.createContext("/login", new LoginHandler(user));
        server.createContext("/initiate-operation", new InitiateOperationHandler(otp));
        server.createContext("/verify-otp-code", new VerifyOtpCodeHandler(otp));

        server.setExecutor(null);
        server.start();
        System.out.println("User API server started on port " + PORT);
    }

    public static void main(String[] args) throws IOException {

        UserDao userDao = new UserDao();
        OtpDao otpDao = new OtpDao();
        EmailNotifyService emailService = new EmailNotifyService();
        SmppClient smsSender = new SmppClient();
        TGBot TGBot = new TGBot();
        User user = new User(userDao);
        Otp otp = new Otp(emailService, otpDao, smsSender, TGBot);


        UserApi userApi = new UserApi(user, otp);
        userApi.startServer();
    }

    static class VerifyOtpCodeHandler implements HttpHandler {
        private final Otp otp;

        public VerifyOtpCodeHandler(Otp otp) {
            this.otp = otp;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("POST")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String requestBody = readRequestBody(exchange);
            JSONObject json = new JSONObject(requestBody);
            String code = json.getString("code");

            try {
                boolean isValid = otp.getOtpCode(code);
                JSONObject responseJson = new JSONObject();
                if (isValid) {
                    responseJson.put("message", "Код введен верно!");
                    otp.updateUsed(code);
                } else {
                    responseJson.put("message", "Неверный код!");
                }
                sendSuccessResponse(exchange, responseJson.toString());
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Ошибка проверки OTP-кода: " + e.getMessage());
            }
        }
    }


    class RegisterHandler implements HttpHandler {
        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("POST")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String requestBody = readRequestBody(exchange);
            JSONObject json = new JSONObject(requestBody);
            String username = json.getString("username");
            String password = json.getString("password");
            String role = json.getString("role");

            // Проверяем, существует ли администратор, если да - выдаём ошибку
            if (user.isExistAdmin() && role.equals("ADMIN")) {
                sendErrorResponse(exchange, 409, "Conflict: User with role 'ADMIN' already exists.");
                return;
            }

            // Генерируем соль и хешируем пароль
            String hashedPassword = BCrypt.hashpw(password, BCrypt.gensalt(12)); // Сложность хеширования - 12

            org.example.model.User user = new org.example.model.User(username, hashedPassword, role);

            try {
                if (UserApi.this.user.addUser(user)) {
                    sendSuccessResponse(exchange, "User registered successfully.");
                } else {
                    sendErrorResponse(exchange, 409, "Conflict: User already exists.");
                }
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Internal Server Error: " + e.getMessage());
            }
        }
    }

    static class LoginHandler implements HttpHandler {

        private final User user;

        public LoginHandler(User user) {
            this.user = user;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("POST")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String requestBody = readRequestBody(exchange);
            JSONObject json = new JSONObject(requestBody);
            String username = json.getString("username");
            String password = json.getString("password");

            // Получаем пользователя по имени пользователя
            org.example.model.User user = this.user.getUserByUsername(username);

            if (user != null) {
                // Проверяем пароль с помощью BCrypt
                boolean isValid = BCrypt.checkpw(password, user.getPasswordHash());

                if (isValid) {
                    // Если пароль верный, формируем ответ
                    JSONObject responseJson = new JSONObject();
                    responseJson.put("user", user.toJSONObject()); // Convert User object to JSON

                    sendSuccessResponse(exchange, responseJson.toString());
                } else {
                    // Если пароль неверный, отправляем ошибку
                    sendErrorResponse(exchange, 401, "Unauthorized: Invalid credentials.");
                }
            } else {
                // Если пользователя не нашли, отправляем ошибку
                sendErrorResponse(exchange, 401, "Unauthorized: Invalid credentials.");
            }
        }
    }


    static class InitiateOperationHandler implements HttpHandler {

        private final Otp otp;

        public InitiateOperationHandler(Otp otp) {
            this.otp = otp;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("POST")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String requestBody = readRequestBody(exchange);
            JSONObject json = new JSONObject(requestBody);
            long operationId = json.getLong("id");
            String description = json.getString("description");
            long userId = json.getLong("user_id");


            String channel = json.getString("channel"); // email, SMS, etc.


            int codeLength = otp.getCodeLength();
            int lifeTimeInMinutes = otp.getLifeTimeInMinutes();
            String generatedOtpCode = otp.generateOtpCode(codeLength);
            LocalDateTime currentTime = LocalDateTime.now();
            LocalDateTime expirationTime = currentTime.plusMinutes(lifeTimeInMinutes);


            OtpCode otpCode = new OtpCode(
                    userId,
                    operationId,
                    generatedOtpCode,
                    "ACTIVE",
                    currentTime,
                    expirationTime,
                    description);


            if (channel.equals("email")) {
                otp.initiateOperationToEmail(otpCode);
            } else if (channel.equals("sms")) {
                otp.initiateOperationToSmpp(otpCode);
            } else if (channel.equals("file")) {
                otp.saveOtpCodeToFile(otpCode);
            } else if (channel.equals("telegram")) {
                otp.initiateOperationToTelegram(otpCode);
            } else {
                sendErrorResponse(exchange, 400, "Unsupported channel.");
                return;
            }

            // Создаем JSON-ответ с информацией о коде и канале отправки
            JSONObject responseJson = new JSONObject();
            responseJson.put("otp_code", generatedOtpCode);
            responseJson.put("sent_channel", channel);
            responseJson.put("message", "OTP code sent successfully.");

            // Отправляем успешный ответ
            sendSuccessResponse(exchange, responseJson.toString());
        }

        private static String readRequestBody(HttpExchange exchange) throws IOException {
            InputStream is = exchange.getRequestBody();
            BufferedReader br = new BufferedReader(new InputStreamReader(is));
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = br.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString();
        }

        private void sendSuccessResponse(HttpExchange exchange, String responseBody) throws IOException {
            Headers headers = exchange.getResponseHeaders();
            headers.add("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, responseBody.length());
            OutputStream os = exchange.getResponseBody();
            os.write(responseBody.getBytes());
            os.close();
        }
    }


    private static void sendSuccessResponse(HttpExchange exchange, String response) throws IOException {
        exchange.sendResponseHeaders(200, response.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(response.getBytes());
        os.close();
    }

    private static void sendErrorResponse(HttpExchange exchange, int statusCode, String message) throws IOException {
        exchange.sendResponseHeaders(statusCode, message.getBytes().length);
        OutputStream os = exchange.getResponseBody();
        os.write(message.getBytes());
        os.close();
    }

    private static String readRequestBody(HttpExchange exchange) throws IOException {
        InputStreamReader isr = new InputStreamReader(exchange.getRequestBody());
        BufferedReader br = new BufferedReader(isr);
        StringBuilder requestBody = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            requestBody.append(line);
        }
        return requestBody.toString();
    }

}