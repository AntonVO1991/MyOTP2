package org.example.api;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import com.sun.net.httpserver.HttpServer;
import org.example.data.OtpDao;
import org.example.data.UserDao;
import org.example.services.Otp;
import org.example.services.User;
import org.example.util.EmailNotifyService;
import org.example.util.SmppClient;
import org.example.util.TGBot;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.util.ArrayList;
import java.util.List;

public class AdminApi {

    private static final int PORT = 8000;

    public static void main(String[] args) throws IOException {
        // Экземпляры DAO и сервисы
        UserDao userDao = new UserDao();
        OtpDao otpDao = new OtpDao();
        EmailNotifyService emailService = new EmailNotifyService();
        SmppClient smsSender = new SmppClient();
        TGBot TGBot = new TGBot();

        User user = new User(userDao);
        Otp otp = new Otp(emailService, otpDao, smsSender, TGBot);

        // HTTP-сервер
        HttpServer server = HttpServer.create(new InetSocketAddress(PORT), 0);
        server.createContext("/admin/configure-otp", new ConfigureOtpHandler(otp));
        server.createContext("/admin/list-users", new ListUsersHandler(user));
        server.createContext("/admin/delete-user", new DeleteUserHandler(user));
        server.setExecutor(null); // creates a default executor
        server.start();
        System.out.println("Admin API server started on port " + PORT);
    }


    static class ConfigureOtpHandler implements HttpHandler {
        private Otp otp;

        public ConfigureOtpHandler(Otp otp) {
            this.otp = otp;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("POST")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String requestBody = readRequestBody(exchange);
            String[] params = requestBody.split("&");
            List<String> paramList = new ArrayList<>();
            for (String param : params) {
                String[] keyValue = param.split("=");
                if (keyValue.length == 2) {
                    paramList.add(keyValue[1]);
                }
            }

            if (paramList.size() >= 2) {
                int codeLength = Integer.parseInt(paramList.get(0));
                int lifetimeInMinutes = Integer.parseInt(paramList.get(1));


                try {
                    otp.changeOtpConfig(codeLength, lifetimeInMinutes);
                    sendSuccessResponse(exchange, "OTP configuration updated successfully.");
                } catch (Exception e) {
                    sendErrorResponse(exchange, 500, "Failed to update OTP configuration: " + e.getMessage());
                }
            } else {
                sendErrorResponse(exchange, 400, "Missing or invalid parameters.");
            }
        }
    }


    static class ListUsersHandler implements HttpHandler {
        private final User user;

        public ListUsersHandler(User user) {
            this.user = user;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("GET")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }

            try {
                List<org.example.model.User> users = user.getAllUsers();
                String response = "";
                for (org.example.model.User user : users) {
                    response += user.getId() + " " + user.getUsername() + " (" + user.getRole() + ")\n";
                }
                sendSuccessResponse(exchange, response);
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Failed to retrieve users: " + e.getMessage());
            }
        }
    }


    static class DeleteUserHandler implements HttpHandler {

        private final User user;

        public DeleteUserHandler(User user) {
            this.user = user;
        }

        @Override
        public void handle(HttpExchange exchange) throws IOException {
            if (!exchange.getRequestMethod().equals("DELETE")) {
                sendErrorResponse(exchange, 405, "Method Not Allowed");
                return;
            }


            String path = exchange.getRequestURI().toString();
            String[] pathParts = path.split("/");
            if (pathParts.length < 3) {
                sendErrorResponse(exchange, 404, "User ID not found in the request.");
                return;
            }
            long userId = Long.parseLong(pathParts[pathParts.length - 1]);

            // Call service method to delete the user
            try {
                user.deleteUser(userId);
                sendSuccessResponse(exchange, "User deleted successfully.");
            } catch (Exception e) {
                sendErrorResponse(exchange, 500, "Failed to delete user: " + e.getMessage());
            }
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
        java.io.InputStreamReader isr = new java.io.InputStreamReader(exchange.getRequestBody());
        java.io.BufferedReader br = new java.io.BufferedReader(isr);
        StringBuilder requestBody = new StringBuilder();
        String line;
        while ((line = br.readLine()) != null) {
            requestBody.append(line);
        }
        return requestBody.toString();
    }
}