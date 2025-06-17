package org.example.util;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Properties;

public class TGBot {

    Properties properties = new Properties();

    private final Log logger = LogFactory.getLog(getClass());
    private final String telegramApiUrl = "https://api.telegram.org/bot";
    private final String botToken = "79516480777:AAH9ZQcPXkn-x1AM1u6AEUuVMPiGFY7fkQo";
    private final long chatId = 542172581L; // Замените на полученный chatId

    public void sendCode(String destination, String code) {
        String message = String.format("%s, ваш код подтверждения: %s", destination, code);
        String encodedMessage = URLEncoder.encode(message, StandardCharsets.UTF_8);

        String url = String.format(
                "%s%s/sendMessage?chat_id=%d&text=%s",
                telegramApiUrl, botToken, chatId, encodedMessage
        );

        sendTelegramRequest(url);
    }

    private void sendTelegramRequest(String url) {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                int statusCode = response.getStatusLine().getStatusCode();

                if (statusCode == 200) {
                    logger.info("Сообщение успешно отправлено.");
                } else {
                    logger.error("Ошибка при отправке сообщения. Код статуса: {}");
                }
            }
        } catch (IOException e) {
            logger.error("Произошла ошибка при отправке сообщения: {}");
        }
    }

    public static void main(String[] args) {
        TGBot service = new TGBot();
        service.sendCode("Пользователь", "12345"); // Здесь можно заменить на реальные значения
    }
}
