package org.example.services;

import org.example.data.OtpDao;
import org.example.model.OtpCode;
import org.example.util.EmailNotifyService;
import org.example.util.SmppClient;
import org.example.util.TGBot;
import org.json.JSONObject;

import javax.mail.MessagingException;
import java.io.FileWriter;
import java.io.IOException;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Random;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;

public class Otp {

    private final EmailNotifyService emailService;
    private final OtpDao otpDao;
    private final SmppClient smsSender;
    private final TGBot TGBot;
    private ScheduledExecutorService scheduler;

    public Otp(EmailNotifyService emailService, OtpDao otpDao, SmppClient smsSender, TGBot TGBot) {
        this.emailService = emailService;
        this.otpDao = otpDao;
        this.smsSender = smsSender;
        this.TGBot = TGBot;
    }

    public void initiateOperationToEmail(OtpCode otpCode) {
        String destination = "chtobnezabut@rambler.ru";
        try {
            emailService.sendCode(destination, otpCode.getCode()); // Вызов метода sendCode
        } catch (MessagingException e) {
            throw new RuntimeException(e);
        }
        otpDao.saveOtpCode(otpCode);
    }

    public void initiateOperationToTelegram(OtpCode otpCode) {
        TGBot.sendCode("Пользователь", otpCode.getCode());
        otpDao.saveOtpCode(otpCode);
    }

    public void initiateOperationToSmpp(OtpCode otpCode) {
        smsSender.loadProperties();
        String destination = "+7";
        smsSender.sendSms(destination, otpCode.getCode());
        otpDao.saveOtpCode(otpCode);
    }

    public int getCodeLength() {
        return otpDao.getCodeLength();
    }

    public int getLifeTimeInMinutes() {
        return otpDao.getLifeTimeInMinutes();
    }

    public void saveOtpCodeToFile(OtpCode otpCode) {
        otpDao.saveOtpCode(otpCode);

        // Указываем относительный путь к файлу в текущей директории
        String fileName = "otp_code.txt";
        String filePath = System.getProperty("user.dir") + "/" + fileName;

        // Преобразуем объект OtpCode в JSON
        JSONObject jsonObject = new JSONObject(otpCode);
        String jsonData = jsonObject.toString();

        // Открываем файл для записи и перезаписи информации
        try (FileWriter writer = new FileWriter(filePath, false)) {
            writer.write(jsonData);
            writer.flush();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Информируем пользователя о сохранении данных
        System.out.println("\nВсе данные OTP-кода успешно сохранены в файл: " + filePath);
    }

    public String generateOtpCode(int otpCodeLength) {
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < otpCodeLength; i++) {
            sb.append(random.nextInt(10)); // Генерируем случайную цифру
        }
        return sb.toString();
    }

    public List<OtpCode> findAllOtpCodes() {
        return otpDao.findAllOtpCodes();
    }

    public void processExpiredOtpCodes(List<OtpCode> otpCodes) {
        LocalDateTime currentTime = LocalDateTime.now();

        for (OtpCode otpCode : otpCodes) {
            if (currentTime.isAfter(otpCode.getExpirationTime())) {
                otpCode.setStatus("EXPIRED");
                otpDao.updateOtpCodeStatus(otpCode); // Обновляем статус в базе данных
            }
        }
    }

    public void updateUsed(String code) {
        String status = "USED";
        otpDao.updateOtpCodeStatusUsed(code, status); // Обновляем статус в базе данных
    }

    public void initScheduler() {
        int intervalInSeconds = 5000;
        scheduler = Executors.newSingleThreadScheduledExecutor();
        scheduler.scheduleWithFixedDelay(() -> {
            List<OtpCode> otpCodes = otpDao.findAllOtpCodes(); // Загружаем все OTP-коды из базы данных
            processExpiredOtpCodes(otpCodes); // Обрабатываем просроченные OTP-коды
        }, 0, intervalInSeconds, TimeUnit.SECONDS);
    }

    public void shutdown() {
        scheduler.shutdownNow();
    }

    public boolean getOtpCode(String otpCode) {
        return otpDao.getOtpCode(otpCode);
    }

    public void changeOtpConfig(int newCodeLength, int newLifetimeInMinutes) {
        System.out.println("Новая конфигурация OTP-кодов установлена: длина кода " + newCodeLength + ", время жизни " + newLifetimeInMinutes + " минут.");
        otpDao.changeOtpConfig(newCodeLength, newLifetimeInMinutes);
    }
}