package org.example.util;

import org.smpp.Session;
import org.smpp.TCPIPConnection;
import org.smpp.pdu.BindResponse;
import org.smpp.pdu.BindTransmitter;
import org.smpp.pdu.SubmitSM;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class SmppClient {

    private String host;
    private int port;
    private String systemId;
    private String password;
    private String systemType;
    private String sourceAddress;

    public void loadProperties() {
        Properties properties = new Properties();
        try (InputStream inputStream = getClass().getClassLoader().getResourceAsStream("sms.properties")) {
            if (inputStream != null) {
                properties.load(inputStream);
                host = properties.getProperty("smpp.host");
                port = Integer.parseInt(properties.getProperty("smpp.port"));
                systemId = properties.getProperty("smpp.system_id");
                password = properties.getProperty("smpp.password");
                systemType = properties.getProperty("smpp.system_type");
                sourceAddress = properties.getProperty("smpp.source_addr");
            } else {
                throw new IOException("File 'sms.properties' not found");
            }
        } catch (IOException e) {
            throw new RuntimeException("Failed to load SMS properties", e);
        }
    }

    public void sendSms(String destination, String code) {
        try {

            TCPIPConnection connection = new TCPIPConnection(host, port);
            Session session = new Session(connection);


            BindTransmitter bindRequest = new BindTransmitter();
            bindRequest.setSystemId(systemId);
            bindRequest.setPassword(password);
            bindRequest.setSystemType(systemType);
            bindRequest.setInterfaceVersion((byte) 0x34); // SMPP v3.4
            bindRequest.setAddressRange(sourceAddress);


            BindResponse bindResponse = session.bind(bindRequest);
            if (bindResponse.getCommandStatus() != 0) {
                throw new Exception("Bind failed: " + bindResponse.getCommandStatus());
            }


            SubmitSM submitSm = new SubmitSM();


            if (sourceAddress == null || sourceAddress.trim().isEmpty()) {
                throw new IllegalStateException("Source address cannot be empty or null");
            }
            if (destination == null || destination.trim().isEmpty()) {
                throw new IllegalStateException("Destination number cannot be empty or null");
            }

            submitSm.setSourceAddr(sourceAddress);
            submitSm.setDestAddr(destination);
            submitSm.setShortMessage("Your code: " + code);

            session.submit(submitSm);
            System.out.println("Сообщение успешно отправлено.");
        } catch (Exception e) {
            System.err.println("Ошибка при отправке сообщения: " + e.getMessage());
        }
    }
}