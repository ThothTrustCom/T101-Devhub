package org.thothtrust.sc.thetakey.timetool;

import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class TimeTool {

    private static DeviceManager devMan = null;

    public static void main(String[] args) {
        try {
            devMan = DeviceManager.getInstance();
            try {
                switch (args[0]) {
                    case "-list":
                        list();
                        break;
                    case "-setkey":
                        if (args.length == 3) {
                            byte[] keyBytes = BinUtils.hexStringToByteArray(args[1]);
                            int devPos = Integer.valueOf(args[2]);
                            if (keyBytes.length == 32) {
                                setKey(devMan.getDevices().get(devPos), keyBytes, (short) 0);
                            } else {
                                System.out.println("[ERR] Incorrect time key argument length !");
                            }
                        } else {
                            System.out.println("[ERR] Incorrect argument length !");
                        }
                        break;
                    case "-settime":
                        if (args.length == 3) {
                            byte[] keyBytes = BinUtils.hexStringToByteArray(args[1]);
                            int devPos = Integer.valueOf(args[2]);
                            if (keyBytes.length == 32) {
                                setTime(devMan.getDevices().get(devPos), keyBytes, (short) 0);
                            } else {
                                System.out.println("[ERR] Incorrect time key argument length !");
                            }
                        } else {
                            System.out.println("[ERR] Incorrect argument length !");
                        }
                        break;
                    case "-gettime":
                        if (args.length == 2) {
                            int devPos = Integer.valueOf(args[1]);
                            getTime(devMan.getDevices().get(devPos));                            
                        } else {
                            System.out.println("[ERR] Incorrect argument length !");
                        }
                        break;
                    default:
                        System.out.println("[ERR] Incorrect argument(s) !");
                        break;
                }
            } catch (Exception e) {
                System.out.println("[ERR] Incorrect argument(s) !");
                help();
            }
        } catch (CardException ex) {
            Logger.getLogger(TimeTool.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static void list() {
        System.out.println("Listing THETAKey T101 devices ...");
        System.out.println("Devices: " + devMan.getDevicesCount());
        ArrayList<THETAKeyDevice> tempDevList = devMan.getDevices();
        THETAKeyDevice tempDev = null;
        for (int i = 0; i < tempDevList.size(); i++) {
            tempDev = tempDevList.get(i);
            System.out.println("Pos: " + i + ", Termianl Name: " + tempDev.getTerminalName());
        }
    }

    public static void setKey(THETAKeyDevice dev, byte[] keyBytes, short offset) throws CardException {
        System.out.println("Setting time key ...");
        ResponseAPDU resp = dev.send(new CommandAPDU((byte) 0xB0, (byte) 0x04, (byte) 0x00, (byte) 0x00, keyBytes, offset, 32, 255));
        System.out.println("Response: " + BinUtils.toHexString(resp.getBytes()));
        if (TerminalHandler.isSuccessfulResponse(resp)) {
            System.out.println("[INF] Successfully installed time key ...");
        } else {
            System.out.println("[ERR] Failed to set time key ...");
            System.out.println("Error Status Word: " + BinUtils.toHexString(TerminalHandler.getResponseSW(resp)));
        }
    }

    /**
     * Utilizes computer time for time setting.
     */
    public static void setTime(THETAKeyDevice dev, byte[] keyBytes, short offset) throws InvalidKeyException, NoSuchAlgorithmException, CardException {
        // Query device for challenge nonce
        boolean allowProceed = false;
        ResponseAPDU resp = null;
        resp = dev.send(new CommandAPDU((byte) 0xB0, (byte) 0x03, (byte) 0x00, (byte) 0x00, 255));
        System.out.println("Response: " + BinUtils.toHexString(resp.getBytes()));
        allowProceed = TerminalHandler.isSuccessfulResponse(resp);

        if (allowProceed) {
            byte[] timekey = new byte[32];
            System.arraycopy(keyBytes, offset, timekey, 0, 32);
            byte[] nonce = TerminalHandler.getSuccessfulResponseData(resp);
            System.out.println("Challenge nonce: " + BinUtils.toHexString(nonce));

            // Get current timestamp and conver to UNIX binary timestamp
            Timestamp ts = new Timestamp(System.currentTimeMillis());
            byte[] tsBytes = DateTimeUtil.unixHexBytesFromTimestsamp(ts);
            System.out.println("Current computer timestamp: " + ts.toString());
            System.out.println("Setting time in unix: " + BinUtils.toHexString(tsBytes));

            // Format response block
            String responseSetTimestamp = "010001" + BinUtils.toHexString(nonce) + BinUtils.toHexString(tsBytes);

            // Sign timestamp response block
            Mac hmacsha256 = Mac.getInstance("HmacSHA256");
            SecretKeySpec secret = new SecretKeySpec(timekey, "HmacSHA256");
            hmacsha256.init(secret);
            byte[] macRes = hmacsha256.doFinal(BinUtils.hexStringToByteArray(responseSetTimestamp));

            // Append signature to response block
            responseSetTimestamp += BinUtils.toHexString(macRes);

            System.out.println("Response Block: " + responseSetTimestamp);

            resp = dev.send(new CommandAPDU((byte) 0xB0, (byte) 0x03, (byte) 0x00, (byte) 0x00, BinUtils.hexStringToByteArray(responseSetTimestamp), 255));
            System.out.println("Response: " + BinUtils.toHexString(resp.getBytes()));
            if (TerminalHandler.isSuccessfulResponse(resp)) {
                System.out.println("[INF] Successfully updated T101 RTC clock ...");
            } else {
                System.out.println("[ERR] Failed to update T101 RTC clock ...");
                System.out.println("Error Status Word: " + BinUtils.toHexString(TerminalHandler.getResponseSW(resp)));
            }
        } else {
            System.out.println("[ERR] Unable to obtain time setting challenge ... exiting");
        }
    }
    
    public static void getTime(THETAKeyDevice dev) throws CardException {
        System.out.println("Getting T101 time ...");
        ResponseAPDU resp = dev.send(new CommandAPDU((byte) 0xB0, (byte) 0xFF, (byte) 0x00, (byte) 0x09, 255));
        if (TerminalHandler.isSuccessfulResponse(resp)) {
            System.out.println("[INF] Current device time (hex): " + BinUtils.toHexString(TerminalHandler.getSuccessfulResponseData(resp)));
        } else {
            System.out.println("[ERR] Failed to get time ...");
            System.out.println("Error Status Word: " + BinUtils.toHexString(TerminalHandler.getResponseSW(resp)));
        }
    }

    public static void help() {
        System.out.println("ThothTrust TimeTool v1.0");
        System.out.println("========================");
        System.out.println("Time Setting Tool for THETAKey T101.\r\n");
        System.out.println("Args:                                   Desc:");
        System.out.println("-list ................................. List all available THETAKey devices.");
        System.out.println("-setkey <256bit-hex-keybytes> <pos> ... Setting Time Key in Factory mode.");
        System.out.println("-settime <256bit-hex-keybytes> <pos> .. Syncs computer time to T101 with");
        System.out.println("                                        HMAC-SHA256 Challenge Respond using");
        System.out.println("                                        Time Key.");
        System.out.println("-gettime <pos> ........................ Get T101 device time.");
    }
}
