package org.thothtrust.sc.thetakey.timetool;

import java.util.ArrayList;
import java.util.List;
import javax.smartcardio.Card;
import javax.smartcardio.CardException;
import javax.smartcardio.CardTerminal;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class DeviceManager {

    private static DeviceManager instance = null;
    private TerminalHandler termMan = null;
    public static final String DEFAULT_CARD_PROTO = TerminalHandler.CARD_PROTO_T_0;
    private ArrayList<THETAKeyDevice> devices = new ArrayList<>();
    private static int appSelection = 0;

    protected DeviceManager() throws CardException {
        termMan = new TerminalHandler();
        refreshDevices();
    }

    public static DeviceManager getInstance() throws CardException {
        if (instance == null) {
            instance = new DeviceManager();
        }

        return instance;
    }

    public static DeviceManager getInstance(int selection) throws CardException {
        appSelection = selection;
        if (instance == null) {
            instance = new DeviceManager();
        }

        return instance;
    }

    public void refreshDevices() throws CardException {
        disconnectAllExistingDevices();
        termMan.loadDefaultTerminal();
        devices.clear();
        List<CardTerminal> terminals = termMan.getTerminals();
        for (int i = 0; i < terminals.size(); i++) {
            Card tempCard = termMan.getCard(DEFAULT_CARD_PROTO, i);
            THETAKeyDevice tempDevice = new THETAKeyDevice(tempCard, terminals.get(i).getName());
            if (tempDevice.connect(appSelection)) {
                devices.add(tempDevice);
            }
        }
    }

    public void disconnectAllExistingDevices() throws CardException {
        if (devices.size() > 0) {
            for (THETAKeyDevice tempDevice : devices) {
                tempDevice.disconnect();
            }
        }
    }

    public int getDevicesCount() {
        return devices.size();
    }

    public ArrayList<THETAKeyDevice> getDevices() {
        return devices;
    }
}
