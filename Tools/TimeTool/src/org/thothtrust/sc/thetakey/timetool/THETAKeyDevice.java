package org.thothtrust.sc.thetakey.timetool;

import javax.smartcardio.Card;
import javax.smartcardio.CardChannel;
import javax.smartcardio.CardException;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

/**
 *
 * @author ThothTrust Pte Ltd.
 */
public class THETAKeyDevice {

    private Card card = null;
    private CardChannel channel = null;
    public static final byte[] APDU_SELECT_THETAKEY = {
        (byte) 0x00, (byte) 0xA4, (byte) 0x04, (byte) 0x00, (byte) 0x05,
        (byte) 0x4B, (byte) 0x4D, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0xFF
    };

    private String terminalName = null;

    public THETAKeyDevice(Card card, String terminalName) {
        if ((card != null) && (terminalName != null)) {
            setCard(card);
            setTerminalName(terminalName);
        }
    }

    public boolean connect(int selection) throws CardException {
        if (card != null) {
            setChannel(getCard().getBasicChannel());
        }
        return checkCard(selection);
    }

    public void disconnect() throws CardException {
        if (card != null) {
            card.disconnect(true);
            card = null;
            channel = null;
        }
    }

    public boolean checkCard(int selection) throws CardException {
        if (channel != null) {
            // Query THETACore Applet
            CommandAPDU cmd = null;
            cmd = new CommandAPDU(APDU_SELECT_THETAKEY);
            ResponseAPDU selectResponse = send(cmd);
            return TerminalHandler.isSuccessfulResponse(selectResponse);
        }

        return false;
    }

    public byte[] getATRBytes() {
        return card.getATR().getBytes();
    }

    public ResponseAPDU send(CommandAPDU message) throws CardException {
        if (channel != null) {
            return channel.transmit(message);
        }

        return null;
    }

    /**
     * @return the card
     */
    public Card getCard() {
        return card;
    }

    /**
     * @param card the card to set
     */
    private void setCard(Card card) {
        this.card = card;
    }

    /**
     * @return the channel
     */
    public CardChannel getChannel() {
        return channel;
    }

    /**
     * @param channel the channel to set
     */
    private void setChannel(CardChannel channel) {
        this.channel = channel;
    }

    /**
     * @return the terminalName
     */
    public String getTerminalName() {
        return terminalName;
    }

    /**
     * @param terminalName the terminalName to set
     */
    private void setTerminalName(String terminalName) {
        this.terminalName = terminalName;
    }

}
