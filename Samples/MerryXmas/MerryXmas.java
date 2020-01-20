package MerryXmas ;

import javacard.framework.*;
import javacard.framework.Util;
import javacard.security.MessageDigest;
import javacard.security.CryptoException;
import javacard.security.ECPrivateKey;
import javacard.security.ECPublicKey;
import javacard.security.KeyPair;
import javacard.security.KeyBuilder;
import javacard.security.RandomData;
import javacardx.crypto.Cipher;

public class MerryXmas extends Applet implements AppletEvent {
	public AID apiAID;
    public KM101.T101OpenAPI api = null;
    public static byte[] b0;
    public short[] sb = JCSystem.makeTransientShortArray((short) 3, JCSystem.CLEAR_ON_RESET);
    public static byte[] serverAID = new byte[]{
						(byte) 0x4B, (byte) 0x4D, (byte) 0x31, (byte) 0x30, (byte) 0x31, (byte) 0x00
					};
	public static byte[] appName = {
		(byte) 0x4D, (byte) 0x65, (byte) 0x72, (byte) 0x72, (byte) 0x79, (byte) 0x58, (byte) 0x4D, (byte) 0x41, (byte) 0x53
	};
		
	public static byte[] aocPin = {(byte) 0x31, (byte) 0x32, (byte) 0x33};

	public static byte[] adminUser = {(byte) 0x41, (byte) 0x42, (byte) 0x43, (byte) 0x44, (byte) 0x45, (byte) 0x46, (byte) 0x47, (byte) 0x48, 
									  (byte) 0x49, (byte) 0x4a, (byte) 0x4b, (byte) 0x4C, (byte) 0x4D, (byte) 0x4E, (byte) 0x39};
									  
	public static byte[] adminPin = {(byte) 0x34, (byte) 0x35, (byte) 0x36};
	
	public static final short tries = (short) 3;
	
	public static final byte[] ets = {(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00};
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		new MerryXmas();
	}
	
	public void uninstall() {
		// Destroy AOC container together with its users and objects and also access to API during applet deletion.		
		destroyEnv();
	}
	
	protected MerryXmas() {
    	b0 = JCSystem.makeTransientByteArray((short) 258, JCSystem.CLEAR_ON_RESET);
        register();
    }

	public void process(APDU apdu) {
        if (selectingApplet()) {
            return;
        }

        byte[] buffer = apdu.getBuffer();

        if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x00)) {
            if (api == null) {
            	apiAID = JCSystem.lookupAID(serverAID, (short) 0, (byte) serverAID.length);
            	if (apiAID != null) {
						api = (KM101.T101OpenAPI) JCSystem.getAppletShareableInterfaceObject(apiAID, (byte) 0);
					if (api == null) {
						ISOException.throwIt(ISO7816.SW_APPLET_SELECT_FAILED);
					}
            	} else {
	            	ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
            	}
            }        
        } else if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x10)) {
            if (!initEnv(buffer)) {
            	ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc0));
            }
        } else if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x12)) {        	
        	byte[] title = {(byte) 0x4d, (byte) 0x45, (byte) 0x52, (byte) 0x52, (byte) 0x59, (byte) 0x58, (byte) 0x4d, (byte) 0x41, 
							(byte) 0x53};
							
        	byte[] greetData = {(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x2a, 
								(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, 
								(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x2f, (byte) 0x2e, 
								(byte) 0x5c, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, 
								(byte) 0x20, (byte) 0x4d, (byte) 0x58, (byte) 0x20, (byte) 0x20, (byte) 0x2f, (byte) 0x2e, (byte) 0x2e, 
								(byte) 0x27, (byte) 0x5c, (byte) 0x20, (byte) 0x20, (byte) 0x48, (byte) 0x4e, (byte) 0x20, (byte) 0x20, 
								(byte) 0x20, (byte) 0x32, (byte) 0x30, (byte) 0x20, (byte) 0x20, (byte) 0x2f, (byte) 0x27, (byte) 0x2e, 
								(byte) 0x27, (byte) 0x5c, (byte) 0x20, (byte) 0x20, (byte) 0x32, (byte) 0x30, (byte) 0x20, (byte) 0x20, 
								(byte) 0x20, (byte) 0x31, (byte) 0x39, (byte) 0x20, (byte) 0x2f, (byte) 0x2e, (byte) 0x27, (byte) 0x27, 
								(byte) 0x2e, (byte) 0x27, (byte) 0x5c, (byte) 0x20, (byte) 0x32, (byte) 0x30, (byte) 0x20, (byte) 0x20, 
								(byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x5e, (byte) 0x5e, (byte) 0x5b, (byte) 0x5f, 
								(byte) 0x5d, (byte) 0x5e, (byte) 0x5e, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20, (byte) 0x20};
			
        	if (uxRender((byte) 0x02, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, title, (short) 0, (short) title.length, greetData, (short) 0, 
						  (short) greetData.length, buffer) == (short) -1) {
	        	ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc0));
        	}        
		} else if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0x14)) {
			JCSystem.getAvailableMemory(sb, (short) 0, JCSystem.MEMORY_TYPE_PERSISTENT);
			shortToBytes(sb[0], b0, (short) 0);
			shortToBytes(sb[1], b0, (short) 2);
			JCSystem.getAvailableMemory(sb, (short) 0, JCSystem.MEMORY_TYPE_TRANSIENT_RESET);
			shortToBytes(sb[0], b0, (short) 4);
			shortToBytes(sb[1], b0, (short) 6);
			apdu.setOutgoing();
        	apdu.setOutgoingLength((short) 8);
        	apdu.sendBytesLong(b0, (short) 0, (short) 8);        
        } else if ((buffer[ISO7816.OFFSET_CLA] == (byte) 0xB0) && (buffer[ISO7816.OFFSET_INS] == (byte) 0xFF)) {
        	if (!destroyEnv()) {
				ISOException.throwIt(ISO7816.SW_WARNING_STATE_UNCHANGED);
        	}
        } else {
            ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }
    
    /*
     * Initialize Applet Object Container environment. 
     *
     * Each applet accessing API MUST have registration in the AOC container to allow management of secure sessions.
     * The AOC container allows 3 credential and 4 keys or generic objects to be stored in the AOC container. 
     *
     * The T101 domain will have a Virtual Filesystem for each AOC container and store highly sensitive credentials
     * and objects in the T101 domain. 
     *
     * The AOC container itself is also its own user and thus the container has a  unique container credential for 
     * performing AOC container management operations and access to the GUI Windowing session.
     */    
    public boolean initEnv(byte[] buffer) {
    	boolean isProceed = false;
	    if (api != null) {
	    	
	    	// Use APDU buffer to carry API perimeters across Open API's Shareable Interface
            sb[0] = (short) (6 + aocPin.length + appName.length);
            Util.arrayFillNonAtomic(buffer, (short) 0, (short) 256, (byte) 0x00);
            buffer[0] = api.CRED_CLASS_PIN;
            Util.arrayCopyNonAtomic(aocPin, (short) 0, buffer, (short) 1, (short) aocPin.length);
            Util.arrayCopyNonAtomic(appName, (short) 0, buffer, (short) (1 + aocPin.length), (short) appName.length);
            Util.arrayCopyNonAtomic(ets, (short) 0, buffer, (short) (1 + aocPin.length + appName.length), (short) 4);
            
            // Create Applet Object Container via Open API before having access to API
            isProceed = api.createAOCContainer(buffer[0], 
											  buffer, (short) 1, (short) aocPin.length, 
											  tries, 
											  buffer, (short) (1 + aocPin.length), (short) appName.length, 
											  buffer, (short) (1 + aocPin.length + appName.length));
            			
			// Enroll Admin
            if(isProceed) {
            	isProceed = enrollNewAdminUsers(buffer);
			}
			
			// Finalize Applet Object Container
			if (isProceed) {
				isProceed = finalizeContainer(buffer);
			}
			
			if (isProceed) {
				// Success message display on screen
				isProceed = uxRender(KM101.T101OpenAPI.UI_TYPE_TEXT, KM101.T101OpenAPI.NULL, KM101.T101OpenAPI.NULL, KM101.T101OpenAPI.NULL,KM101.T101OpenAPI.NULL, 
									 TEXT_SETUP_COMPLETE, (short) 5, (short) 5, TEXT_SETUP_COMPLETE, (short) 0, (short) TEXT_SETUP_COMPLETE.length, buffer);
			} else {
				// Fail message display on screen
				isProceed = uxRender(KM101.T101OpenAPI.UI_TYPE_TEXT, KM101.T101OpenAPI.NULL, KM101.T101OpenAPI.NULL, KM101.T101OpenAPI.NULL,KM101.T101OpenAPI.NULL, 
									 TEXT_SETUP_COMPLETE, (short) 5, (short) 5, TEXT_FAILED, (short) 0, (short) TEXT_FAILED.length, buffer);
			}
		}
		
		return isProceed;
    }
    
    /*
     * Destroy container and also access to API.
     */
    public boolean destroyEnv() {
	    if (api != null) {
		    api.destroyAOCContainer();
			return true;			
	    }
	    
	    return false;
    }
    
    /*
	 * GUI Windowing call.
	 *
	 * T101 presents the User Interface and embedded keypad as a unified Windowing system for security and ease of usability.
	 * Users will not have direct access to the keypad or screen as part of a security measure to ensure applets cannot affect
	 * or hijack each other's session via direct access.
	 *
	 * The Windowing Session is similar to the Java Swing JFrame construct which consists of a Title Bar on the top of the screen, 
	 * a status bar on the bottom of the screen and the Content Window. Although the Windowing system is designed with Java Swing
	 * as an inspiration, this is a security sensitive environment and thus security restrictions are applied to prevent applets
	 * with and without API access from hijacking the screen and keypad under normal operational environmental parameters.	  
	 *
	 * UI Windowing Types:
	 *  - User List Window: 
	 *     * Generates a list of users in the AOC container for selection. Useful for user management functionalities.
	 *     * UI_TYPE_T_USER_LIST = (byte) 0x01;
	 *
	 *  - Text Display Window: 
	 *     * Generates text and listens for users  OK or Cancel button press as feedback.
	 *     * UI_TYPE_TEXT = (byte) 0x02;
	 *
	 *  - QR Code Display Window: 
	 *     * Similar to Text Display Window but displays QR codes. Status bar is removed due to space constraint.
	 *     * UI_TYPE_QR = (byte) 0x03;
	 *
	 *  - Secure Input Window: 
	 *     * Secure Input capable of accepting plain text data, numerical numbers and hexadecimal inputs as a virtual keypad.
	 *     * Support for secret data input obfuscated with '*' symbol or plain data.
	 *     * Supports keyboard input type (QWERTY + ASCII symbols, digit inputs and a hexadecimal input keyboard).
	 *     * Allows display for a single line of optional text (16 characters) to describe the data entry operation.
	 *     * UI_TYPE_INPUT = (byte) 0x04;
	 *
	 *  - List Window: 
	 *     * Close looped list of 6 elements and open looped list with 6 elements displayed per session.
	 *     * Listens to Up, Down buttons for directional travel of cursor.
	 *     * Allows 1 element to be selected.
	 *     * Listen to OK or Cancel buttons for selection of element.
	 *     * UI_TYPE_LIST = (byte) 0x05; 
     */    
    public short uxRender(byte type, byte subMode, byte subMode1, byte subMode2, byte subMode3, byte[] title, short titleOffset, short titleLen,byte[] input, short inOffset, 
							short inLen, byte[] buffer) {
    	buffer[0] = type;
    	sb[1] = (short) 0;
    	sb[2] = (short) 0;
    	if (title != null && titleLen > 0) {
			Util.arrayCopyNonAtomic(title, titleOffset, buffer, (short) 1, titleLen);
			sb[1] = titleLen;
    	}
    	
    	if (input != null && inLen > 0) {
			Util.arrayCopyNonAtomic(input, inOffset, buffer, (short) (1 + sb[1]), inLen);
			sb[2] = inLen;
		}
    	
    	// Request API for UI Windowing Session
    	sb[0] = api.uiSession(buffer[0], 
							  subMode, 
							  subMode1, 
							  subMode2, 
							  subMode3,
							  buffer, (short) 1, sb[1],
							  buffer, (short) (1 + sb[1]), sb[2],
							  buffer, (short) (1 + sb[1] + sb[2]));
		if (sb[0] != -1) {
			// Copy authentication nonce
			Util.arrayCopyNonAtomic(buffer, (short) (1 + sb[1] + sb[2]), b0, (short) 0, (short) 8);
			
			// Authenticate nonce using AOC container's PIN since the UI Windowing falls under the authority of the container, not the normal or admin user.
			sb[0] = authContainer(aocPin, (short) 0, (short) aocPin.length, b0, (short) 0, buffer);
			if (sb[0] > -1) {
				return sb[0];
			} else {
				ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc2));
			}
		} else {
			ISOException.throwIt(Util.makeShort((byte) 0x6f, (byte) 0xc1));
		}
	    return (short) -1;
    }
    
    /*
     * HMAC-SHA256 nonce based authentication across Shareable Interface for activities.
     */
    public short authContainer(byte[] secret, short secOffset, short secLen, byte[] nonce, short nonceOffset, byte[] buffer) {
	    buffer[0] = MessageDigest.ALG_SHA_256;
	    Util.arrayCopyNonAtomic(secret, secOffset, buffer, (short) 1, secLen);
	    Util.arrayCopyNonAtomic(nonce, nonceOffset, buffer, (short) (1 + secLen), (short) 8);
	    
		api.cryptoHMAC(buffer[0], // hashType
					   buffer, (short) 1, secLen, // key 0001 0003
					   buffer, (short) (1 + secLen), (short) 8,  // nonce 0004 0008
					   buffer, (short) (9 + secLen), // ipad 000c 
					   buffer, (short) (73 + secLen), // opad 004c
					   buffer, (short) (137 + secLen), // secBuff 008c
					   buffer, (short) 201); // output 00c9
					   
		sb[0] = api.extendedRequest(buffer, (short) 201, (short) 32, buffer, (short) 0);
	    return sb[0];
    }
    
    /*
     * Finalize AOC container creation before allowing access to other API functions.
     */
    public boolean finalizeContainer(byte[] buffer) {
		if (api.finalizeNewContainer(buffer, (short) 0)) {
			Util.arrayCopyNonAtomic(buffer, (short) 0, b0, (short) 0, (short) 8);
			if (authContainer(aocPin, (short) 0, (short) aocPin.length, b0, (short) 0, buffer) == 1) {							
				return true;
			}
		}
		
		return false;
    }
    
    /*
     * AOC container's PIN must be used to enroll the first user as a container Admin user. Once the container 
     * creation has been finalized, the AOC's container PIN cannot be used to enroll anymore users. The Admin
     * has to take over for more user enrollment afterwards.
     */
    public boolean enrollNewAdminUsers(byte[] buffer) {
    	buffer[0] = KM101.T101OpenAPI.CRED_CLASS_PIN;
    	buffer[1] = KM101.T101OpenAPI.CRED_MGMT_FRONT_PANEL;
    	Util.arrayCopyNonAtomic(adminPin, (short) 0, buffer, (short) 2, (short) adminPin.length);
    	Util.arrayCopyNonAtomic(adminUser, (short) 0, buffer, (short) (2 + adminPin.length), (short) adminUser.length);	
    	Util.arrayCopyNonAtomic(ets, (short) 0, buffer, (short) (2 + adminPin.length + adminUser.length), (short) 4);
		if (api.newAOCUserCred(buffer[0], 
							   buffer, (short) 2, (short) adminPin.length, 
							   (short) 3, 
							   buffer, (short) (2 + adminPin.length), (short) adminUser.length,
						       buffer, (short) (2 + adminPin.length + adminUser.length), 
							   KM101.T101OpenAPI.NULL, null, (short) 0, (short) 0, 
							   KM101.T101OpenAPI.AUTH_INTERNAL,
							   buffer, (short) (6 + adminPin.length + adminUser.length))) {
			if (authContainer(aocPin, (short) 0, (short) aocPin.length, buffer, (short) (6 + adminPin.length + adminUser.length), buffer) == 1) {			
				return true;
			}
		}		
	    return false;
    }
    
    public static void shortToBytes(short s, byte[] b, short offset) {
        b[offset] = (byte) ((s >> 8) & 0xFF);
        b[(short) (offset + 1)] = (byte) (s & 0xFF);
    }
}