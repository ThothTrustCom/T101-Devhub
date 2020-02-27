package KM101;

import javacard.framework.Shareable;

public interface T101OpenAPI extends Shareable {
	
	public static final short MAX_OBJ_PER_CRED = (short) 4;
    public static final short MAX_GLOBAL = (short) 2;
    public static final short MAX_AOC = (short) 2;
    public static final short MAX_USERS_PER_OBJ = (short) 3;
    public static final short MAX_LIST_OBJ_CNT = (short) 10;
    public static final short MAX_KMAC_LEN = (short) 128;
    public static final short MAX_GEN_MAT_LEN = MAX_KMAC_LEN;
    public static final byte OBJ_TYPE_GENERIC = (byte) 0x01;
    public static final byte OBJ_TYPE_CRED = (byte) 0x02;
    public static final byte OBJ_TYPE_KEY = (byte) 0x03;
    public static final byte OBJ_FIELD_VER = (byte) 0x01;
    public static final byte OBJ_FIELD_TYPE = (byte) 0x02;
    public static final byte OBJ_FIELD_SUBTYPE_CLASS = (byte) 0x03;
    public static final byte OBJ_FIELD_SUBTYPE_TYPE = (byte) 0x04;
    public static final byte OBJ_FIELD_SN = (byte) 0x05;
    public static final byte OBJ_FIELD_CREATE = (byte) 0x06;
    public static final byte OBJ_FIELD_EXPIRE = (byte) 0x07;
    public static final byte OBJ_FIELD_ID = (byte) 0x08;
    public static final byte OBJ_FIELD_EXPORT = (byte) 0x09;
    public static final byte OBJ_FIELD_ACL = (byte) 0x0A;
    public static final byte OBJ_FIELD_MATERIAL_SECRET = (byte) 0x0B;
    public static final byte OBJ_FIELD_MATERIAL_PUBLIC = (byte) 0x0C;
    public static final byte OBJ_FIELD_ATTEST = (byte) 0x0D;
    public static final byte OBJ_FIELD_HANDLE = (byte) 0x0E;
    public static final byte OBJ_EXPIRED = (byte) 0x01;
    public static final byte OBJ_NOT_EXPIRED = (byte) 0x02;
    public static final byte OBJ_EXPIRY_UNDETERMINED = (byte) 0x03;
    public static final byte OBJ_PERM_EXPORT_ALLOW_FLAG = (byte) 0xE0;
    public static final byte OBJ_PERM_EXPORT_DENY_FLAG = (byte) 0xEF;
    public static final byte LOOKUP_AVAILABLE_AOC = (byte) 0x01;
    public static final byte LOOKUP_HAS_FREE_AOC = (byte) 0x02;
    public static final byte LOOKUP_AVAILABLE_CRED_BY_NAME = (byte) 0x03;
    public static final byte LOOKUP_AVAILABLE_CRED_BY_ID = (byte) 0x04;
    public static final byte LOOKUP_HAS_FREE_CRED = (byte) 0x05;
    public static final byte LOOKUP_HAS_FREE_OBJ = (byte) 0x06;    
    public static final byte LOOKUP_AVAILABLE_OBJ_BY_HANDLE = (byte) 0x07;
    public static final byte LOOKUP_LIST_OBJ = (byte) 0x08;
    public static final byte LOOKUP_COUNT_OBJ_AOC = (byte) 0x09;
    public static final byte LOOKUP_COUNT_OBJ_GLOBCRED = (byte) 0x0A;
    public static final byte LOOKUP_LIST_CRED = (byte) 0x0B;
    public static final byte KEY_CLASS_SYMMETRIC = (byte) 0x01;
    public static final byte KEY_CLASS_ASYMMETRIC = (byte) 0x02;
    public static final byte KEY_TYPE_AES = (byte) 0x11;
    public static final byte KEY_TYPE_DES = (byte) 0x12;
    public static final byte KEY_TYPE_CHACHA = (byte) 0x13;
    public static final byte KEY_TYPE_RSA = (byte) 0x21;
    public static final byte KEY_TYPE_DH = (byte) 0x22;
    public static final byte KEY_TYPE_ECC_P256R1 = (byte) 0x23;
    public static final byte KEY_TYPE_ECC_P384R1 = (byte) 0x24;
    public static final byte KEY_TYPE_ECC_P521R1 = (byte) 0x25;
    public static final byte KEY_TYPE_ECC_P256K1 = (byte) 0x26;
    public static final byte KEY_TYPE_KMAC = (byte) 0x51;
    public static final byte CRED_CLASS_PIN = (byte) 0x80;
    public static final byte CRED_CLASS_PWD = (byte) 0x40;
    public static final byte CRED_AOC_ADMIN_RESET_FLAG = (byte) 0x01;
    public static final byte CRED_PERM_ADMIN_FLAG = (byte) 0x01;    
    public static final byte CRED_FIELD_NAME = (byte) 0x01;
    public static final byte CRED_FIELD_IDPUBKEY = (byte) 0x02;
    public static final byte CRED_FIELD_SECRET = (byte) 0x03;
    public static final byte CRED_FIELD_EXPORT = (byte) 0x04;
    public static final byte CRED_FIELD_ACTIVE = (byte) 0x05;
    public static final byte CRED_FIELD_MANAGEMENT = (byte) 0x06;
    public static final byte CRED_FIELD_CREDID = (byte) 0x07;
    public static final byte CRED_FIELD_ADMIN = (byte) 0x08;
    public static final byte CRED_FIELD_SECRET_TYPE = (byte) 0x09;
    public static final byte CRED_FIELD_MAX_RETRIES = (byte) 0x0A;
    public static final byte CRED_FIELD_RETAIN_ORPHAN = (byte) 0x0B;
    public static final byte CRED_FIELD_CREATE = (byte) 0x0C;
    public static final byte CRED_FIELD_EXPIRE = (byte) 0x0D;
    public static final byte CRED_FIELD_ATTEST = (byte) 0x0E;
    public static final byte CRED_FIELD_OID = (byte) 0x0F;
    public static final byte CRED_FIELD_OBJCTR = (byte) 0x10;
    public static final byte CRED_MGMT_FRONT_PANEL = (byte) 0x01;
    public static final byte CRED_STAT_INACTIVE = (byte) 0x00;
    public static final byte CRED_STAT_INIT = (byte) 0x01;
    public static final byte CRED_STAT_ACTIVE = (byte) 0x02;
    public static final byte AOCS_NONE = (byte) 0x00;
    public static final byte AOCS_LOGIN_BEGIN = (byte) 0x01;
    public static final byte AOCS_READY = (byte) 0x05;
    public static final byte ACT_AOC_MGMT = (byte) 0x01;
    public static final byte ACT_USR_MGMT = (byte) 0x02;
    public static final byte ACT_OBJ_MGMT = (byte) 0x03;
    public static final byte ACT_OBJ_EXEC = (byte) 0x04;
    public static final byte ACT_OBJ_IMPORT = (byte) 0x05;
    public static final byte ACT_OBJ_EXPORT_PUBLIC = (byte) 0x06;
    public static final byte ACT_OBJ_EXPORT_PRIVATE = (byte) 0x07;
    public static final byte ACT_OBJ_FIND = (byte) 0x08;
    public static final byte ACT_OBJ_CREATE = (byte) 0x09;
    public static final byte ACT_OBJ_SIZE = (byte) 0x0A;
    public static final byte ACT_STE_AUTH = (byte) 0x01;
    public static final byte ACT_STE_CRYPT = (byte) 0x02;
    public static final byte ACT_STE_PROC = (byte) 0x03;
    public static final byte ACT_STATUS_BEGIN = (byte) 0x01;
    public static final byte ACT_STATUS_UPDATE = (byte) 0x02;
    public static final byte ACT_STATUS_FINAL = (byte) 0x03;
    public static final byte ACT_STATUS_CANCEL = (byte) 0x04;
    public static final byte ACT_STATUS_SUCCESS = (byte) 0x05;
    public static final byte ACT_STATUS_FAIL = (byte) 0x06;
    public static final byte CRYPT_LOAD = (byte) 0x01;
    public static final byte CRYPT_UPDATE = (byte) 0x02;
    public static final byte CRYPT_FINAL = (byte) 0x03;
    public static final byte CRYPT_RESET = (byte) 0x04;
    public static final byte CRYPT_KEYGEN = (byte) 0x05;
    public static final byte AUTH_FRONTPANEL = (byte) 0x01;
    public static final byte AUTH_INTERNAL = (byte) 0x02;
    public static final byte AUTH_MODE_USR_AUTH = (byte) 0x01;
    public static final byte AUTH_MODE_CONTAINER_AUTH = (byte) 0x02;
    public static final byte AUTH_MODE_STATE_AUTH = (byte) 0x03;
    public static final byte EXEC_COMPARE = (byte) 0x11;
    public static final byte EXEC_CRYPT_INTEGRITY_CREATION = (byte) 0x21;
    public static final byte EXEC_CRYPT_INTEGRITY_VERIFICATION = (byte) 0x22;
    public static final byte EXEC_CRYPT_CONTENT_PROTECT = (byte) 0x23;
    public static final byte EXEC_CRYPT_CONTENT_EXTRACT = (byte) 0x24;
    public static final byte ATTEST_LEVEL_ROOT_AUTH = (byte) 0x00;
    public static final byte ATTEST_LEVEL_INTERMEDIATE_AUTH = (byte) 0x01;
    public static final byte ATTEST_LEVEL_KM_AUTH = (byte) 0x02;
    public static final byte ATTEST_LEVEL_GLOBUSER_AUTH = (byte) 0x03;
    public static final byte ATTEST_LEVEL_AOC_AUTH = (byte) 0x04;
    public static final byte ATTEST_LEVEL_OBJECT = (byte) 0x05;
    public static final byte ACL_ALLOW_READ = (byte) 0x02;
    public static final byte ACL_ALLOW_EDIT = (byte) 0x01;
    public static final byte ACL_ALLOW_EXEC = (byte) 0x00;
    public static final byte UI_TYPE_T_USER_LIST = (byte) 0x01;
    public static final byte UI_TYPE_TEXT = (byte) 0x02;
    public static final byte UI_TYPE_QR = (byte) 0x03;
    public static final byte UI_TYPE_INPUT = (byte) 0x04;
    public static final byte UI_TYPE_LIST = (byte) 0x05;
    public static final byte NULL = ACL_ALLOW_EXEC;
		
	// OK
	public boolean createAOCContainer(byte secretType, byte[] secret, short secretOffset, short secretLen, short maxRetry, byte[] name, short appNameOffset, 
									  short appNameLen, byte[] expireTS, short expOffset);
	
	// OK
	public boolean finalizeNewContainer(byte[] output, short outOffset);
	
	// OK
	public boolean destroyAOCContainer();
	
	// OK
	public boolean manageAOCContainer(byte fieldType, byte[] input, short offset, short len, byte[] output, short outOffset);
	
	// OK
	public short getAOCInfo(byte targetProfileFieldSearch, byte[] output, short outOffset);
									  
	// OK
	public boolean newAOCUserCred(byte secretType, byte[] secret, short secOffset, short secLen, short maxRetry, byte[] username, short usernameOffset, short usernameLen, 
								  byte[] expireTS, short etsOffset, byte credFieldType, byte[] credInput, short cOffset, short cLen, byte authMethod, byte[] output, 
								  short outOffset);
	
	// OK
	public boolean manageUserCred(byte fieldType, byte[] input, short offset, short len, byte[] output, short outOffset, byte credFieldType, byte[] credInput, short cOffset, 
								  short cLen, byte authMethod);
	
	// OK
	public boolean resetAOCUserCred(byte[] input, short offset, short len, byte[] username, short usernameOffset, short usernameLen, byte credFieldType, byte[] credInput, 
									short cOffset, short cLen, byte authMethod, byte[] output, short outOffset);
	
	// OK
	public short listAOCUsers(byte credFieldType, byte[] credInput, short cOffset, short cLen,  byte[] output, short outOffset, byte authMethod);
	
 	// OK
	public short getUserInfo(byte credFieldType, byte[] credInput, short cOffset, short cLen, byte targetFieldType, byte[] targetInput, short targetOffset, short targetLen, 
							 byte targetProfileFieldSearch, byte[] output, short outOffset, byte authMethod);
	
	// OK
	public boolean importLocalGlobalUserCredToAOC(byte credFieldType, byte[] credInput, short cOffset, short cLen, byte[] input, short offset, short len, byte[] output, 
												  short outOffset, byte authMethod);
	
	// OK
	public boolean promoteAOCUserCred(byte credFieldType, byte[] credInput, short cOffset, short cLen, byte fieldType, byte[] input, short offset, short len, 
									  byte[] output, short outOffset, byte authMethod);
	
	// OK
	public boolean deleteUserCred(byte credFieldType, byte[] credInput, short cOffset, short cLen, byte fieldType, byte[] input, short offset, short len, 
								  byte[] output, short outOffset, byte authMethod);
	// OK
	public boolean newObject(byte objectType, byte[] objectName, short nameOffset, short nameLen, byte[] objectMat1, short om1Offset, short om1Len, 
							 byte[] objectMat2, short om2Offset, short om2Len, byte export, byte acl, byte extendedObjectClass, byte extendedObjectType, 
							 boolean requireAttestation, byte[] expiryTS, short expiryOffset, byte credFieldType, byte[] credInput, short cOffset, short cLen, 
							 byte[] output, short outOffset, byte authMethod);
	
	// OK
	public short manageObject(byte[] objectName, short nameOffset, short nameLen, byte objectFieldType, byte[] input, short offset, short len, byte[] output, 
							  short outOffset, boolean isSecret, byte credFieldType, byte[] credInput, short cOffset, short cLen, byte authMethod);			

	// OK
	public short listObjects(byte[] output, short outOffset, byte credFieldType, byte[] credInput, short cOffset, short cLen, byte authMethod);
				
	// OK
	public short getObjectInfo(byte[] input, short offset, short len, byte field, byte[] output, short outOffset, byte credFieldType, byte[] credInput, short credOffset, 
							   short credLen, byte authMethod);

	// OK
	public short getObjectMaterial(byte[] input, short offset, short len, boolean isPublic, byte[] output, short outOffset, byte credFieldType, byte[] credInput, 
								   short credOffset, short credLen, byte authMethod);

	// OK
	public short executeObject(byte execMethod, byte subOpMode1, byte subOpMode2, boolean useBufferedData, byte[] objectName, short nameOffset, short nameLen, byte[] input, 
							   short offset, short len, byte[] output, short outOffset, byte credFieldType, byte[] credInput, short credOffset, short credLen, byte authMethod);						

	// OK
	public boolean deleteObject(byte[] input, short offset, short len, byte[] output, short outOffset, byte credFieldType, byte[] credInput, short credOffset, short credLen, 
								byte authMethod);
		
	// OK
	public short extendedRequest(byte[] input, short offset, short len, byte[] output, short outOffset);
	
	// OK
	public short importExportObject(boolean isCredential, byte action, byte subAction, byte[] input, short offset, short len, byte[] secInput, 
									short secOffset, short secLen, byte[] sec1Input, short sec1Offset, short sec1Len, byte[] output, short outOffset, 
									byte credFieldType, byte[] credInput, short cOffset, short cLen, byte authMethod);
	
	// OK
	public short cryptoChaCha20(byte[] key, short keyOffset, byte[] nonce, short nonceOffset, byte[] counter, short ctrOffset, byte[] input, short inOffset, short length, 
								byte[] output, short outOffset);
	
	// OK
	public short cryptoHMAC(byte hashType, byte[] key, short keyOffset, short keyLength, byte[] msg, short mOff, short mLen, byte[] ipad, 
							short offIPad, byte[] opad, short offOPad, byte[] secB, short offSecB, byte[] oMsg, short outOff);
	
	// OK
	public short uiSession(byte uiType, byte uiSubMode, byte uiSubMode1, byte uiSubMode2, byte uiSubMode3, byte[] title, short titleOffset, short titleLen, 
						   byte[] input, short inOffset, short inLen, byte[] output, short outOffset);
	
	// OK
	public boolean getTime(byte[] output, short offset);
	
	// OK
	public boolean isSessionBusy();
	
	// OK
	public void resetSession();
	
	// OK
	public short bufferData(boolean isWrite, short newMaxLen, byte[] input, short offset, short len, short buffStartOff, byte[] output, short outOffset);
	
	// OK
	public short getBufferDataLength();
	
	// OK
	public short clearBuffer(byte[] output, short outOffset);
	
	// OK
	public short hexStrToBin(byte[] input, short offset, byte[] output, short outOffset, short len);
}
