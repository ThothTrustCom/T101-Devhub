package KM101;

import javacard.framework.Shareable;

public interface T101OpenAPI extends Shareable {

    /** Maximum Application Object Containers. */
    public static final short MAX_AOC = (short) 5;
    
    /** Maximum HMAC key length in bytes. */
    public static final short MAX_KMAC_LEN = (short) 128; 

    /** Maximum all geeric object material length in bytes. */
    public static final short MAX_GEN_MAT_LEN = MAX_KMAC_LEN; 
    
    /** Generic object type. */
    public static final byte OBJ_TYPE_GENERIC = (byte) 0x01; 
    
    /** Credential object type. */
    public static final byte OBJ_TYPE_CRED = (byte) 0x02; 

    /** Key object type. */
    public static final byte OBJ_TYPE_KEY = (byte) 0x03; 

    /** Version field. */
    public static final byte OBJ_FIELD_VER = (byte) 0x01; 

    /** Object type field. */
    public static final byte OBJ_FIELD_TYPE = (byte) 0x02; 

    /** Object subtype for key class field. */
    public static final byte OBJ_FIELD_SUBTYPE_CLASS = (byte) 0x03; 

    /** Object subtype for key type field. */
    public static final byte OBJ_FIELD_SUBTYPE_TYPE = (byte) 0x04; 

    /**  Object subtype for serial number field. */
    public static final byte OBJ_FIELD_SN = (byte) 0x05; 

    /** Object creation timestamp field. */
    public static final byte OBJ_FIELD_CREATE = (byte) 0x06; 

    /** Object expiry timestamp field. */
    public static final byte OBJ_FIELD_EXPIRE = (byte) 0x07;

    /** Object ID field. */
    public static final byte OBJ_FIELD_ID = (byte) 0x08;

    /** Object export field. */
    public static final byte OBJ_FIELD_EXPORT = (byte) 0x09;

    /** Object ACL field. */
    public static final byte OBJ_FIELD_ACL = (byte) 0x0A;

    /** Object secret material field. */
    public static final byte OBJ_FIELD_MATERIAL_SECRET = (byte) 0x0B;

    /** Object public material field. */
    public static final byte OBJ_FIELD_MATERIAL_PUBLIC = (byte) 0x0C;

    /** Object attestation field. */
    public static final byte OBJ_FIELD_ATTEST = (byte) 0x0D;

    /** Object handle/name field. */
    public static final byte OBJ_FIELD_HANDLE = (byte) 0x0E;

    /** Check object expiry field. */
    public static final byte OBJ_EXPIRED = (byte) 0x01;

    /** Check object not expired field. */
    public static final byte OBJ_NOT_EXPIRED = (byte) 0x02;

    /** Check object expiry undetermined field. */
    public static final byte OBJ_EXPIRY_UNDETERMINED = (byte) 0x03;

    /** Export allow permission field. */
    public static final byte OBJ_PERM_EXPORT_ALLOW_FLAG = (byte) 0xE0;

    /** Export deny permission field. */
    public static final byte OBJ_PERM_EXPORT_DENY_FLAG = (byte) 0xEF;

    /** Lookup existing AOC field. */
    public static final byte LOOKUP_AVAILABLE_AOC = (byte) 0x01;

    /** Lookup for free AOC field. */
    public static final byte LOOKUP_HAS_FREE_AOC = (byte) 0x02;

    /** Lookup available GOC by name field. */
    public static final byte LOOKUP_AVAILABLE_CRED_BY_NAME = (byte) 0x03;

    /** Lookup available GOC by ID field. */
    public static final byte LOOKUP_AVAILABLE_CRED_BY_ID = (byte) 0x04;

    /** Lookup for free GOC field. */
    public static final byte LOOKUP_HAS_FREE_CRED = (byte) 0x05;

    /** Lookup for free object field. */
    public static final byte LOOKUP_HAS_FREE_OBJ = (byte) 0x06;

    /** Lookup available object by name field. */
    public static final byte LOOKUP_AVAILABLE_OBJ_BY_HANDLE = (byte) 0x07;

    /** Lookup list object field.Maximum Application Object Containers. */
    public static final byte LOOKUP_LIST_OBJ = (byte) 0x08;

    /** Lookup count object field. */
    public static final byte LOOKUP_COUNT_OBJ_AOC = (byte) 0x09;
    
    public static final byte LOOKUP_COUNT_OBJ_GLOBCRED = (byte) 0x0A;

    /** Lookup list credentials field. */
    public static final byte LOOKUP_LIST_CRED = (byte) 0x0B;

    /** Symmetric key object field. */
    public static final byte KEY_CLASS_SYMMETRIC = (byte) 0x01;

    /** Asymmetric key object field. */
    public static final byte KEY_CLASS_ASYMMETRIC = (byte) 0x02;

    /** AES key object field. */
    public static final byte KEY_TYPE_AES = (byte) 0x11;

    /** DES and 3DES key object field. */
    public static final byte KEY_TYPE_DES = (byte) 0x12;

    /** ChaCha20 key object field. */
    public static final byte KEY_TYPE_CHACHA = (byte) 0x13;

    /** RSA key object field. */
    public static final byte KEY_TYPE_RSA = (byte) 0x21;

    /** Diffie-Hellman key object field. */
    public static final byte KEY_TYPE_DH = (byte) 0x22;

    /** ECC-P256R1 key object field. */
    public static final byte KEY_TYPE_ECC_P256R1 = (byte) 0x23;

    /** ECC-P384R1 key object field. */
    public static final byte KEY_TYPE_ECC_P384R1 = (byte) 0x24;

    /** ECC-P521R1 key object field. */
    public static final byte KEY_TYPE_ECC_P521R1 = (byte) 0x25;

    /** ECC-P256K1 key object field. */
    public static final byte KEY_TYPE_ECC_P256K1 = (byte) 0x26;

    /** HMAC and Key-based MAC key object field. */
    public static final byte KEY_TYPE_KMAC = (byte) 0x51;

    /** PIN credential field. */
    public static final byte CRED_CLASS_PIN = (byte) 0x80;

    /** Password credential field. */
    public static final byte CRED_CLASS_PWD = (byte) 0x40;

    public static final byte CRED_AOC_ADMIN_RESET_FLAG = (byte) 0x01;

    public static final byte CRED_PERM_ADMIN_FLAG = (byte) 0x01;

    /** Credential name field. */
    public static final byte CRED_FIELD_NAME = (byte) 0x01;

    /** Credential ID Public Key field. */
    public static final byte CRED_FIELD_IDPUBKEY = (byte) 0x02;
    
    public static final byte CRED_FIELD_SECRET = (byte) 0x03;

    /** Credential export field. */
    public static final byte CRED_FIELD_EXPORT = (byte) 0x04;

    /** Credential active field. */
    public static final byte CRED_FIELD_ACTIVE = (byte) 0x05;

    /** Credential Front Panel management field. */
    public static final byte CRED_FIELD_MANAGEMENT = (byte) 0x06;

    public static final byte CRED_FIELD_CREDID = (byte) 0x07;

    /** Credential AOC administration field. */
    public static final byte CRED_FIELD_ADMIN = (byte) 0x08;

    public static final byte CRED_FIELD_SECRET_TYPE = (byte) 0x09;

    /** Credential authentication maximum retries field. */
    public static final byte CRED_FIELD_MAX_RETRIES = (byte) 0x0A;

    public static final byte CRED_FIELD_RETAIN_ORPHAN = (byte) 0x0B;

    /** Credential creation timestamp field. */
    public static final byte CRED_FIELD_CREATE = (byte) 0x0C;

    /** Credential expiry timestamp field. */
    public static final byte CRED_FIELD_EXPIRE = (byte) 0x0D;

    /** Credential creation attestation field. */
    public static final byte CRED_FIELD_ATTEST = (byte) 0x0E;

    /** Credential Object ID field. */
    public static final byte CRED_FIELD_OID = (byte) 0x0F;

    /** Credential Object Counter field. */
    public static final byte CRED_FIELD_OBJCTR = (byte) 0x10;

    /** Allow credential Front Panel management field. */
    public static final byte CRED_MGMT_FRONT_PANEL = (byte) 0x01;

    /** Credential inactive flag field. */
    public static final byte CRED_STAT_INACTIVE = (byte) 0x00;

    /** Credential init flag field. */
    public static final byte CRED_STAT_INIT = (byte) 0x01;

    /** Credential active flag field. */
    public static final byte CRED_STAT_ACTIVE = (byte) 0x02;

    public static final byte AOCS_NONE = (byte) 0x00;

    public static final byte AOCS_LOGIN_BEGIN = (byte) 0x01;

    public static final byte AOCS_READY = (byte) 0x05;

    /** AOC management action flag field. */
    public static final byte ACT_AOC_MGMT = (byte) 0x01;

    /** User management action flag field. */
    public static final byte ACT_USR_MGMT = (byte) 0x02;

    /** Object management action flag field. */
    public static final byte ACT_OBJ_MGMT = (byte) 0x03;

    /** Object execution action flag field. */
    public static final byte ACT_OBJ_EXEC = (byte) 0x04;

    /** Object import action flag field. */
    public static final byte ACT_OBJ_IMPORT = (byte) 0x05;

    /** Object public export action flag field. */
    public static final byte ACT_OBJ_EXPORT_PUBLIC = (byte) 0x06;

    /** Object private export action flag field. */
    public static final byte ACT_OBJ_EXPORT_PRIVATE = (byte) 0x07;

    /** Finds an object by its attributes. */
    public static final byte ACT_OBJ_FIND = (byte) 0x08;

    /** Object create action flag field. */
    public static final byte ACT_OBJ_CREATE = (byte) 0x09;

    /** Object size action flag field. */
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

    /** Object crypto ops doLoad field. */
    public static final byte CRYPT_LOAD = (byte) 0x01;

    /** Object crypto ops doUpdate field. */
    public static final byte CRYPT_UPDATE = (byte) 0x02;

    /** Object crypto ops doFinal field. */
    public static final byte CRYPT_FINAL = (byte) 0x03;

    /** Object crypto ops doReset field. */
    public static final byte CRYPT_RESET = (byte) 0x04;

    /** Object crypto ops generate new key field. */
    public static final byte CRYPT_KEYGEN = (byte) 0x05;

    /** Authenticate with Front Panel flag field. */
    public static final byte AUTH_FRONTPANEL = (byte) 0x01;

    /** Authenticate with Internal Authentication flag field. */
    public static final byte AUTH_INTERNAL = (byte) 0x02;

    public static final byte AUTH_MODE_USR_AUTH = (byte) 0x01;

    public static final byte AUTH_MODE_CONTAINER_AUTH = (byte) 0x02;

    public static final byte AUTH_MODE_STATE_AUTH = (byte) 0x03;

    public static final byte EXEC_COMPARE = (byte) 0x11;

    /** Object execution using cryptographic integrity creation (HMAC creation or digital signing) action flag field. */
    public static final byte EXEC_CRYPT_INTEGRITY_CREATION = (byte) 0x21;

    /** Object execution using cryptographic integrity verification (HMAC verification or digital verification) action flag field. */
    public static final byte EXEC_CRYPT_INTEGRITY_VERIFICATION = (byte) 0x22;

    /** Object execution using cryptographic content protection (encryption or Key Establishment with ECDH) action flag field. */
    public static final byte EXEC_CRYPT_CONTENT_PROTECT = (byte) 0x23;

    /** Object execution using cryptographic content extraction (decryption) action flag field. */
    public static final byte EXEC_CRYPT_CONTENT_EXTRACT = (byte) 0x24;

    /** Attestation at Root Auth flag field. */
    public static final byte ATTEST_LEVEL_ROOT_AUTH = (byte) 0x00;

    /** Attestation at Intermediate Auth flag field. */
    public static final byte ATTEST_LEVEL_INTERMEDIATE_AUTH = (byte) 0x01;

    /** Attestation at KM Auth flag field. */
    public static final byte ATTEST_LEVEL_KM_AUTH = (byte) 0x02;

    /** Attestation at Global User Container Auth flag field. */
    public static final byte ATTEST_LEVEL_GLOBUSER_AUTH = (byte) 0x03;

    /** Attestation at AOC Auth flag field. */
    public static final byte ATTEST_LEVEL_AOC_AUTH = (byte) 0x04;

    /** Attestation at Object Auth flag field. */
    public static final byte ATTEST_LEVEL_OBJECT = (byte) 0x05;

    /** ACL permission to allow reading of an object with export permission taking precedence. */
    public static final byte ACL_ALLOW_READ = (byte) 0x02;

    /** ACL permission to allow editing of an object. */
    public static final byte ACL_ALLOW_EDIT = (byte) 0x01;

    /** ACL permission to allow execution of an object. */
    public static final byte ACL_ALLOW_EXEC = (byte) 0x00;

    /** UI Text flag field. */
    public static final byte UI_TYPE_TEXT = (byte) 0x02;

    /** UI QR flag field. */
    public static final byte UI_TYPE_QR = (byte) 0x03;

    /** UI Input textpad flag field. */
    public static final byte UI_TYPE_INPUT = (byte) 0x04;

    /** UI List flag field. */
    public static final byte UI_TYPE_LIST = (byte) 0x05;

    /** UI_TYPE_INPUT GUI session flag to support upper case alphabet keypad. XOR with other FLAG_VKEY_KEYPAD_* types to have multiple types of keypad for input during the UI_TYPE_INPUT GUI session. */
    public static final byte FLAG_VKEY_KEYPAD_CAPS_ALPHA = (byte) 0x01;

    /** UI_TYPE_INPUT GUI session flag to support lower case alphabet keypad. XOR with other FLAG_VKEY_KEYPAD_* types to have multiple types of keypad for input during the UI_TYPE_INPUT GUI session. */
    public static final byte FLAG_VKEY_KEYPAD_LOWR_ALPHA = (byte) 0x02;

    /** UI_TYPE_INPUT GUI session flag to support numerical keypad. XOR with other FLAG_VKEY_KEYPAD_* types to have multiple types of keypad for input during the UI_TYPE_INPUT GUI session. */
    public static final byte FLAG_VKEY_KEYPAD_NUMERIC = (byte) 0x04;

    /** UI_TYPE_INPUT GUI session flag to support ASCII printable symbols keypad. XOR with other FLAG_VKEY_KEYPAD_* types to have multiple types of keypad for input during the UI_TYPE_INPUT GUI session. */
    public static final byte FLAG_VKEY_KEYPAD_SPECIAL = (byte) 0x08;

    /** UI_TYPE_INPUT GUI session flag to set the upper case alphabet keypad as the initially displayed keypad. */
    public static final byte FLAG_VKEY_KEYPAD_PREF_CAPS_ALPHA = (byte) 0x01;

    /** UI_TYPE_INPUT GUI session flag to set the lower case alphabet keypad as the initially displayed keypad. */
    public static final byte FLAG_VKEY_KEYPAD_PREF_LOWR_ALPHA = (byte) 0x02;

    /** UI_TYPE_INPUT GUI session flag to set the numerical keypad as the initially displayed keypad. */
    public static final byte FLAG_VKEY_KEYPAD_PREF_NUMERIC = (byte) 0x03;

    /** UI_TYPE_INPUT GUI session flag to set the ASCII printable symbols keypad as the initially displayed keypad. */
    public static final byte FLAG_VKEY_KEYPAD_PREF_SPECIAL = (byte) 0x04;

    /** NULL flag (0x00). */
    public static final byte NULL = ACL_ALLOW_EXEC;

    /** 
     * Creates an Applet Object Container (AOC).
     * 
     * @param secretType the secret type to be used for digital signing challenge-response protocol between the KeyManager and client applet.
     * @param secret the buffer containing the secret data used for digital signing challenge-response protocol between the KeyManager and client applet.
     * @param secretOffset the offset within secret to start.
     * @param secretLen the length of the secret data.
     * @param maxRetry the maximum consecutive invalid challenge-response authentication counts before the AOC container becomes locked.
     * @param name the buffer containing the AOC container's unique application name.
     * @param appNameOffset the offset within name to start.
     * @param appNameLen the length of the AOC container's unique application name.
     * @param expireTS the buffer containing the expiry timestamp of the AOC container.
     * @param expOffset the offset within the expireTS to start.
     * @return true if the creation of an AOC container has been successfully called.
     */
    public boolean createAOCContainer(byte secretType, byte[] secret, short secretOffset, short secretLen,
            short maxRetry, byte[] name, short appNameOffset, short appNameLen, byte[] expireTS, short expOffset);

    /** 
     * Finalize a newly created Applet Object Container.
     * 
     * @param output containing the 8-byte challenge for the applet's AOC PIN/Key to sign using HMAC-SHA256 algorithm for this activity.
     * @param outOffset offset within output to start.
     * @return true if an AOC container creation has successfully been created, initialized and made ready.
     */
    public boolean finalizeNewContainer(byte[] output, short outOffset);

    /** 
     * Destroys AOC container.
     * <br><br>
     * The caller must be the AOC container owning applet.
     * 
     * @return true if an AOC container has successfully been destroyed.
     */
    public boolean destroyAOCContainer();

    /**  
     * Manages AOC container.
     * <br><br>
     * The caller must be the AOC container owning applet.
     * 
     * @param fieldType the field type to edit and manage for the AOC container.
     * @param input the input data for managing the AOC container.
     * @param offset the offset within input to start.
     * @param len the length of input data for managing the AOC container.
     * @param output containing the 8-byte challenge for the applet's AOC PIN/Key to sign using HMAC-SHA256 algorithm for this activity.
     * @param outOffset offset within output to start.
     * @return true if an AOC conrainer management function has been successfully performed.
     */
    public boolean manageAOCContainer(byte fieldType, byte[] input, short offset, short len, byte[] output,
            short outOffset);

    /** 
     * Get AOC public information.
     * <br><br>
     * The caller must be the AOC container owning applet.
     * 
     * @param targetProfileFieldSearch the field type to search for public AOC information.
     * @param output containing the returned result of the AOC container enquiry.
     * @param outOffset offset within output to start.
     * @return the length of result returned in the output buffer.
     */
    public short getAOCInfo(byte targetProfileFieldSearch, byte[] output, short outOffset);

    /**  
     * Extending request of an AUTH_INTERNAL authenticated call to a function requiring authentication.
     * <br><br>
     * The caller must be the AOC container owning applet.
     * <br><br>
     * The <i><code>extendedRequest</code></i> command is to be called subsequenyl after the following API commands are called first:
     * <ul>
     *  <li>finalizeNewContainer</li>
     *  <li>manageAOCContainer</li>
     *  <li>uiSession</li>
     *  <li>setMainMenuSession</li>
     *  <li>resetMainMenuSession</li>
     * </ul>
     * <br><br>
     * <table border="1" width="100%">
     *  <caption><i>Output results for finalizeNewContainer, manageAOCContainer, setMainMenuSession and resetMainMenuSession methods</i></caption>
     *  <thead>
     *      <tr>
     *          <th width="12%">Output Length</th>
     *          <th>Output Parameter Description</th>
     *      </tr>
     *  </thead>
     *  <tbody>
     *      <tr>
     *          <td>1 (Success)</td>
     *          <td>Content has no significance.</td>
     *      </tr>
     *      <tr>
     *          <td>0 (Fail)</td>
     *          <td>Content has no significance.</td>
     *      </tr>
     *      <tr>
     *          <td>-1 (Authentication Failure)</td>
     *          <td>Content has no significance. It may reflect an invalid Session Status where the current executing job is not assigned to your applet or your applet is not registered as an AOC applet.</td>
     *      </tr>     
     *  </tbody>
     * </table>
     * <br><br>
     * <table border="1" width="100%">
     *  <caption><i>Output results for uiSession different UI types</i></caption>
     *  <thead>
     *      <tr>
     *          <th width="12%">UI Type</th>
     *          <th>Output Length</th>
     *          <th>Output Parameter Description</th>
     *      </tr>
     *  </thead>
     *  <tbody>
     *      <tr>
     *          <td>Text Display Window</td>
     *          <td>0 (C button pressed)<br>1 (OK button pressed)<br>2 (Timeout without key input)<br>-1 (Invalid parameters. It may reflect an invalid Session Status where the current executing job is not assigned to your applet or your applet is not registered as an AOC applet.)</td>
     *          <td>Content has no significance.</td>
     *      </tr>
     *      <tr>
     *          <td>QR Code Display Window</td>
     *          <td>0 (C button pressed)<br>1 (OK button pressed)<br>2 (Timeout without key input)<br>-1 (Invalid parameters. It may reflect an invalid Session Status where the current executing job is not assigned to your applet or your applet is not registered as an AOC applet.)</td>
     *          <td>Content has no significance.</td>
     *      </tr>
     *      <tr>
     *          <td>Input Entry Display Window</td>
     *          <td>>= 0 && <= uiSubMode4 specified max input length.<br>-1 (Invalid parameters. It may reflect an invalid Session Status where the current executing job is not assigned to your applet or your applet is not registered as an AOC applet.)</td>
     *          <td>Output contains the ASCII formatted text output that the user have keyed into the Input Entry keypad window.</td>
     *      </tr>
     *      <tr>
     *          <td>List Selection Display Window</td>
     *          <td>2 (Length of list selected item result)<br>-1 (Invalid parameters. It may reflect an invalid Session Status where the current executing job is not assigned to your applet or your applet is not registered as an AOC applet.)</td>
     *          <td>First byte represents the type of selection status. The second byte represents the item index of the selected item.
     *              <br><br>
     *              <table border="1" width="100%">
     *                  <caption><i>First byte item selection status</i></caption>
     *                  <thead>
     *                      <tr>
     *                          <th width="15%">Selection Status</th>
     *                          <th>Selection Description</th>
     *                      </tr>
     *                  </thead>
     *                  <tbody>
     *                      <tr><td width="15%">(byte) 0x00</td><td>Activity Timeout. Nothing selected.</td></tr>
     *                      <tr><td width="15%">(byte) 0x01</td><td>Item selected. Selected item index is in the second byte. Index 0 (1st item) to 5 (6th item)</td></tr>
     *                      <tr><td width="15%">(byte) 0x02</td><td>Activity Cancelled. Nothing selected.</td></tr>
     *                  </tbody>
     *              </table>
     *              <br>
     *          </td>
     *      </tr>
     *  </tbody>
     * </table>
     * <br>
     * 
     * @param input the input buffer containing the digital signature response using HMAC-SHA256 on the 8-byte activity challenge.
     * @param offset offset within input to start.
     * @param len length of the digital signature response data.
     * @param output the output buffer containing the returned response from the executing target activity.
     * @param outOffset offset within outOffset to start.
     * @return the lenght of returned response in the output buffer.
     */
    public short extendedRequest(byte[] input, short offset, short len, byte[] output, short outOffset);

    /** 
     * Cryptographic assistant function for one-shot ChaCha256 calculation. KeyManager does not store any data after this method has completed.
     * <br><br>
     * Any applet with access to the T101OpenAPI may utilize this function without authentication required.
     * <br><br>
     * End user may implement their own ChaCha256 function or use this ChaCha256 crypto-assistant function for cryptographic operations and are 
     * advised to actively zeroize the buffers after each use.
     * 
     * @param key the buffer containing the ChaCha256 key.
     * @param keyOffset the offset within key to start.
     * @param nonce the buffer containing the ChaCha256 nonce.
     * @param nonceOffset the offset within ChaCha256 to start.
     * @param counter the buffer containing the ChaCha256 counter.
     * @param ctrOffset the offset within counter to start.
     * @param input the buffer containing the plaintext or ciphertext for ChaCha256 function to process.
     * @param inOffset the offset within input to start.
     * @param length the length of the input buffer data.
     * @param output the output buffer containing the returned response from the ChaCha256 function.
     * @param outOffset the offset within output to start.
     * @return the length of returned result in the output buffer.
     */
    public short cryptoChaCha20(byte[] key, short keyOffset, byte[] nonce, short nonceOffset, byte[] counter,
            short ctrOffset, byte[] input, short inOffset, short length, byte[] output, short outOffset);

    /** 
     * Cryptographic assistant function for one-shot HMAC calculation. KeyManager does not store any data after this method has completed.
     * <br><br>
     * Any applet with access to the T101OpenAPI may utilize this function without authentication required.
     * <br><br>
     * End user may implement their own HMAC function or use this HMAC crypto-assistant function for cryptographic operations and are 
     * advised to actively zeroize the buffers after each use.
     * 
     * @param hashType the MessageDigest hash type for HMAC function.
     * @param key the buffer containing the HMAC key data.
     * @param keyOffset the offset within key to start.
     * @param keyLength the length of the HMAC key data.
     * @param msg the buffer containing the data for HMAC computation.
     * @param mOff the offset within msg to start.
     * @param mLen the length of the msg data.
     * @param ipad the ipad buffer for computation.
     * @param offIPad the offset within ipad to start.
     * @param opad the opad buffer for computation.
     * @param offOPad the offset within opad to start.
     * @param secB the intermediate computation buffer.
     * @param offSecB the offset within secB to start.
     * @param oMsg the output buffer containing the returned response from the HMAC function.
     * @param outOff the offset within oMsg to start.
     * @return the length of returned result in the output buffer.
     */
    public short cryptoHMAC(byte hashType, byte[] key, short keyOffset, short keyLength, byte[] msg, short mOff,
            short mLen, byte[] ipad, short offIPad, byte[] opad, short offOPad, byte[] secB, short offSecB, byte[] oMsg,
            short outOff);

    /** 
     * Executes a GUI Session.
     * <br><br>
     * The caller must be the AOC container owning applet.
     * <br><br>
     * The following steps should be taken when trying to render a GUI session using uiSession() method.
     * <ol>
     *  <li> Call the uiSession() with appropriate parameters. An 8-byte challenge will be used in the output buffer.
     *  <li> Calling applet will be required to use the aocPIN to sign via HMAC-SHA256 the 8-byte challenge.
     *  <li> Calling applet will call the extendedRequest() method while setting the HMAC signature as the input buffer.
     *  <li> The output buffer in the extendedRequest() will return the result of executing the uiSession() call.
     * </ol>
     * <br>
     * <table border="1">
     *  <caption><i>GUI window types and parameters</i></caption>
     *  <thead>
     *      <tr>
     *          <th>UI Type</th>
     *          <th>Constants</th>
     *          <th>Description</th>
     *          <th>uiSubMode</th>
     *          <th>uiSubMode1</th>
     *          <th>uiSubMode2</th>
     *          <th>uiSubMode3</th>
     *          <th>uiSubMode4</th>
     *      </tr>
     *  </thead>
     *  <tbody>
     *      <tr>
     *          <td>Text Display Window</td>
     *          <td>T101OpenAPI.UI_TYPE_TEXT / (byte) 0x02</td>
     *          <td>Displays a text message and listens for a button press (OK / C). Only ASCII formatted text messages maybe displayed. Binary hexadecimals must be converted to ASCII formats before displaying.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *      </tr>
     *      <tr>
     *          <td>QR Code Display Window</td>
     *          <td>T101OpenAPI.UI_TYPE_QR / (byte) 0x03</td>
     *          <td>Displays a QR code message and listens for a button press (OK / C). ASCII formatted text messages or binary messages maybe displayed.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *      </tr>
     *      <tr>
     *          <td>Input Entry Display Window</td>
     *          <td>T101OpenAPI.UI_TYPE_INPUT / (byte) 0x04</td>
     *          <td>Displays an input dialog window to receive a plaintext or secret input. Secret input are obfuscated with '*' character.
     *              <br>
     *              <table border="1">
     *                  <caption><i>Supported Keypad Modes</i></caption>
     *                  <thead>
     *                      <tr>
     *                          <th>Keypad Mode</th>
     *                          <th>Constants</th>
     *                          <th>Description</th>
     *                      </tr>
     *                  </thead>
     *                  <tbody>
     *                      <tr>
     *                          <td>Capitalized alphabet keypad</td>
     *                          <td>T101OpenAPI.FLAG_VKEY_KEYPAD_CAPS_ALPHA / 0x01</td>
     *                          <td>Displays a capitalized alpahbet keypad for input.</td>
     *                      </tr>
     *                      <tr>
     *                          <td>Small alphabet keypad</td>
     *                          <td>T101OpenAPI.FLAG_VKEY_KEYPAD_LOWR_ALPHA / 0x02</td>
     *                          <td>Displays a small letter alpahbet keypad for input.</td>
     *                      </tr>
     *                      <tr>
     *                          <td>Numeric keypad / PINpad</td>
     *                          <td>T101OpenAPI.FLAG_VKEY_KEYPAD_NUMERIC_ALPHA / 0x04</td>
     *                          <td>Displays a numerical keypad for input.</td>
     *                      </tr>
     *                      <tr>
     *                          <td>Printable ASCII symbols keypad</td>
     *                          <td>T101OpenAPI.FLAG_VKEY_KEYPAD_SPECIAL / 0x08</td>
     *                          <td>Displays a printable ASCII symbols keypad for input.</td>
     *                      </tr>
     *                  </tbody> 
     *              </table>
     *              <br>
     *          </td>
     *          <td>Starting keypad mode.<br><br>The first keypad mode to render.</td>
     *          <td>Loaded keypads flags.<br><br>Perform XOR on all keypads that will be loaded for this GUI Session window.<br><br>
     *              Example for a ASCII letters only keypad with both captials and small letters enabled (uiSubMode1 = T101OpenAPI.FLAG_VKEY_KEYPAD_CAPS_ALPHA ^ T101OpenAPI.FLAG_VKEY_KEYPAD_LOWR_ALPHA)
     *          </td>
     *          <td>Is Secret Input flag (0xFF - true)</td>
     *          <td>If the input field has more than 0 bytes of input, the maximum input length is <= 16, else maximum input length <=  32.</td>
     *          <td>If the input field has more than 0 bytes of input, the minimum input length is <= 16, else minimum input length <=  32.</td>
     *      </tr>
     *      <tr>
     *          <td>List Selection Display Window</td>
     *          <td>T101OpenAPI.UI_TYPE_LIST / (byte) 0x05</td>
     *          <td>Displays a list of items in a continously looping list or a non-looping list.</td>
     *          <td>Loop flag (0xFF - true, 0x00 - false)</td>
     *          <td>Item count flag representing the total amount of items to display</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *          <td align="center">N/A.</td>
     *      </tr>
     *  </tbody>
     * </table>
     * <br><br>
     * <table border="1">
     *  <caption><i>Input types for different UI types</i></caption>
     *  <thead>
     *      <tr>
     *          <th>UI Type</th>
     *          <th>Input Parameter Description</th>
     *          <th>Minimum Length</th>
     *          <th>Maximum Length</th>
     *      </tr>
     *  </thead>
     *  <tbody>
     *      <tr>
     *          <td>Text Display Window</td>
     *          <td>Only ASCII formatted text.</td>
     *          <td align="center">0</td>
     *          <td align="center">128</td>
     *      </tr>
     *      <tr>
     *          <td>QR Code Display Window</td>
     *          <td>ASCII formatted text messages or binary messages.</td>
     *          <td align="center">0</td>
     *          <td align="center">128</td>
     *      </tr>
     *      <tr>
     *          <td>Input Entry Display Window</td>
     *          <td>Input used in the Input Entry Display Window provides an additional hint to the end user on the context for input entry. If a hint is set, the input entry will be reduced from 32 bytes to 16 bytes input can be accepted.</td>
     *          <td align="center">0</td>
     *          <td align="center">16</td>
     *      </tr>
     *      <tr>
     *          <td>List Selection Display Window</td>
     *          <td>Displays a list of items in a continously looping list or a non-looping list.<br><br>Only ASCII formatted text maybe display as list items.<br><br>
     *              A length-value array (binary length followed by ASCII content) is used to represent a list of items with each item having a length of <= 15 bytes.<br><br>
     *              Example of the following hexadecimal string "0b68656c6c6f20776f726c640961636d6520636f72700b74686574616b6579313031" will render:
     *              <table>
     *                  <caption></caption>
     *                  <tr><td>&#9658;&nbsp;hello world</td></tr>
     *                  <tr><td>&nbsp;&nbsp;&nbsp;acme corp</td></tr>
     *                  <tr><td>&nbsp;&nbsp;&nbsp;thetakey101</td></tr>
     *              </table>
     *              The list selection cursor (&#9658;) will always select the first item in the list.
     *          </td>
     *          <td align="center">1</td>
     *          <td align="center">96</td>
     *      </tr>
     *  </tbody>
     * </table>
     * <br>
     *
     * @param uiType the type of UI Session to call.
     * @param uiSubMode refer to UI Session subModes table above.
     * @param uiSubMode1 refer to UI Session subModes table above.
     * @param uiSubMode2 refer to UI Session subModes table above.
     * @param uiSubMode3 refer to UI Session subModes table above.
     * @param uiSubMode4 refer to UI Session subModes table above.
     * @param title the title to display on the UI Session title bar.
     * @param titleOffset the offset within title to start.
     * @param titleLen the length of the title to display.
     * @param input the input data for the UI Session.
     * @param inOffset the offset within input to start.
     * @param inLen the length of the input data for the UI Session.
     * @param output containing the 8-byte challenge for the applet's AOC PIN/Key to sign using HMAC-SHA256 algorithm for this activity.
     * @param outOffset offset within output to start.
     * @return the length of returned result in the output buffer.
     */
    public short uiSession(byte uiType, byte uiSubMode, byte uiSubMode1, byte uiSubMode2, byte uiSubMode3,
            byte uiSubMode4, byte[] title, short titleOffset, short titleLen, byte[] input, short inOffset, short inLen,
            byte[] output, short outOffset);

    /** 
     * Get the current system time from the T101's internal RTC clock.
     * <br><br>
     * A 4 byte hexadecimal representation of the current UNIX timestamp will be given.
     * 
     * @param output containing the hexadecimal representation of the current RTC clock time.
     * @param offset offset within output to start. 
     * @return true if getTime fetches the current internal RTC clock time successfully.
     */
    public boolean getTime(byte[] output, short offset);

    /** 
     * Checks if the session is busy in the Key Manager.
     * 
     * @return true if the current KeyManager session is busy.
     */
    public boolean isSessionBusy();

    /** 
     * Resets a busy session by a registered applet. The currently running session and its internal states will be reset and yield no results.
     * <br><br>
     * This function should only be used to break a deadlocked KeyManager session and be used with utmost care. 
     */
    public void resetSession();

    /** 
     * Sets the current AOC registered applet as the Main Menu applet. After this method is called, a physical reboot of the T101 via the power button is needed.
     * <br><br>
     * An extendedRequest call needs to be followed up with the digital signature computed from the 8-byte challenge found in the output of this activity call for activity authentication purposes.
     * 
     * @param output containing the 8-byte challenge for the applet's AOC PIN/Key to sign using HMAC-SHA256 algorithm for this activity.
     * @param outOffset offset within output to start.
     * @return the length of returned result in the output buffer.
     */
    public short setMainMenuSession(byte[] output, short outOffset);
    
    /** 
     * Sets the KeyManager applet as the Main Menu applet. Physically rebooting the T101 via the power button is needed.
     * <br><br>
     * Developers are encouraged to implement this method to reset the KeyManager back to the default Main Menu for convenience of other applets.
     * <br><br>
     * An extendedRequest call needs to be followed up with the digital signature computed from the 8-byte challenge found in the output of this activity call for activity authentication purposes.
     * 
     * @param output containing the 8-byte challenge for the applet's AOC PIN/Key to sign using HMAC-SHA256 algorithm for this activity.
     * @param outOffset offset within output to start.
     * @return the length of returned result in the output buffer or an output status.
     */
    public short resetMainMenuSession(byte[] output, short outOffset);

    /** 
     * Convenience function to covert hexadecimal string representation to its binary equivalent. An example is a hexstring representation "AABBCCDDEEFF" to binary form of 0xAABBCCDDEEFF.
     * 
     * @param input the input buffer containing the hexadecimal string input for encoding.
     * @param offset the offset within input to start.
     * @param output the output buffer containing the binary format derived from the hexadecimal string input.
     * @param outOffset the offset within output to start.
     * @param len the length of the input to be encoded.
     * @return the length of returned result in the output buffer.
     */
    public short hexStrToBin(byte[] input, short offset, byte[] output, short outOffset, short len);
}