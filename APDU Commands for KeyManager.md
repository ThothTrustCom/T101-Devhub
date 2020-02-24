# APDU Commands for KeyManager #

The applet AID for the KeyManager is `4B4D313031` for acquiring basic data from KeyManager and to securely set your RTC clock on the KeyManager.

### Query KeyManager Public Key ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>C0</td>
<td>00</td>
<td>N/A</td>
<td>33</td>
</tr>
</table>

Return: Unique ECC-P256K1 public key for KeyManager's Identity Key.


### Query KeyManager General State Information ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>C0</td>
<td>00</td>
<td>N/A</td>
<td>09</td>
</tr>
</table>

Return: Current KeyManager provisioning state, available persistent memory, available transient memory (RESET type).

<table border="1">
<tr>
<td>Prov State</td>
<td>Memory (Persist)</td>
<td>Memory (Trans)</td>
</tr>
<tr>
<td>1 byte.</td>
<td>4 bytes. 32-bit Integer representation.</td>
<td>4 bytes. 32-bit Integer representation.</td>
</tr>
</table>

Note: Provisioning state should be in FF otherwise the card is unusable.

### Query Root Authorization Serial Number ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>08</td>
</tr>
</table>

Return: Root Authority's Serial Number used for Trustchain attestation.


### Query Root Authorization Creation Timestamp ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>01</td>
<td>00</td>
<td>N/A</td>
<td>04</td>
</tr>
</table>

Return: Root Authority's creation timestamp used for Trustchain attestation.


### Query Root Authorization Object ID ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>02</td>
<td>00</td>
<td>N/A</td>
<td>20</td>
</tr>
</table>

Return: Root Authority'sObject ID used for Trustchain attestation.


### Query Intermediate Authorization Serial Number ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>03</td>
<td>00</td>
<td>N/A</td>
<td>08</td>
</tr>
</table>

Return: Intermediate Authority's Serial Number used for Trustchain attestation.


### Query Intermediate Authorization Creation Timestamp ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>04</td>
<td>00</td>
<td>N/A</td>
<td>04</td>
</tr>
</table>

Return: Intermediate Authority's creation timestamp used for Trustchain attestation.

### Query Intermediate Authorization Object ID ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>05</td>
<td>00</td>
<td>N/A</td>
<td>20</td>
</tr>
</table>

Return: Intermediate Authority's Object ID used for Trustchain attestation.

### Query KeyManager Authorization Serial Number ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>06</td>
<td>00</td>
<td>N/A</td>
<td>08</td>
</tr>
</table>

Return: KeyManager's Serial Number used for Trustchain attestation.


### Query KeyManager Creation Timestamp ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>07</td>
<td>00</td>
<td>N/A</td>
<td>04</td>
</tr>
</table>

Return: KeyManager's creation timestamp used for Trustchain attestation.


### Query KeyManager Object ID ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>08</td>
<td>00</td>
<td>N/A</td>
<td>20</td>
</tr>
</table>

Return: KeyManager's Serial Number used for Trustchain attestation. Used on the Front Panel mode to double check the ID displayed.


### Query Current Device RTC Time ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>00</td>
<td>09</td>
<td>00</td>
<td>N/A</td>
<td>04</td>
</tr>
</table>

Return: Current device RTC time.


### Query TrustChain Certificate Chain Length ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>01</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>02</td>
</tr>
</table>

Return: Two byte short representation of the length of the Trustchain certificate chain loaded in the KeyManager. Trustchain chains from Root Authority to Intermediate Authority to KeyManager level chaining.


### Segmented Reading of Trustchain Data ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>FF</td>
<td>02</td>
<td>00</td>
<td>04</td>
<td>2 byte short representation offset to read followed by 2 byte short representation length to read.</td>
<td>FF</td>
</tr>
</table>

Return: Trustchain data in segments.

### Set Time Key ###

<table border="1">
<tr>
<td>CLA</td>
<td>INS</td>
<td>P1</td>
<td>P2</td>
<td>LC</td>
<td>DATA</td>
<td>LE</td>
</tr>
<tr>
<td>B0</td>
<td>04</td>
<td>00</td>
<td>00</td>
<td>20</td>
<td>new Time Key bytes - 256 bits long.</td>
<td>00</td>
</tr>
</table>

Return: Set new Time Key. Can only be done if the device is in 'Factory' mode.

### Set Time ###

1. Query for random challenge nonce (8 bytes) before setting time.

	<table border="1">
	<tr>
	<td>CLA</td>
	<td>INS</td>
	<td>P1</td>
	<td>P2</td>
	<td>LC</td>
	<td>DATA</td>
	<td>LE</td>
	</tr>
	<tr>
	<td>B0</td>
	<td>03</td>
	<td>00</td>
	<td>00</td>
	<td>00</td>
	<td>N/A</td>
	<td>08</td>
	</tr>
	</table>

	Return: First step retrieving time setting challenge will return 8 bytes of nonce.

2. Format payload

	<table border="1">
	<tr>
	<td>Header</td>
	<td>Nonce</td>
	<td>Timestamp (UNIX)</td>
	</tr>
	<tr>
	<td>3 bytes. Use bytes `1010001` </td>
	<td>8 bytes.</td>
	<td>4 bytes.</td>
	</tr>
	</table>

	The header `010001` with the first two bytes `0100` represents version `1` of the time setting protocol. The last `01` represents option `1`. Option `1` uses a clear channel with HMAC-SHA256 signing. Currently only Option 1 setting method is available. Introduction of other methods maybe intorudced in later times when necessary.

3. Sign payload with Time Key

	Sign the above payload with HMAC-SHA256 using a Time Key you set and append the 32 byte output from the MAC to the end of the above payload. Your payload should now look like this:

	<table border="1">
	<tr>
	<td>Header</td>
	<td>Nonce</td>
	<td>Timestamp (UNIX)</td>
	<td>MAC</td>
	</tr>
	<tr>
	<td>3 bytes. Use bytes `1010001` </td>
	<td>8 bytes.</td>
	<td>4 bytes.</td>
	<td>32 bytes.</td>
	</tr>
	</table>

4. Send payload to device

	Use the same APDU as `Step 1` but now adjust it to have the payload data.

	<table border="1">
	<tr>
	<td>CLA</td>
	<td>INS</td>
	<td>P1</td>
	<td>P2</td>
	<td>LC</td>
	<td>DATA</td>
	<td>LE</td>
	</tr>
	<tr>
	<td>B0</td>
	<td>03</td>
	<td>00</td>
	<td>00</td>
	<td>2F</td>
	<td>Signed Payload</td>
	<td>00</td>
	</tr>
	</table>

	Return: It should return `9000` to indicate successful setting of new RTC time. If it returns `6984`, either the length or format is invalid (which may include incorrect header) or the signature is signed incorrectly (i.e. using wrong Time Key or bad formatting). You should query the device RTC time to confirm that the new time has been set correctly.





