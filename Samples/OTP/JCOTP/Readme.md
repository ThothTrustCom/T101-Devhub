# APDU For TOTP Applet #

### Select Applet ###

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
<td>00</td>
<td>A4</td>
<td>04</td>
<td>00</td>
<td>05</td>
<td>4A434F5450</td>
<td>00</td>
</tr>
</table>

Return: `9000` should always be returned.

### Get API Instance ###

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
<td>00</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>00</td>
</tr>
</table>

Description: Call this method if this is your first attempt after loading the CAP file to gain an API instance.

Return: `9000` should always be returned. 

### Create AOC Container Instance ###

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
<td>00</td>
</tr>
</table>

Description: Call this method if this is your first attempt after loading the CAP file and after calling the `Get API Instance` method to create an AOC container. You will need to look at your T101 smart card screen to check if the setup of AOC container is successful or not.

Return: `9000` should always be returned. 

### Set OTP Key ###

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
<td>01</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>00</td>
</tr>
</table>

Description: You may set your OTP key at any time. The OTP key should be in Base32 format. The demo will only use HMAC-SHA1 algorithm with a 6 digit OTP output.

Return: `9000` should always be returned. If OTP key is not in a valid Base32 format, it will throw `SW_DATA_INVALID`.

### Generate OTP Number ###

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
<td>02</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>00</td>
</tr>
</table>

Description: Generates a 6 digit OTP number on the T101's screen. You may only call this method when you have already called `Get API Instance` and `Create AOC Container Instance` with both of them successful.

Return: `9000` should always be returned. If no OTP key is set, it will throw `SW_SECURITY_STATUS_NOT_SATISFIED`.

### Get OTP Key ###

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
<td>00</td>
</tr>
</table>

Description: Exports OTP key that have been set into the applet.

Return: `9000` should always be returned.

### Set OTP Key ###

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
<td>01</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>00</td>
</tr>
</table>

Description: You may set your OTP key at any time. The OTP key should be in Base32 format. The demo will only use HMAC-SHA1 algorithm with a 6 digit OTP output.

Return: `9000` should always be returned.

### Get RTC Time ###

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
<td>0E</td>
<td>00</td>
<td>00</td>
<td>00</td>
<td>N/A</td>
<td>00</td>
</tr>
</table>

Description: Get's the RTC clock's internal UNIX time. You may only call this method when you have already called `Get API Instance` and `Create AOC Container Instance` with both of them successful.

Return: `9000` should always be returned.