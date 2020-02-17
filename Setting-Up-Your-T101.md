# Instructions for Setting Up Your THETAKey T101

* Before using the THETAKey T101 card, please follow the steps and instructions below.

## Required Software ##

* Oracle Java J2SE 8 and above
* Your J2SE installation must be able to support HMAC-SHA256 via the Unlimited Strength Policy file for Java version 8 and below. Visit Oracle page for more information [here](https://www.oracle.com/java/technologies/javase-jce-all-downloads.html).
* OpenSC for Linux machines
* Go to the `Tools` folder in Github and clone the `TimeTool` folder.

## Checking the Card Status after received a card shipment ##

After you have received your shipment, you should perform the following checks.

* The two pieces of tamper evident stickers that have been used to seal the box must be intact without revealing signs of attempted tamper on them. The tamper evident sticker will have visible 'VOID' words across the box when there is an attempt to peel or break the tamper evident sticker.
* The boxes must not have sign of forced entry.
* Power-on the card by holding onto the Power button firmly for 5 seconds until the card boots up and scroll to the `Info` option on the main screen. The card information page will be displayed on the E-Ink screen showing the firmware version, hardware version, the Key Manager Identity value as well as the current card status via the `Stat` value. The `Stat` value must show a `Factory` state to indicate that the Key Manager environment have not seen usage.


## Setting Up Card's Time Key ##

The accuracy and reliability of the THETAKey T101's internal RTC clock is highly important as it is an important source of time to credentials and security objects within the Key Manager environment. A static HMAC-SHA256 key with a length of 256-bit is used to authorize the updating of the RTC clock's time, called the Time Key.

Before a card holder may perform any operation to create a Global User or an Applet Object Container, the Time Key may freely be set over an insecure APDU. Once the Key Manager detects the creation of any Containers, the function of setting the Time Key will be permanently disabled.

The `TimeTool` folder provides both the Java source code as well as binary JAR file to allow the interaction and updating of the Time Key as well as performing authenticated time updates on the T101 card.

## Compiling TimeTool from source code ##

You may use any Java capable IDE and create a project named `TimeTool` with the package `org/thothtrust/sc/thetakey/timetool` otherwise you might have to slightly edit the codes with your own package name.

## Running TimeTool ##

You may want to look at the options available via:

	> java -jar TimeTool.jar
    [ERR] Incorrect argument(s) !
    ThothTrust TimeTool v1.0
    ========================
    Time Setting Tool for THETAKey T101.
    Args:                                   Desc:
    -list ................................. List all available THETAKey devices.
    -setkey <256bit-hex-keybytes> <pos> ... Setting Time Key in Factory mode.
    -settime <256bit-hex-keybytes> <pos> .. Syncs computer time to T101 with
                                            HMAC-SHA256 Challenge Respond using
                                            Time Key.
    -gettime <pos> ........................ Get T101 device time.

### Listing T101 cards ###

	> java -jar TimeTool.jar -list
	Listing THETAKey T101 devices ...
	Devices: 1
	Pos: 0, Termianl Name: Excelsecu Reader 0

Note the card's position via the terminal name. You will be choosing a card position as the `pos` parameter for other commands later on.

### Setting Up Your Time Key ###

You will need to have on hand a 256-bit key value you desire as your new Time Key and the card must be in Factory mode for device position 0.

	> java -jar TimeTool.jar -setkey 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f 0
	Setting time key ...
	Response: 9000
	[INF] Successfully installed time key ...

Note that currently success response would be given even if your T101 card is not in Factory mode but in reality the card would silently reject any attempts to set a new Time Key when Factory mode has been removed.

You will need to test the setting of the Time Key to ensure your desired Time Key has been loaded when the card is in Factory mode via attempting to set T101's RTC clock via the `settime` command.

### Setting RTC clock ###

You will need to have the Time Key and device position on hand. Your computer time will be used as the time source for the T101 card's RTC clock. You may want to enable an NTP sync on your computer time for additional RTC clock accuracy. We will not provide a tutorial on setting up NTP service on your computer.

	> java -jar TimeTool.jar -settime 404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f 0
	Response: A4F521052A5FDD519000
	Challenge nonce: A4F521052A5FDD51
	Current computer timestamp: 2020-02-17 11:46:23.962
	Setting time in unix: 5E4A0C8F
	Response Block: 010001A4F521052A5FDD515E4A0C8F293C5664E392A08C2265795501AEB3549804693E955E55F747677DD06671FD5A
	Response: 9000
	[INF] Successfully updated T101 RTC clock ...

If you receive a response similar to the following:

	> java -jar TimeTool.jar -settime 0000000000000000000000000000000000000000000000000000000000000000 0
	Response: 41520833534090749000
	Challenge nonce: 4152083353409074
	Current computer timestamp: 2020-02-17 12:21:14.06
	Setting time in unix: 5E4A14BA
	Response Block: 01000141520833534090745E4A14BA4AF63FC8698EB1B7360B66D5E4502DE7E9823ED693929C35F448E193CD299590
	Response: 6984
	[ERR] Failed to update T101 RTC clock ...
	Error Status Word: 6984

You have most likely used an incorrect Time Key for setting the RTC clock.

## Retrieving Timestamp from T101 Card ##

You may retrieve the current time from the card by running the following command. The response would be a 4 byte UNIX timestamp.

	> java -jar TimeTool.jar -gettime 0
	Getting T101 time ...
	[INF] Current device time (hex): 5E4A15C4