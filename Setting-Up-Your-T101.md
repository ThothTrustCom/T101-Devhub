# Instructions for Setting Up Your THETAKey T101

* Before using the THETAKey T101 card, please follow the steps and instructions below.

## Required Software ##

* Oracle Java J2SE 8 and above
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



