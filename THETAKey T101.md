# ThothTrust THETAKey T101 #

## About THETAKey ##

The THETAKey smart card is a rechargeable and highly advanced JavaCard capable smart card with an embedded e-Ink display screen with a 
screen dimension of 256 pixels on the width and height.

A single mechanical power button and 12 touch capacitive buttons are also equipped with the THETAKey smart card to allow users to securely 
interact with the smart card without having their keystrokes being keylogged on a conventional keyboard and the embedded e-Ink screen to 
provide a much more trusted and secure display than a conventional computer screen monitor.

The THETAKey product aims to provide high levels of digital security for secure logic execution combined with much more secure and trusted 
user interactions in a single end-user programmable smart card which is unlike most advanced smart cards which requires the card's 
manufacturer involvement in customizing the card's firmware.

The THETAKey with its Open API, allows end users to simply utilize existing JavaCard programming language to create their own JavaCard 
applets or to re-use existing off-the-shelf JavaCard applets with minimal changes to existing JavaCard applet codebases to be able to 
fully utilize the security framework and capabilities provided by the THETAKey T101 OpenAPI to fully realize and utilize the THETAKey's 
smart card functionalities.

## Product Naming Convention ##

The T101 product code designation for the THETAKey product denotes the first variant of the THETAKey smart card and subsequent variant 
will see the numerical changes while retaining the initial 'T' designation for the THETAKey product line. Due to the possibility of 
expanding the product line beyond an advanced smart card, numerical designations would be used to indicate the different hardware 
variants that the THETAKey devices that are available.

## THETAKey Physical Characteristics ##
* ISO-7816 (Contact) and ISO-14443 (Contactless/NFC) physical and electrical compliant
* CC EAL 5+ smart card chip (THD-89 chip)
* 256 x 256 E-Ink display
* 1 mechanical power button
* 12 capacitive touch 'soft' buttons
* Internal dual chip MCU design with integrated Bluetooth LE in Controller MCU
* RTC clock residing in Controller MCU
* Re-chargeable internal battery using ISO-7816 contact pad for re-charging
  * Uses conventional smart card readers with 5 volts to re-charge smart card battery over contact pad.
  
## The THD-89 Common Criteria Secure MicroController Certification ##
* Note that the certification does not apply to the JCOS or other applets and libraries not specified in the Common Criteria document.
* [https://www.commoncriteriaportal.org/files/epfiles/2017-28%20INF-2492.pdf](https://www.commoncriteriaportal.org/files/epfiles/2017-28%20INF-2492.pdf)

## THETAKey Subsystems ##

The THETAKey subsystems available:
* Secure display, input and windowing system
* Protected RTC clock
  * Protected Key Manager objects and credentials maybe tied to expiry timestamps to allow objects to be expired
* Key Manager system
* Open API
* Global User Management Applet

## THETAKey's JavaCard Components Architecture ##

The THETAKey T101 JavaCard hosts multiple proprietary applets and packages that gives access to the numerous physical hardware (i.e. E-Ink screen). ThothTrust have developed an OpenAPI built on top of a Key Manager framework to allow client card applications to freely and securely access the OpenAPI via calling the Shareable Interface of the KM101 Key Manager Applet from the client card application.

A client card application is required to register it's presence and setup an Application Container within the ThothTrust Key Manager environment so as to allow secure resource access while providing gaurantees that the access calls are authenticated from the registered client application's end to prevent malicious spoofing of API access calls.

JavaCard applets that are not registered to the Key Manager will only be able to access the following methods:

* `cryptoHMAC`
* `cryptoChaCha20`
* `getTime`
* `getBufferDataLength`
* `isSessionBusy`
* `hexStrToBin`

![THETAKey T101 JavaCard Architecture](/img/JC-Arch.png)


## T101's KeyManager and OpenAPI Components Architecture ##

Access to the lower level hardware (i.e. E-Ink screen) requires the access to the Key Manager via registered Containers to allow a controlled and secure access to native resources. The Key Manager is currently capable of:

* Global User's Object Container - 2 containers
* Applet Object Container - 2 containers

JavaCard Applets that lack the access to Applet Object Containers are still capable of using the  standard JavaCard and GlobalPlatform APIs without any negative side effects. 

JavaCard developers may decide to utilize local storage of keys and data within their own applets outside of the control of the Key Manager without any negative consequences in the event that the developers may have legitimate reasons and/or concerns for not trusting the Key Manager applet provided by ThothTrust.

Some applets may require larger amount of storage capacities than the limited object storage slots that the Key Manager provides for each Applet Object Container and storing less important objects outside of the Key Manager is highly recommended due to the significantly small amount of storage slots available in the Key Manager.

One scenario for Card Developers that partially or stronger trust the Key Manager that ThothTrust provides may store high priority cryptographic keys (i.e. Master Keys or Key Encrypting Keys) inside the Key Manager while wrapped Key Blobs maybe stored within their own applets.

Objects stored in the Key Manager stand to benefit from a structured Access Control List with specific Access Control rules developed by ThothTrust for managing access to stored objects as well as strongly binding objects to unique identifiers (if specified by developers) as well as allowing objects to be protected by an expiration timestamp utilizing the built-in RTC clock within the THETAKey T101 when properly defined during creation of an object.

Global Users play a significant role in the Key Manager environment by allowing a single user to participate in any registered Applet Object Containers as either administrative users or normal users by not having to require re-creating the same user within the same THETAKey card multiple times when new aplets are installed.

All Global Users have an internal attestation Identity Certificate generated during their creation thus are capable of being used as Trusted Identities when used as administrative users within Applet Object Containers once proper attestation verification have been performed.

One possible use case might involve a national level Registration Authority creating a properly attested user identity that is injected into a THETAKey T101 card which can the global user (card holder), may have other applets that wish to access the card holder's attested identity for financial or Governmental use cases.

![KM101 Architecture](/img/KM-Arch.png)
