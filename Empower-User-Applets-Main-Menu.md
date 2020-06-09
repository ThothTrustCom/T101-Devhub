# Empowering User Applets With Main Menu #

## About the T101 Main Menu ##
The T101 comes equipped with a software driven Main Menu for users to interact with the smart card without the need of a smart card reader or an NFC equipped smartphone. The Main Menu is displayed when the user presses the Power button on the card to power up the card.

The Main Menu session is driven by the T101's KeyManager session with the highest UI Session trust level.

In the firmware upgrade for the KeyManager to `version 1.1`, the Main Menu session is now open to user loaded applets for gaining access to the Main Menu session with the user applet's own Main Menu interface.

The UI session's security and the security of the KeyManager does not diminish even if the user applet gains control of the Main Menu session.

## Benefits of Giving User Applets access to Main Menu ##

User applets with access to the Main Menu are given another method of accessing the smart card functuionalities without the need to utilize a contact or contactless reader to access the card. Part of the user applet's functionalities may be accessed on-the-fly when the user is on the move where deploying card readers may become a hassle.

Some use cases where user applets may exploit the access to the Main Menu:
* Generating QR codes for fast identification or exchange of Bitcoin addresses
* Generating One-Time Passwords and other offline authentication codes from Main Menu for 2nd Factor Authentication
* Managing user profiles within the user applets without needing card readers or NFC access

	![OTP Applet Controlled Main Menu](/img/OTP-Menu.jpg)

## Limitations of Main Menu ##

Accessing the Main Menu from the front panel of the T101 card is limited by the amount of battery power the card has in its internal battery. A card with low power would not be capable of operation directly from the front panel of the card which makes the access to the Main Menu inaccessible until the card has its power fully charged using a card reader.

Developers designing the Main Menu for their User applets are advised to keep the Main Menu interface as simple as possible for easy user access and also to limit the amount of exposed features (including security sensitive operations) from the front panel Main Menu. 

Operations that are security sensitive must be protected by some form of authentication from the front panel of the card.

## User Applet Prerequisites To Gain Main Menu Access ##

User applets are required to make the following changes to their user applets to gain access to the front panel's Main Menu session:
* Change their AOC container's `CRED_FIELD_MANAGEMENT` field's value to `CRED_MGMT_FRONT_PANEL` via the API's `manageAOCContainer()` method.

* The APDU of `CLA=B0, INS=10, P1=02, P1=00, LC=00` in an applet's `process()` method should return the bytes `0101` in the outgoing APDU response.

* The APDU of `CLA=B0, INS=10, P1=00, P1=00, LC=00` in an applet's `process()` method should begin the rendering of the Main Menu interface and codes for constructing the Main menu interface must be done upon the call of this APDU.


## How To Setup User Applets For Main Menu Access ##

Upon installing a user applet with the above access conditions for Main Menu access, the user applet does not automatically gain access to the Main Menu interface.

The card user must manually select the suitable user applet to become the default Main Menu accessing applet from the KeyManager's Main Menu interface. This is to prevent user applets from trying to set themselves as the default Main Menu accessing applet thus possibly creating a race condition between multiple applets trying to access the Main Menu session.

1. The card user would first need to boot up the card by holding down on the Power button for about two seconds firmly until the card boots up (card must NOT be in the card reader or connected to an NFC device). The user would scroll from the Main Menu to an applet menu of the applet they are interested in setting as the Main Menu default applet.

	![Main Menu](/img/T101-V1_1-Main-Menu.jpg)

2. The card user would then be presented with two sub-options, `Manage` and `Set Menu`.

	![Version 1.1 new Selection Sub-Menu](/img/T101-V1_1-Selection-Action-Menu.jpg)

3. The card user would scroll and select `Set Menu`. 

4. A successful operation message would appear and the user have to press on the Power button to power down the card and then power on the card again to allow the Main Menu session to take effect.

## Changing Main Menu Accessing Applets ##

In the event that the Main Menu session is not set to the KeyManager and the card user decides to revoke the current applet's access to the Main Menu session and to reinstate the KeyManager as the default Main Menu applet, the card user may issue the APDU of `CLA=B0, INS=0F, P1=00, P1=00, LC=00` from a contact or contactless card reader to the KeyManager applet thus triggering a hard reset on the Main Menu session and thus returning control of the Main Menu back to the KeyManager.

Once the KeyManager is back in control of the Main Menu session, the user may continue to select other user applets as Main Menu default applets.
