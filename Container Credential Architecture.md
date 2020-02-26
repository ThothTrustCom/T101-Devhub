# Container Credential Architecture #

## About Containers ##

Containers are structured collection of data for a collection of users and data objects (i.e. cryptographic keys). Within the KeyManager is a separation of containers via separated data groups in a proprietary vritual Filesystem created by ThothTrust for the THETAKey environment for its specific requirements.

Users gain access to data objects within their own isolated containers and between containers, they are usually not able to cooperate with each other to ensure secure isolation between each container even if the containers may share the same users (i.e. Global users).

There are two type of containers that exists in the KeyManager environment. A Global Object Container and a Applet Object Container are the two existing types of containers specifically 
tailored to different types of users.

![Container Security Model](/img/Credential-Security-Model.png)

## The Global User ##

A Global Object Container (a.k.a Global User) is both a special container with the container being  the user itself at the same time. This container (Global Object Container/User) may participate in non-Global Object Container (Applet Object Containers) as normal or admininstrative users. Global users typically represent an interactive user. The Global user will also be a member of its own Container User Group.

Essentially, one may consider a Global Object Container as an independent user that can cross domains (Applet Object Containers) upon invitation and their credentials are not manageable by other domains they participate except themselves.

## The Applet Object Container ##

An Applet Object Container AOC container) represents a container linked to an existing JavaCard client applet to allow the JavaCard applet to fully utilize the different features and capabilities of the T101. The AOC container by itself is its own user similar to the Global user but differs from the Global user's cotainer due to the limited ability for JavaCard applets to act on its own unlike a typically human controlled global user.

The AOC container's own container credential (called the AOC Container Credential) is used in a limited capacity for managing the container's environment and to allow access to the UISession and temporary data buffering capabilities of the container environment. The expiry or lost of the AOC Container Credential will cause the lost of access to manage the container's environment (i.e. rename container, update AOC Container Credential authetnication PIN/Password), the UISession and temporary data buffering functions.

Seperate from the AOC container are users that would require access to data stored within the AOC container for processing and storage. These users are typically interactive human users and they make up the Container User Group that will be granted access to data stored and processed by the container (i.e. key storage and cryptographic key operations via stored keys). The AOC Container Credential is excluded from the Container User Group as part of a security measure to ensure that the ability to control the UISession by the AOC Container Credential would not directly give access to sensitive key materials and cryptographic key operations within the container's data store in the event of a compromise of the JavaCard client applet.

The Container User Group compromises of a two level hierarchy of Container Admininstrators and Container Users that will have different access levels to sensitive data object stored within the container. Admininstrators are by default given all the rights (Read, Edit, Execute) to all objects and normal users will have to be dependent on the Access Control List assigned to each object during the time of the object's creation.

Administrators within the Container User group would also be capable of adminstrating and resetting credentials of all Container Users that are not Global User.

## Management of AOC Container ##

An AOC container maybe considered adminstrable when there are administrators existing in the container. An AOC container without any administrator would immediately become unadmininstrable and thus user management would become disabled where no additional users can be created and no promotion of any users to the role of administrator is allowed. All object access would immediately default to the existing ACLs assigned on a per object basis for all container users.

## Participation of Global Users in AOC Containers ##

Global Users may participate in an AOC container strictly by invitation of any administrators within the Container User Group of an AOC container either as a normal user or as an administrator. The participation is not automatic and immediate during the sending of invitation by an administrator of the Container to the Global User. The Global User has to acknowledge the invite via their Invitation Inbox either from the Front Panel access of the T101 or via the GOC Applet with APDU commands.

Global Users will still be treated as container users with access to the data objects stored in the AOC container but they are still subjected to the Access Control List and the two-tier hierarchy of the Container User Group as with other normal users.

## User Creation And Enrollment During Applet Object Container Creation ##

During the creation phase of an AOC container (before the `finalizeContainer()` method is called), all methods used for creating new AOC users are automatically promoted as container administrators and all invitation sent to Global Users during the AOC container's creation phase are also automatically elevated to the position of administrator.

If no administrators are created or invited (for Global User's case) into the AOC container during the creation phase and the `finalizeContainer()` has been called without any users created as admininstrators, the AOC container would automatically default into an unadministrable state and no other users can be created and no Global Users can be invited to become members of an AOC container.

During the creation phase, the AOC Container Credential is the sole credential with the power to invite Global Users and create new users (that will become administrators) for the AOC container. When the `finalizeContainer()` has been called due to the AOC Container Credential being the sole credential that exists within the partially created AOC container at the intial AOC container creation stage, the AOC Container Credential will lose the ability to create and invite users as
the AOC container would now become fully operational and giving the AOC Container Credential the special privilege of creating and inviting users would become a security risk in the event the client side JavaCard applet were to become compromised and the AOC Container Credential leaks.

## Promotion Of User In AOC Containers ##

Users within an AOC container's Container User group with no administrative privileges maybe promoted to administrators when any administrators decides to promote a normal user.

## Termination of Containers ##

Global Users can only be destroyed when upon the fulfillment of the following circumstances:
* Manual self-deletion
* Global Users have their expiry timestamp set and their credentials have expired.
* Too many failed PIN/Password entry causing their credentials to become locked.

Note: For the last two points, an additional APDU command for the KeyManager must be sent to cleanup the "stale" Global Users.

AOC containers can only be destroyed  when upon the fulfillment of the following circumstances:
* Manual self-deletion by calling the `destroyContainer()` from the client applet without requiring authentication.
* The client JavaCard applet corresponding to the AOC container have been deleted but the AOC container becomes orphaned whereby a manual APDU command on the KeyManager has to be called to cleanup the "stale" AOC containers.

