This is a fork of the Eclipse project Californium created with the purpose of adding object security to CoAP in accordance with https://tools.ietf.org/html/draft-selander-ace-object-security-04

##setup:

git clone --recursive git@bitbucket.org:joakimb/oscoap_californium.git

cd oscoap_californium

./makeCOSElocal.sh

##import instructions for intellij: 
###(any other java IDE such as eclipse should work aswell)

* Start intellij
* Select "import project" and navigate to OSCoAP directory
* Select "import project from external model" and "maven", hit next
* Select "import maven projects automatically"
* Hit next until prompted for java SDK, select a java 1.8 version
* Hit next, next and finish

Example code is provided in californium-core/src/test/java/org/eclipse/californium/core/test/objectsecurity/ObjectSecurityTest.java

The test devTest() starts an OSCoAP server and client and sends a request and response over the local interface.


