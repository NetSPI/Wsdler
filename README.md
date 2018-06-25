Wsdler
======

WSDL Parser extension for Burp

## How to Run ##

1. Download and install from the Burp App store.

2. Right-click on WSDL request and select Parse WSDL

  ![alt tag](https://blog.netspi.com/wp-content/uploads/2015/05/1430624759-035d370fd48f0d9a8c8326a78fccb714.png)

3. The Wsdler tab should populate with the SOAP requests

  ![alt tag](https://blog.netspi.com/wp-content/uploads/2015/05/1430624761-83fe6f80d8d373113cced26ab6c0714b.png)

(Older) Blog detailing how to use the Wsdler Plugin:

https://blog.netspi.com/hacking-web-services-with-burp/

How To Compile
==============

I used IntelliJ to compile this plugin. However, Eclipse should work too. 

1. Clone the repo and open the folder as a project in Intellij/Eclipse
2. Maven is used to retrieve dependencies. So import the pom.xml into Maven. For Intellij, this should happen automatically. You can see the dependencies by clicking the vertically aligned Maven Projects tab on the right side of the window.
3. You should now be able to compile the plugin. Make sure that when you are building, a jar file gets created. In Intellij, select File > Project Structure > Artifacts > Plus Sign > Jar > From modules with dependencies > OK and check the Build on make checkbox. That should be it. Again, the process should be similar in Eclipse.
