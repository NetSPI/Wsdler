package burp;

public class BurpExtender implements IBurpExtender
{

    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {

        callbacks.setExtensionName("Wsdler");

        callbacks.registerContextMenuFactory(new Menu(callbacks));

    }
}