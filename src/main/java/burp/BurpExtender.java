package burp;

public class BurpExtender implements IBurpExtender
{

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {

        callbacks.setExtensionName("Wsdler");

        callbacks.registerContextMenuFactory(new Menu(callbacks));

    }
}