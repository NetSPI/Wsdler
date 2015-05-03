package burp;

import java.awt.*;

public class BurpExtender implements IBurpExtender
{

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks)
    {

        IExtensionHelpers helpers = callbacks.getHelpers();

        callbacks.setExtensionName("WSDLer");

        callbacks.registerContextMenuFactory(new Menu(callbacks));

    }
}