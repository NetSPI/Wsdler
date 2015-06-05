package burp;

import java.awt.*;

import javax.swing.*;

public class WSDLParserTab implements ITab {

    JTabbedPane tabs;
    private IBurpExtenderCallbacks callbacks;
    static int tabCount = 0;
    static int removedTabCount = 0;

    public WSDLParserTab(final IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;

        tabs = new JTabbedPane();

        callbacks.customizeUiComponent(tabs);

        callbacks.addSuiteTab(WSDLParserTab.this);

    }

    public WSDLTab createTab(String request) {

        WSDLTab wsdltab = new WSDLTab((callbacks), tabs, request);
        tabs.setSelectedIndex(tabCount - removedTabCount);
        tabCount++;

        return wsdltab;
    }

    public String getTabCaption() {
        return "Wsdler";
    }

    public Component getUiComponent() {
        return tabs;
    }


}
