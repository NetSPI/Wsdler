package burp;

import org.xml.sax.SAXException;

import javax.swing.*;
import javax.wsdl.WSDLException;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.event.MouseEvent;
import java.awt.event.MouseListener;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.util.ArrayList;
import java.util.List;

public class Menu implements IContextMenuFactory {
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private WSDLParserTab tab;

    public Menu(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        helpers = callbacks.getHelpers();
        tab = new WSDLParserTab(callbacks);
    }

    public List<JMenuItem> createMenuItems(
            final IContextMenuInvocation invocation) {
        List<JMenuItem> list;
        list = new ArrayList<JMenuItem>();
        JMenuItem item = new JMenuItem("Parse WSDL");

        item.addMouseListener(new MouseListener() {

            public void mouseClicked(MouseEvent e) {

            }


            public void mousePressed(MouseEvent e) {
                WSDLParser parser = new WSDLParser(callbacks, helpers, tab);
                try {
                    parser.parseWSDL(invocation.getSelectedMessages()[0]);
                } catch (ParserConfigurationException e1) {
                    e1.printStackTrace();
                } catch (IOException e1) {
                    e1.printStackTrace();
                } catch (SAXException e1) {
                    e1.printStackTrace();
                } catch (WSDLException e1) {
                    e1.printStackTrace();
                }
            }


            public void mouseReleased(MouseEvent e) {

            }


            public void mouseEntered(MouseEvent e) {

            }


            public void mouseExited(MouseEvent e) {

            }
        });
        list.add(item);

        return list;
    }

}