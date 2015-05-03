package burp;

import org.reficio.ws.SoapContext;
import org.reficio.ws.builder.SoapBuilder;
import org.reficio.ws.builder.SoapOperation;
import org.reficio.ws.builder.core.Wsdl;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.wsdl.BindingOperation;
import javax.wsdl.WSDLException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;

public class WSDLParser {

    private IExtensionHelpers helpers;
    private IBurpExtenderCallbacks callbacks;
    private WSDLParserTab tab;
    private Wsdl parser;
    private File temp;


    public WSDLParser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, WSDLParserTab tab) {
        this.helpers = helpers;
        this.callbacks = callbacks;
        this.tab = tab;

    }

    public void parseWSDL(IHttpRequestResponse requestResponse) throws ParserConfigurationException, IOException, SAXException, WSDLException {

        byte[] response = requestResponse.getResponse();

        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        int bodyOffset = responseInfo.getBodyOffset();

        String body = new String(response, bodyOffset, response.length - bodyOffset);

        temp = createTempFile(body);
        if (temp == null) {
            return;
        }
        WSDLTab wsdltab = tab.createTab();
        test();
        temp.delete();
        List<QName> bindings = parser.getBindings();
        SoapBuilder builder;
        List<SoapOperation> operations;
        SoapOperation operation;
        String bindingName;
        String operationName;
        byte[] xmlRequest = null;
        List<String> endpoints;
        for (QName i : bindings) {
            boolean success = true;
            bindingName = i.getLocalPart();
            builder = parser.binding().localPart(bindingName).find();
            operations = builder.getOperations();
            for (SoapOperation j : operations) {
                operationName = j.getOperationName();
                operation = builder.operation().name(operationName).find();
                try {
                    xmlRequest = createRequest(requestResponse, builder, operation);
                } catch (Exception e) {
                    success = false;

                }
                if (success) {
                    endpoints = builder.getServiceUrls();
                    wsdltab.addEntry(new WSDLEntry(bindingName, xmlRequest, operationName, endpoints, requestResponse));

                }

            }
        }
    }

    private File createTempFile(String body) {
        File temp = null;
        if (!body.contains("definitions")) {
            System.out.println("WSDL definition not found");
            return temp;
        }

        try {
            temp = File.createTempFile("temp", ".wsdl");
            BufferedWriter bw = new BufferedWriter(new FileWriter(temp));

            bw.write(body);
            bw.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
        return temp;
    }

    private byte[] createRequest(IHttpRequestResponse requestResponse, SoapBuilder builder, SoapOperation operation) {
        SoapContext context = SoapContext.builder()
                .alwaysBuildHeaders(true).exampleContent(false).typeComments(true).buildOptional(true).build();
        String message = builder.buildInputMessage(operation, context);
        String host = getHost(builder.getServiceUrls().get(0));
        String endpointURL = getEndPoint(builder.getServiceUrls().get(0), host);
        BindingOperation
                soapActionOperation =
                builder.getBinding().getBindingOperation(builder.getOperationBuilder(operation).getOperationName(), builder.getOperationBuilder(operation).getOperationInputName(),
                        builder.getOperationBuilder(operation).getOperationOutputName());

        List<String> headers;

        headers = helpers.analyzeRequest(requestResponse).getHeaders();

        headers.remove(0);
        headers.add(0, "POST " + endpointURL + " HTTP/1.1");
        Iterator<String> iter = headers.iterator();
        while (iter.hasNext()) {
            if (iter.next().contains("Host:")) {
                iter.remove();

            }
        }
        headers.add("Host: " + host);
        //headers.add("SOAPAction: " + SoapUtils.getSOAPActionUri(soapActionOperation));


        return helpers.buildHttpMessage(headers, message.getBytes());
    }

    private String getHost(String endpoint) {
        String host;

        if (endpoint.contains("https://")) {
            endpoint = endpoint.replace("https://", "");
        } else {
            endpoint = endpoint.replace("http://", "");
        }

        int index = endpoint.indexOf("/");
        host = endpoint.substring(0, index);

        return host;
    }

    private String getEndPoint(String endpoint, String host) {

        if (endpoint.contains("https://")) {
            endpoint = endpoint.replace("https://", "");
        } else {
            endpoint = endpoint.replace("http://", "");
        }

        endpoint = endpoint.replace(host, "");

        //endpoint = endpoint.substring(endpoint.indexOf("/")+1);

        return endpoint;
    }

    public void test() {

        JFrame topFrame = (JFrame) SwingUtilities.getRoot(tab.getUiComponent().getParent());
        final JDialog loading = new JDialog(topFrame);
        JPanel p1 = new JPanel(new BorderLayout());
        p1.add(new JLabel("Please wait..."), BorderLayout.CENTER);
        loading.setUndecorated(true);
        loading.getContentPane().add(p1);
        loading.pack();
        loading.setDefaultCloseOperation(JDialog.DO_NOTHING_ON_CLOSE);
        loading.setModal(true);

        SwingWorker worker = new SwingWorker<Wsdl, Void>() {
            @Override
            public Wsdl doInBackground() {
                parser = Wsdl.parse(temp.toURI().toString());

                return parser;
            }

            @Override
            public void done() {
                loading.dispose();
            }
        };

        worker.execute();
        loading.setVisible(true);
        try {
            worker.get();
        } catch (Exception e1) {
            e1.printStackTrace();
        }
    }
}


