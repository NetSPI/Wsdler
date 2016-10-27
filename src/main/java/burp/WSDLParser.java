package burp;

import org.reficio.ws.SoapContext;
import org.reficio.ws.builder.SoapBuilder;
import org.reficio.ws.builder.SoapOperation;
import org.reficio.ws.builder.core.Wsdl;
import org.xml.sax.SAXException;

import javax.swing.*;
import javax.wsdl.WSDLException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import java.awt.*;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class WSDLParser {

    public static IExtensionHelpers helpers;
    public static IBurpExtenderCallbacks callbacks;
    public static IHttpRequestResponse httpRequestResponse;
    private WSDLParserTab tab;
    public static List<String> headers;

    public WSDLParser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers, WSDLParserTab tab) {
        WSDLParser.helpers = helpers;
        this.tab = tab;
        WSDLParser.callbacks = callbacks;

    }

    public int parseWSDL(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) throws ParserConfigurationException, IOException, SAXException, WSDLException, ExecutionException, InterruptedException {
        httpRequestResponse = requestResponse;
        byte[] response = requestResponse.getResponse();

        if (response == null){

            IHttpRequestResponse request = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
            response = request.getResponse();
        }
        if (response == null){
            JOptionPane.showMessageDialog(tab.getUiComponent().getParent(), "Can't Read Response", "Error", JOptionPane.ERROR_MESSAGE);
            return -1;
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        IRequestInfo request = helpers.analyzeRequest(requestResponse);
        headers = request.getHeaders();

        String url = request.getUrl().toString();

        String requestName = url.substring(url.lastIndexOf("/") + 1);

        if (requestName.contains(".")){
            requestName = requestName.substring(0,requestName.indexOf("."));
        }
        if (requestName.contains("?")){
            requestName = requestName.substring(0,requestName.indexOf("?"));
        }
        Wsdl parser;
        try {
            parser = Wsdl.parse(url);
        } catch (Exception e){
            StringBuilder sb = new StringBuilder();
            sb.append(e.getMessage());
            sb.append("\n");
            for (StackTraceElement ste : e.getStackTrace()) {
                sb.append(ste.toString());
                sb.append("\n");
            }
            JTextArea jta = new JTextArea(sb.toString());
            jta.setWrapStyleWord(true);
            jta.setLineWrap(true);
            jta.setEditable(false);
            JScrollPane jsp = new JScrollPane(jta,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER){
                @Override
                public Dimension getPreferredSize() {
                    return new Dimension(480, 320);
                }
            };
            JOptionPane.showMessageDialog(
                    tab.getUiComponent().getParent(), jsp, "Error", JOptionPane.ERROR_MESSAGE);
            return -3;
        }

        WSDLTab wsdltab = tab.createTab(requestName);
        List<QName> bindings;
        try {
            bindings = parser.getBindings();
        } catch (Exception e){
            StringBuilder sb = new StringBuilder();
            sb.append(e.getMessage());
            sb.append("\n");
            for (StackTraceElement ste : e.getStackTrace()) {
                sb.append(ste.toString());
                sb.append("\n");
            }
            JTextArea jta = new JTextArea(sb.toString(),6,40);
            jta.setWrapStyleWord(true);
            jta.setLineWrap(true);
            jta.setEditable(false);
            JScrollPane jsp = new JScrollPane(jta,ScrollPaneConstants.VERTICAL_SCROLLBAR_AS_NEEDED,ScrollPaneConstants.HORIZONTAL_SCROLLBAR_NEVER);
            JOptionPane.showMessageDialog(
                    tab.getUiComponent().getParent(), jsp, "Error", JOptionPane.ERROR_MESSAGE);
            return -2;
        }
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
        return 0;
    }

    private byte[] createRequest(IHttpRequestResponse requestResponse, SoapBuilder builder, SoapOperation operation) {
        SoapContext context = SoapContext.builder()
                .alwaysBuildHeaders(true).exampleContent(true).typeComments(true).buildOptional(true).build();
        String message = builder.buildInputMessage(operation, context);
        String host = getHost(builder.getServiceUrls().get(0));
        String endpointURL = getEndPoint(builder.getServiceUrls().get(0), host);
        List<String> headers;

        headers = helpers.analyzeRequest(requestResponse).getHeaders();

        headers.remove(0);
        headers.add(0, "POST " + endpointURL + " HTTP/1.1");
        Iterator<String> iter = headers.iterator();
        String i;
        while (iter.hasNext()) {
            i = iter.next();
            if (i.contains("Host:")) {
                iter.remove();
            }
            if (i.contains("Content-Type:")) {
                iter.remove();
            }
        }
        headers.add("SOAPAction: " + operation.getSoapAction());
        headers.add("Content-Type: text/xml;charset=UTF-8");
        headers.add("Host: " + host);


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

        return endpoint;
    }

}



