package burp;

import org.reficio.ws.SoapContext;
import org.reficio.ws.builder.SoapBuilder;
import org.reficio.ws.builder.SoapOperation;
import org.reficio.ws.builder.core.Wsdl;
import org.xml.sax.SAXException;

import javax.wsdl.WSDLException;
import javax.xml.namespace.QName;
import javax.xml.parsers.ParserConfigurationException;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Iterator;
import java.util.List;
import java.util.concurrent.ExecutionException;

public class WSDLParser {

    private IExtensionHelpers helpers;
    private WSDLParserTab tab;

    public WSDLParser(IExtensionHelpers helpers, WSDLParserTab tab) {
        this.helpers = helpers;
        this.tab = tab;

    }

    public int parseWSDL(IHttpRequestResponse requestResponse, IBurpExtenderCallbacks callbacks) throws ParserConfigurationException, IOException, SAXException, WSDLException, ExecutionException, InterruptedException {

        byte[] response = requestResponse.getResponse();

        if (response == null){

            IHttpRequestResponse request = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
            response = request.getResponse();
        }
        if (response == null){
            return -1;
        }

        IResponseInfo responseInfo = helpers.analyzeResponse(response);

        if (!responseInfo.getStatedMimeType().contains("XML")){
            return -2;

        }

        int bodyOffset = responseInfo.getBodyOffset();

        String body = new String(response, bodyOffset, response.length - bodyOffset);

        File temp = createTempFile(body);
        if (temp == null) {
            return -2;
        }

        IRequestInfo request = helpers.analyzeRequest(requestResponse);

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
            parser = Wsdl.parse(temp.toURI().toString());
        } catch (Exception e){
            return -3;
        }
        if (!temp.delete()){
            System.out.println("Can't delete temp file");
        }

        WSDLTab wsdltab = tab.createTab(requestName);
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

        return 0;
    }

    private File createTempFile(String body) {
        File temp = null;
        if (!body.contains("definitions")) {
            return null;
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



