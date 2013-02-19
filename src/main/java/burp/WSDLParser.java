package burp;

import com.centeractive.ws.builder.SoapBuilder;
import com.centeractive.ws.builder.SoapOperation;
import com.centeractive.ws.builder.core.SoapUtils;
import com.centeractive.ws.builder.core.WsdlParser;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.util.ArrayList;
import java.util.List;

import javax.wsdl.BindingOperation;
import javax.xml.namespace.QName;

public class WSDLParser {

  private WSDLTab tab;
  private IExtensionHelpers helpers;
  private IBurpExtenderCallbacks callbacks;

  public WSDLParser(IBurpExtenderCallbacks callbacks, IExtensionHelpers helpers) {
    this.helpers = helpers;
    this.callbacks = callbacks;
    tab = new WSDLTab(callbacks);
  }

  public void parseWSDL(IHttpRequestResponse requestResponse) {
    File temp;
    temp = createTempFile(requestResponse);

    WsdlParser parser = WsdlParser.parse(temp.toURI().toString());
    temp.delete();
    List<QName> bindings = parser.getBindings();
    SoapBuilder builder;
    List<SoapOperation> operations;
    SoapOperation operation;
    String bindingName;
    String operationName;
    byte[] xmlRequest;
    List<String> endpoints;
    for (QName i : bindings) {
      bindingName = i.getLocalPart();
      builder = parser.binding().localPart(bindingName).builder();
      operations = builder.getOperations();
      for (SoapOperation j : operations) {
        operationName = j.getOperationName();
        operation = builder.operation().name(operationName).find();
        xmlRequest = createRequest(requestResponse, builder, operation);
        endpoints = builder.getServiceUrls();
        tab.addEntry(new WSDLEntry(bindingName, xmlRequest, operationName, endpoints, requestResponse));
      }
    }
  }

  private File createTempFile(IHttpRequestResponse requestResponse) {
    IHttpRequestResponse response = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
    while (response.getResponse().length < 200) {
      response = callbacks.makeHttpRequest(requestResponse.getHttpService(), requestResponse.getRequest());
    }
     int offset = helpers.analyzeResponse(response.getResponse()).getBodyOffset();
    String body = new String(response.getResponse(), offset, response.getResponse().length - offset);
    File temp = null;
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

    String message = builder.buildInputMessage(operation);
    String endpointURL = getEndPoint(builder.getServiceUrls().get(0), requestResponse);
    BindingOperation
        soapActionOperation =
        builder.getBinding().getBindingOperation(builder.getOperationBuilder(operation).getOperationName(), builder.getOperationBuilder(operation).getOperationInputName(),
                                                 builder.getOperationBuilder(operation).getOperationOutputName());

    List<String> headers = new ArrayList<String>();

    headers.add("POST " + endpointURL + " HTTP/1.1");
    headers.add("Accept-Encoding: gzip,deflate");
    headers.add("Content-Type: text/xml;charset=UTF-8");
    headers.add("SOAPAction: " + SoapUtils.getSOAPActionUri(soapActionOperation));
    headers.add("Host: " + requestResponse.getHttpService().getHost());

    return helpers.buildHttpMessage(headers, message.getBytes());
  }

  private String getEndPoint(String endpoint, IHttpRequestResponse requestResponse) {

    int index = endpoint.indexOf("//") + 2;
    String j = endpoint.substring(index, endpoint.length());

    j = j.replace(requestResponse.getHttpService().getHost(), "");

    return j;
  }

}
