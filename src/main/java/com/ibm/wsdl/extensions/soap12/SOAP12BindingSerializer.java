/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import java.io.*;
import org.w3c.dom.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.xml.*;

/**
 * Copied from com.ibm.wsdl.extensions.soap.SOAPBindingSerializer
 */
public class SOAP12BindingSerializer implements ExtensionSerializer,
                                              ExtensionDeserializer,
                                              Serializable
{
  public static final long serialVersionUID = 1;

  public void marshall(Class parentType,
                       QName elementType,
                       ExtensibilityElement extension,
                       PrintWriter pw,
                       Definition def,
                       ExtensionRegistry extReg)
                         throws WSDLException
  {
    SOAP12Binding soapBinding = (SOAP12Binding)extension;

    if (soapBinding != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAP12Constants.NS_URI_SOAP12,
                                   "binding",
                                   def);

      pw.print("    <" + tagName);

      DOMUtils.printAttribute(SOAP12Constants.ATTR_STYLE,
                              soapBinding.getStyle(),
                              pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_TRANSPORT,
                              soapBinding.getTransportURI(),
                              pw);

      Boolean required = soapBinding.getRequired();

      if (required != null)
      {
        DOMUtils.printQualifiedAttribute(Constants.Q_ATTR_REQUIRED,
                                         required.toString(),
                                         def,
                                         pw);
      }

      pw.println("/>");
    }
  }

  public ExtensibilityElement unmarshall(Class parentType,
                                         QName elementType,
                                         Element el,
                                         Definition def,
                                         ExtensionRegistry extReg)
                                           throws WSDLException
  {
    SOAP12Binding soapBinding = (SOAP12Binding)extReg.createExtension(parentType,
                                                                  elementType);
    String transportURI = DOMUtils.getAttribute(el,
                                                SOAP12Constants.ATTR_TRANSPORT);
    String style = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_STYLE);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (transportURI != null)
    {
      soapBinding.setTransportURI(transportURI);
    }

    if (style != null)
    {
      soapBinding.setStyle(style);
    }

    if (requiredStr != null)
    {
      soapBinding.setRequired(new Boolean(requiredStr));
    }

    return soapBinding;
  }
}