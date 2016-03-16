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
 * Based on com.ibm.wsdl.extensions.soap.SOAPFaultSerializer
 */
public class SOAP12FaultSerializer implements ExtensionSerializer,
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
    SOAP12Fault soapFault = (SOAP12Fault)extension;

    if (soapFault != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAP12Constants.NS_URI_SOAP12,
                                   "fault",
                                   def);

      pw.print("        <" + tagName);

      DOMUtils.printAttribute(Constants.ATTR_NAME, soapFault.getName(), pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_USE, soapFault.getUse(), pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_ENCODING_STYLE,
                      soapFault.getEncodingStyle(),
                      pw);
      DOMUtils.printAttribute(Constants.ATTR_NAMESPACE,
                              soapFault.getNamespaceURI(),
                              pw);

      Boolean required = soapFault.getRequired();

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
    SOAP12Fault soapFault = (SOAP12Fault)extReg.createExtension(parentType,
                                                            elementType);
    //TODO: remove unused variable, message
    QName message = DOMUtils.getQualifiedAttributeValue(el,
                                                    Constants.ATTR_MESSAGE,
                                                    SOAP12Constants.ELEM_HEADER,
                                                    false,
                                                    def);
    String name = DOMUtils.getAttribute(el, Constants.ATTR_NAME);
    String use = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_USE);
    String encStyleStr = DOMUtils.getAttribute(el,
                                          SOAP12Constants.ATTR_ENCODING_STYLE);
    String namespaceURI = DOMUtils.getAttribute(el,
                                                Constants.ATTR_NAMESPACE);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (name != null)
    {
      soapFault.setName(name);
    }

    if (use != null)
    {
      soapFault.setUse(use);
    }

    if (encStyleStr != null)
    {
      soapFault.setEncodingStyle(encStyleStr);
    }

    if (namespaceURI != null)
    {
      soapFault.setNamespaceURI(namespaceURI);
    }

    if (requiredStr != null)
    {
      soapFault.setRequired(new Boolean(requiredStr));
    }

    return soapFault;
  }
}
