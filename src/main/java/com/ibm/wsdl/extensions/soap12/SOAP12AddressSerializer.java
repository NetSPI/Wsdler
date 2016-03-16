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
 * Copied from com.ibm.wsdl.extensions.soap.SOAPAddressSerializer
 */
public class SOAP12AddressSerializer implements ExtensionSerializer,
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
    SOAP12Address soapAddress = (SOAP12Address)extension;

    if (soapAddress != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAP12Constants.NS_URI_SOAP12,
                                   "address",
                                   def);

      pw.print("      <" + tagName);

      DOMUtils.printAttribute(Constants.ATTR_LOCATION,
                              soapAddress.getLocationURI(),
                              pw);

      Boolean required = soapAddress.getRequired();

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
    SOAP12Address soapAddress = (SOAP12Address)extReg.createExtension(parentType,
                                                                  elementType);
    String locationURI = DOMUtils.getAttribute(el, Constants.ATTR_LOCATION);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (locationURI != null)
    {
      soapAddress.setLocationURI(locationURI);
    }

    if (requiredStr != null)
    {
      soapAddress.setRequired(new Boolean(requiredStr));
    }

    return soapAddress;
	}
}