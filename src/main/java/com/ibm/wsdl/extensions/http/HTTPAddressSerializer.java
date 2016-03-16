/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.http;

import java.io.*;
import org.w3c.dom.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.extensions.http.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.xml.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class HTTPAddressSerializer implements ExtensionSerializer,
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
    HTTPAddress httpAddress = (HTTPAddress)extension;

    if (httpAddress != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(HTTPConstants.NS_URI_HTTP,
                                   "address",
                                   def);

      pw.print("      <" + tagName);

      DOMUtils.printAttribute(Constants.ATTR_LOCATION,
                              httpAddress.getLocationURI(),
                              pw);

      Boolean required = httpAddress.getRequired();

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
    HTTPAddress httpAddress = (HTTPAddress)extReg.createExtension(parentType,
                                                                  elementType);
    String locationURI = DOMUtils.getAttribute(el, Constants.ATTR_LOCATION);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (locationURI != null)
    {
      httpAddress.setLocationURI(locationURI);
    }

    if (requiredStr != null)
    {
      httpAddress.setRequired(new Boolean(requiredStr));
    }

    return httpAddress;
	}
}