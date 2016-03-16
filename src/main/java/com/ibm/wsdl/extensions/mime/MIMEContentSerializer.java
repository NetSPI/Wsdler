/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.mime;

import java.io.*;
import org.w3c.dom.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.extensions.mime.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.xml.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class MIMEContentSerializer implements ExtensionSerializer,
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
    MIMEContent mimeContent = (MIMEContent)extension;

    if (mimeContent != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(MIMEConstants.NS_URI_MIME,
                                   "content",
                                   def);

      if (parentType != null
          && MIMEPart.class.isAssignableFrom(parentType))
      {
        pw.print("    ");
      }

      pw.print("        <" + tagName);

      DOMUtils.printAttribute(MIMEConstants.ATTR_PART,
                              mimeContent.getPart(),
                              pw);
      DOMUtils.printAttribute(Constants.ATTR_TYPE,
                              mimeContent.getType(),
                              pw);

      Boolean required = mimeContent.getRequired();

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
    MIMEContent mimeContent = (MIMEContent)extReg.createExtension(parentType,
                                                                  elementType);
    String part = DOMUtils.getAttribute(el, MIMEConstants.ATTR_PART);
    String type = DOMUtils.getAttribute(el, Constants.ATTR_TYPE);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (part != null)
    {
      mimeContent.setPart(part);
    }

    if (type != null)
    {
      mimeContent.setType(type);
    }

    if (requiredStr != null)
    {
      mimeContent.setRequired(new Boolean(requiredStr));
    }

    return mimeContent;
	}
}