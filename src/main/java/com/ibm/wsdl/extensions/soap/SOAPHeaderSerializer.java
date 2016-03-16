/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.soap;

import java.io.*;
import java.util.*;
import org.w3c.dom.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.extensions.soap.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.*;
import com.ibm.wsdl.util.xml.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class SOAPHeaderSerializer implements ExtensionSerializer,
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
    SOAPHeader soapHeader = (SOAPHeader)extension;

    if (soapHeader != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAPConstants.NS_URI_SOAP,
                                   "header",
                                   def);

      pw.print("        <" + tagName);

      DOMUtils.printQualifiedAttribute(Constants.ATTR_MESSAGE,
                                       soapHeader.getMessage(),
                                       def,
                                       pw);
      DOMUtils.printAttribute(SOAPConstants.ATTR_PART,
                              soapHeader.getPart(),
                              pw);
      DOMUtils.printAttribute(SOAPConstants.ATTR_USE, soapHeader.getUse(), pw);
      DOMUtils.printAttribute(SOAPConstants.ATTR_ENCODING_STYLE,
                      StringUtils.getNMTokens(soapHeader.getEncodingStyles()),
                      pw);
      DOMUtils.printAttribute(Constants.ATTR_NAMESPACE,
                              soapHeader.getNamespaceURI(),
                              pw);

      Boolean required = soapHeader.getRequired();

      if (required != null)
      {
        DOMUtils.printQualifiedAttribute(Constants.Q_ATTR_REQUIRED,
                                         required.toString(),
                                         def,
                                         pw);
      }

      pw.println('>');

      printSoapHeaderFaults(soapHeader.getSOAPHeaderFaults(), def, pw);

      pw.println("        </" + tagName + '>');
    }
  }

  private static void printSoapHeaderFaults(List soapHeaderFaults,
                                            Definition def,
                                            PrintWriter pw)
                                              throws WSDLException
  {
    if (soapHeaderFaults != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAPConstants.NS_URI_SOAP,
                                   "headerfault",
                                   def);
      Iterator soapHeaderFaultIterator = soapHeaderFaults.iterator();

      while (soapHeaderFaultIterator.hasNext())
      {
        SOAPHeaderFault soapHeaderFault =
          (SOAPHeaderFault)soapHeaderFaultIterator.next();

        if (soapHeaderFault != null)
        {
          pw.print("          <" + tagName);

          DOMUtils.printQualifiedAttribute(Constants.ATTR_MESSAGE,
                                           soapHeaderFault.getMessage(),
                                           def,
                                           pw);
          DOMUtils.printAttribute(SOAPConstants.ATTR_PART,
                                  soapHeaderFault.getPart(),
                                  pw);
          DOMUtils.printAttribute(SOAPConstants.ATTR_USE,
                                  soapHeaderFault.getUse(),
                                  pw);
          DOMUtils.printAttribute(SOAPConstants.ATTR_ENCODING_STYLE,
                StringUtils.getNMTokens(soapHeaderFault.getEncodingStyles()),
                pw);
          DOMUtils.printAttribute(Constants.ATTR_NAMESPACE,
                                  soapHeaderFault.getNamespaceURI(),
                                  pw);

          Boolean required = soapHeaderFault.getRequired();

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
    }
  }

  public ExtensibilityElement unmarshall(Class parentType,
                                         QName elementType,
                                         Element el,
                                         Definition def,
                                         ExtensionRegistry extReg)
                                           throws WSDLException
  {
    SOAPHeader soapHeader = (SOAPHeader)extReg.createExtension(parentType,
                                                               elementType);
    QName message =
      DOMUtils.getQualifiedAttributeValue(el,
                                          Constants.ATTR_MESSAGE,
                                          SOAPConstants.ELEM_HEADER,
                                          false,
                                          def);
    String part = DOMUtils.getAttribute(el, SOAPConstants.ATTR_PART);
    String use = DOMUtils.getAttribute(el, SOAPConstants.ATTR_USE);
    String encStyleStr = DOMUtils.getAttribute(el,
                                          SOAPConstants.ATTR_ENCODING_STYLE);
    String namespaceURI = DOMUtils.getAttribute(el, Constants.ATTR_NAMESPACE);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (message != null)
    {
      soapHeader.setMessage(message);
    }

    if (part != null)
    {
      soapHeader.setPart(part);
    }

    if (use != null)
    {
      soapHeader.setUse(use);
    }

    if (encStyleStr != null)
    {
      soapHeader.setEncodingStyles(StringUtils.parseNMTokens(encStyleStr));
    }

    if (namespaceURI != null)
    {
      soapHeader.setNamespaceURI(namespaceURI);
    }

    if (requiredStr != null)
    {
      soapHeader.setRequired(new Boolean(requiredStr));
    }

    Element tempEl = DOMUtils.getFirstChildElement(el);

    while (tempEl != null)
    {
      if (QNameUtils.matches(SOAPConstants.Q_ELEM_SOAP_HEADER_FAULT, tempEl))
      {
        soapHeader.addSOAPHeaderFault(
          parseSoapHeaderFault(SOAPHeader.class,
                               SOAPConstants.Q_ELEM_SOAP_HEADER_FAULT,
                               tempEl,
                               extReg,
                               def));
      }
      else
      {
        DOMUtils.throwWSDLException(tempEl);
      }

      tempEl = DOMUtils.getNextSiblingElement(tempEl);
    }

    return soapHeader;
  }

  private static SOAPHeaderFault parseSoapHeaderFault(Class parentType,
                                                      QName elementType,
                                                      Element el,
                                                      ExtensionRegistry extReg,
                                                      Definition def)
                                                        throws WSDLException
  {
    SOAPHeaderFault soapHeaderFault =
      (SOAPHeaderFault)extReg.createExtension(parentType, elementType);
    QName message =
      DOMUtils.getQualifiedAttributeValue(el,
                                          Constants.ATTR_MESSAGE,
                                          SOAPConstants.ELEM_HEADER,
                                          false,
                                          def);
    String part = DOMUtils.getAttribute(el, SOAPConstants.ATTR_PART);
    String use = DOMUtils.getAttribute(el, SOAPConstants.ATTR_USE);
    String encStyleStr = DOMUtils.getAttribute(el,
                                          SOAPConstants.ATTR_ENCODING_STYLE);
    String namespaceURI = DOMUtils.getAttribute(el, Constants.ATTR_NAMESPACE);
    String requiredStr = DOMUtils.getAttributeNS(el,
                                                 Constants.NS_URI_WSDL,
                                                 Constants.ATTR_REQUIRED);

    if (message != null)
    {
      soapHeaderFault.setMessage(message);
    }

    if (part != null)
    {
      soapHeaderFault.setPart(part);
    }

    if (use != null)
    {
      soapHeaderFault.setUse(use);
    }

    if (encStyleStr != null)
    {
      soapHeaderFault.setEncodingStyles(
        StringUtils.parseNMTokens(encStyleStr));
    }

    if (namespaceURI != null)
    {
      soapHeaderFault.setNamespaceURI(namespaceURI);
    }

    if (requiredStr != null)
    {
      soapHeaderFault.setRequired(new Boolean(requiredStr));
    }

    return soapHeaderFault;
  }
}
