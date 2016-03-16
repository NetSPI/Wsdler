/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import java.io.*;
import java.util.*;
import org.w3c.dom.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.xml.*;

/**
 * Based on com.ibm.wsdl.extensions.soap.SOAPHeaderSerializer
 */
public class SOAP12HeaderSerializer implements ExtensionSerializer,
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
    SOAP12Header soapHeader = (SOAP12Header)extension;

    if (soapHeader != null)
    {
      String tagName =
        DOMUtils.getQualifiedValue(SOAP12Constants.NS_URI_SOAP12,
                                   "header",
                                   def);

      pw.print("        <" + tagName);

      DOMUtils.printQualifiedAttribute(Constants.ATTR_MESSAGE,
                                       soapHeader.getMessage(),
                                       def,
                                       pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_PART,
                              soapHeader.getPart(),
                              pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_USE, soapHeader.getUse(), pw);
      DOMUtils.printAttribute(SOAP12Constants.ATTR_ENCODING_STYLE,
                      soapHeader.getEncodingStyle(),
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

      printSoapHeaderFaults(soapHeader.getSOAP12HeaderFaults(), def, pw);

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
        DOMUtils.getQualifiedValue(SOAP12Constants.NS_URI_SOAP12,
                                   "headerfault",
                                   def);
      Iterator soapHeaderFaultIterator = soapHeaderFaults.iterator();

      while (soapHeaderFaultIterator.hasNext())
      {
        SOAP12HeaderFault soapHeaderFault =
          (SOAP12HeaderFault)soapHeaderFaultIterator.next();

        if (soapHeaderFault != null)
        {
          pw.print("          <" + tagName);

          DOMUtils.printQualifiedAttribute(Constants.ATTR_MESSAGE,
                                           soapHeaderFault.getMessage(),
                                           def,
                                           pw);
          DOMUtils.printAttribute(SOAP12Constants.ATTR_PART,
                                  soapHeaderFault.getPart(),
                                  pw);
          DOMUtils.printAttribute(SOAP12Constants.ATTR_USE,
                                  soapHeaderFault.getUse(),
                                  pw);
          DOMUtils.printAttribute(SOAP12Constants.ATTR_ENCODING_STYLE,
                soapHeaderFault.getEncodingStyle(),
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
    SOAP12Header soapHeader = (SOAP12Header)extReg.createExtension(parentType,
                                                               elementType);
    QName message =
      DOMUtils.getQualifiedAttributeValue(el,
                                          Constants.ATTR_MESSAGE,
                                          SOAP12Constants.ELEM_HEADER,
                                          false,
                                          def);
    String part = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_PART);
    String use = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_USE);
    String encStyleStr = DOMUtils.getAttribute(el,
                                          SOAP12Constants.ATTR_ENCODING_STYLE);
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
      soapHeader.setEncodingStyle(encStyleStr);
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
      if (QNameUtils.matches(SOAP12Constants.Q_ELEM_SOAP_HEADER_FAULT, tempEl))
      {
        soapHeader.addSOAP12HeaderFault(
          parseSoapHeaderFault(SOAP12Header.class,
                               SOAP12Constants.Q_ELEM_SOAP_HEADER_FAULT,
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

  private static SOAP12HeaderFault parseSoapHeaderFault(Class parentType,
                                                      QName elementType,
                                                      Element el,
                                                      ExtensionRegistry extReg,
                                                      Definition def)
                                                        throws WSDLException
  {
    SOAP12HeaderFault soapHeaderFault =
      (SOAP12HeaderFault)extReg.createExtension(parentType, elementType);
    QName message =
      DOMUtils.getQualifiedAttributeValue(el,
                                          Constants.ATTR_MESSAGE,
                                          SOAP12Constants.ELEM_HEADER,
                                          false,
                                          def);
    String part = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_PART);
    String use = DOMUtils.getAttribute(el, SOAP12Constants.ATTR_USE);
    String encStyleStr = DOMUtils.getAttribute(el,
                                          SOAP12Constants.ATTR_ENCODING_STYLE);
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
      soapHeaderFault.setEncodingStyle(encStyleStr);
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
