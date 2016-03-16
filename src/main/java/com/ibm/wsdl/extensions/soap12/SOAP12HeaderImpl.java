/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import java.util.*;
import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;

/**
 * Based on com.ibm.wsdl.extensions.soap.SOAPHeaderImpl
 */
public class SOAP12HeaderImpl implements SOAP12Header
{
  protected QName elementType = SOAP12Constants.Q_ELEM_SOAP_HEADER;
  protected Boolean required = null;
  protected QName message = null;
  protected String part = null;
  protected String use = null;
  protected String encodingStyle = null;
  protected String namespaceURI = null;
  protected List soapHeaderFaults = new Vector();

  public static final long serialVersionUID = 1;

  /**
   * Set the type of this extensibility element.
   *
   * @param elementType the type
   */
  public void setElementType(QName elementType)
  {
    this.elementType = elementType;
  }

  /**
   * Get the type of this extensibility element.
   *
   * @return the extensibility element's type
   */
  public QName getElementType()
  {
    return elementType;
  }

  /**
   * Set whether or not the semantics of this extension
   * are required. Relates to the wsdl:required attribute.
   */
  public void setRequired(Boolean required)
  {
    this.required = required;
  }

  /**
   * Get whether or not the semantics of this extension
   * are required. Relates to the wsdl:required attribute.
   */
  public Boolean getRequired()
  {
    return required;
  }

  /**
   * Set the message for this SOAP header.
   *
   * @param message the desired message
   */
  public void setMessage(QName message)
  {
    this.message = message;
  }

  /**
   * Get the message for this SOAP header.
   */
  public QName getMessage()
  {
    return message;
  }

  /**
   * Set the part for this SOAP header.
   *
   * @param part the desired part
   */
  public void setPart(String part)
  {
    this.part = part;
  }

  /**
   * Get the part for this SOAP header.
   */
  public String getPart()
  {
    return part;
  }

  /**
   * Set the use for this SOAP header.
   *
   * @param use the desired use
   */
  public void setUse(String use)
  {
    this.use = use;
  }

  /**
   * Get the use for this SOAP header.
   */
  public String getUse()
  {
    return use;
  }

  /**
   * Set the encodingStyle for this SOAP header.
   *
   * @param encodingStyle the desired encodingStyle
   */
  public void setEncodingStyle(String encodingStyle)
  {
    this.encodingStyle = encodingStyle;
  }

  /**
   * Get the encodingStyle for this SOAP header.
   */
  public String getEncodingStyle()
  {
    return encodingStyle;
  }

  /**
   * Set the namespace URI for this SOAP header.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI)
  {
    this.namespaceURI = namespaceURI;
  }

  /**
   * Get the namespace URI for this SOAP header.
   */
  public String getNamespaceURI()
  {
    return namespaceURI;
  }

  public void addSOAP12HeaderFault(SOAP12HeaderFault soap12HeaderFault)
  {
    soapHeaderFaults.add(soap12HeaderFault);
  }
  
  public SOAP12HeaderFault removeSOAP12HeaderFault(SOAP12HeaderFault soap12HeaderFault)
  {
    if(soapHeaderFaults.remove(soap12HeaderFault))
      return soap12HeaderFault;
    else
      return null;
  }

  public List getSOAP12HeaderFaults()
  {
    return soapHeaderFaults;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SOAPHeader (" + elementType + "):");
    strBuf.append("\nrequired=" + required);

    if (message != null)
    {
      strBuf.append("\nmessage=" + message);
    }

    if (part != null)
    {
      strBuf.append("\npart=" + part);
    }

    if (use != null)
    {
      strBuf.append("\nuse=" + use);
    }

    if (encodingStyle != null)
    {
      strBuf.append("\nencodingStyle=" + encodingStyle);
    }

    if (namespaceURI != null)
    {
      strBuf.append("\nnamespaceURI=" + namespaceURI);
    }

    if (soapHeaderFaults != null)
    {
      strBuf.append("\nsoapHeaderFaults=" + soapHeaderFaults);
    }

    return strBuf.toString();
  }
}