/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;

/**
 * Based on com.ibm.wsdl.extensions.soap.SOAPHeaderFaultImpl
 */
public class SOAP12HeaderFaultImpl implements SOAP12HeaderFault
{
  protected QName elementType = SOAP12Constants.Q_ELEM_SOAP_HEADER_FAULT;
  protected Boolean required = null;
  protected QName message = null;
  protected String part = null;
  protected String use = null;
  protected String encodingStyle = null;
  protected String namespaceURI = null;

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
   * Set the message for this SOAP header fault.
   *
   * @param message the desired message
   */
  public void setMessage(QName message)
  {
    this.message = message;
  }

  /**
   * Get the message for this SOAP header fault.
   */
  public QName getMessage()
  {
    return message;
  }

  /**
   * Set the part for this SOAP header fault.
   *
   * @param part the desired part
   */
  public void setPart(String part)
  {
    this.part = part;
  }

  /**
   * Get the part for this SOAP header fault.
   */
  public String getPart()
  {
    return part;
  }

  /**
   * Set the use for this SOAP header fault.
   *
   * @param use the desired use
   */
  public void setUse(String use)
  {
    this.use = use;
  }

  /**
   * Get the use for this SOAP header fault.
   */
  public String getUse()
  {
    return use;
  }

  /**
   * Set the encodingStyle for this SOAP header fault.
   *
   * @param encodingStyle the desired encodingStyle
   */
  public void setEncodingStyle(String encodingStyle)
  {
    this.encodingStyle = encodingStyle;
  }

  /**
   * Get the encodingStyle for this SOAP header fault.
   */
  public String getEncodingStyle()
  {
    return encodingStyle;
  }

  /**
   * Set the namespace URI for this SOAP header fault.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI)
  {
    this.namespaceURI = namespaceURI;
  }

  /**
   * Get the namespace URI for this SOAP header fault.
   */
  public String getNamespaceURI()
  {
    return namespaceURI;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SOAPHeaderFault (" + elementType + "):");
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
      strBuf.append("\nencodingStyles=" + encodingStyle);
    }

    if (namespaceURI != null)
    {
      strBuf.append("\nnamespaceURI=" + namespaceURI);
    }

    return strBuf.toString();
  }
}