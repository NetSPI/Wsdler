/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl.extensions.soap;

import java.util.*;
import javax.wsdl.extensions.soap.*;
import javax.xml.namespace.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class SOAPHeaderImpl implements SOAPHeader
{
  protected QName elementType = SOAPConstants.Q_ELEM_SOAP_HEADER;
  protected Boolean required = null;
  protected QName message = null;
  protected String part = null;
  protected String use = null;
  protected List encodingStyles = null;
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
   * Set the encodingStyles for this SOAP header.
   *
   * @param encodingStyles the desired encodingStyles
   */
  public void setEncodingStyles(List encodingStyles)
  {
    this.encodingStyles = encodingStyles;
  }

  /**
   * Get the encodingStyles for this SOAP header.
   */
  public List getEncodingStyles()
  {
    return encodingStyles;
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

  public void addSOAPHeaderFault(SOAPHeaderFault soapHeaderFault)
  {
    soapHeaderFaults.add(soapHeaderFault);
  }
  
  public SOAPHeaderFault removeSOAPHeaderFault(SOAPHeaderFault soapHeaderFault)
  {
    if(soapHeaderFaults.remove(soapHeaderFault))
      return soapHeaderFault;
    else
      return null;
  }

  public List getSOAPHeaderFaults()
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

    if (encodingStyles != null)
    {
      strBuf.append("\nencodingStyles=" + encodingStyles);
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