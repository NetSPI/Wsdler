/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.soap;

import java.util.*;
import javax.wsdl.extensions.soap.*;
import javax.xml.namespace.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class SOAPBodyImpl implements SOAPBody
{
  protected QName elementType = SOAPConstants.Q_ELEM_SOAP_BODY;
  protected Boolean required = null;
  protected List parts = null;
  protected String use = null;
  protected List encodingStyles = null;
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
   * Set the parts for this SOAP body.
   *
   * @param parts the desired parts
   */
  public void setParts(List parts)
  {
    this.parts = parts;
  }

  /**
   * Get the parts for this SOAP body.
   */
  public List getParts()
  {
    return parts;
  }

  /**
   * Set the use for this SOAP body.
   *
   * @param use the desired use
   */
  public void setUse(String use)
  {
    this.use = use;
  }

  /**
   * Get the use for this SOAP body.
   */
  public String getUse()
  {
    return use;
  }

  /**
   * Set the encodingStyles for this SOAP body.
   *
   * @param encodingStyles the desired encodingStyles
   */
  public void setEncodingStyles(List encodingStyles)
  {
    this.encodingStyles = encodingStyles;
  }

  /**
   * Get the encodingStyles for this SOAP body.
   */
  public List getEncodingStyles()
  {
    return encodingStyles;
  }

  /**
   * Set the namespace URI for this SOAP body.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI)
  {
    this.namespaceURI = namespaceURI;
  }

  /**
   * Get the namespace URI for this SOAP body.
   */
  public String getNamespaceURI()
  {
    return namespaceURI;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SOAPBody (" + elementType + "):");
    strBuf.append("\nrequired=" + required);

    if (parts != null)
    {
      strBuf.append("\nparts=" + parts);
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

    return strBuf.toString();
  }
}