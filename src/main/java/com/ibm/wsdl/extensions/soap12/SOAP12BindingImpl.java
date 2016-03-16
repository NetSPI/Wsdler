/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;

/**
 * Copied from com.ibm.wsdl.extensions.soap.SOAPBindingImpl
 */
public class SOAP12BindingImpl implements SOAP12Binding
{
  protected QName elementType = SOAP12Constants.Q_ELEM_SOAP_BINDING;
  protected Boolean required = null;
  protected String style = null;
  protected String transportURI = null;

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
   * Set the style for this SOAP binding.
   *
   * @param style the desired style
   */
  public void setStyle(String style)
  {
    this.style = style;
  }

  /**
   * Get the style for this SOAP binding.
   */
  public String getStyle()
  {
    return style;
  }

  /**
   * Set the SOAP transport URI to be used for communicating 
   * with this binding.
   *
   * @param transportURI the URI describing the transport 
   * to be used
   */
  public void setTransportURI(String transportURI)
  {
    this.transportURI = transportURI;
  }

  /**
   * Get the transport URI to be used with this binding.
   *
   * @return the transport URI to be used
   */
  public String getTransportURI()
  {
    return transportURI;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SOAPBinding (" + elementType + "):");
    strBuf.append("\nrequired=" + required);

    if (transportURI != null)
    {
      strBuf.append("\ntransportURI=" + transportURI);
    }

    if (style != null)
    {
      strBuf.append("\nstyle=" + style);
    }

    return strBuf.toString();
  }
}