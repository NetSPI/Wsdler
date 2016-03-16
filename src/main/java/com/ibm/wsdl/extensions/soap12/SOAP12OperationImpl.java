/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import javax.wsdl.extensions.soap12.*;
import javax.xml.namespace.*;

/**
 * Based on com.ibm.wsdl.extensions.soap.SOAPOperationImpl
 */
public class SOAP12OperationImpl implements SOAP12Operation
{
  protected QName elementType = SOAP12Constants.Q_ELEM_SOAP_OPERATION;
  protected Boolean required = null;
  protected String soapActionURI = null;
  protected Boolean soapActionRequired = null;
  protected String style = null;

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
   * Set the SOAP action attribute.
   *
   * @param soapActionURI the desired value of the SOAP
   * action header for this operation.
   */
  public void setSoapActionURI(String soapActionURI)
  {
    this.soapActionURI = soapActionURI;
  }

  /**
   * Get the value of the SOAP action attribute.
   *
   * @return the SOAP action attribute's value
   */
  public String getSoapActionURI()
  {
    return soapActionURI;
  }

  /**
   * Specify whether the SOAP Action is required for this operation.
   *
   * @param soapActionRequired true if the SOAP Action is required, otherwise false.
   */
  public void setSoapActionRequired(Boolean soapActionRequired)
  {
    this.soapActionRequired = soapActionRequired;
  }

  /**
   * Indicates whether the SOAP Action is required for this operation.
   *
   * @return true if the SOAP action is required, otherwise false.
   */
  public Boolean getSoapActionRequired()
  {
    return soapActionRequired;
  }
  
  /**
   * Set the style for this SOAP operation.
   *
   * @param style the desired style
   */
  public void setStyle(String style)
  {
    this.style = style;
  }

  /**
   * Get the style for this SOAP operation.
   */
  public String getStyle()
  {
    return style;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SOAPOperation (" + elementType + "):");
    strBuf.append("\nrequired=" + required);

    if (soapActionURI != null)
    {
      strBuf.append("\nsoapActionURI=" + soapActionURI);
    }
    
    if (soapActionRequired != null)
    {
      strBuf.append("\nsoapActionRequired=" + soapActionRequired);
    }

    if (style != null)
    {
      strBuf.append("\nstyle=" + style);
    }

    return strBuf.toString();
  }
}