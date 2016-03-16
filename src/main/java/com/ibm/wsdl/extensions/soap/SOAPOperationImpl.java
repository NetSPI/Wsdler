/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.soap;

import javax.wsdl.extensions.soap.*;
import javax.xml.namespace.*;

/**
 * This class stores information associated with a SOAP operation that
 * acts as the concrete implementation of an abstract operation specified
 * in WSDL.
 *
 * @author Nirmal Mukhi (nmukhi@us.ibm.com)
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class SOAPOperationImpl implements SOAPOperation
{
  protected QName elementType = SOAPConstants.Q_ELEM_SOAP_OPERATION;
  protected Boolean required = null;
	protected String soapActionURI = null;
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

    if (style != null)
    {
      strBuf.append("\nstyle=" + style);
    }

    return strBuf.toString();
  }
}