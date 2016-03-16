/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions.soap;

import javax.wsdl.extensions.*;

/**
 * This class stores information associated with a SOAP operation that
 * acts as the concrete implementation of an abstract operation specified
 * in WSDL.
 *
 * @author Nirmal Mukhi (nmukhi@us.ibm.com)
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface SOAPOperation extends ExtensibilityElement,
                                       java.io.Serializable
{
	/**
	 * Set the SOAP action attribute.
   *
	 * @param soapActionURI the desired value of the SOAP
	 * action header for this operation.
	 */
	public void setSoapActionURI(String soapActionURI);

	/**
	 * Get the value of the SOAP action attribute.
   *
	 * @return the SOAP action attribute's value
	 */
	public String getSoapActionURI();

  /**
   * Set the style for this SOAP operation.
   *
   * @param style the desired style
   */
  public void setStyle(String style);

  /**
   * Get the style for this SOAP operation.
   */
  public String getStyle();
}