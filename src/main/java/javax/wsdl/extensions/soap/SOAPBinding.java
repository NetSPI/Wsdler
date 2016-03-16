/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions.soap;

import javax.wsdl.extensions.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface SOAPBinding extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the style for this SOAP binding.
   *
   * @param style the desired style
   */
  public void setStyle(String style);

  /**
   * Get the style for this SOAP binding.
   */
  public String getStyle();

  /**
   * Set the SOAP transport URI to be used for communicating 
   * with this binding.
   *
   * @param transportURI the URI describing the transport 
   * to be used
   */
  public void setTransportURI(String transportURI);

  /**
   * Get the transport URI to be used with this binding.
   *
   * @return the transport URI to be used
   */
  public String getTransportURI();
}