/*
 * (c) Copyright IBM Corp 20016 
 */

package javax.wsdl.extensions.soap12;

import javax.wsdl.extensions.*;

/**
 * Copied from javax.wsdl.extensions.soap.SOAPBinding.
 */
public interface SOAP12Binding extends ExtensibilityElement, java.io.Serializable
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