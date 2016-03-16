/*
 * (c) Copyright IBM Corp 2006 
 */

package javax.wsdl.extensions.soap12;

import javax.wsdl.extensions.*;

/**
 * Copied from javax.wsdl.extensions.soap.SOAPAddress.
 */
public interface SOAP12Address extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the location URI for this SOAP address.
   *
   * @param locationURI the desired location URI
   */
  public void setLocationURI(String locationURI);

  /**
   * Get the location URI for this SOAP address.
   */
  public String getLocationURI();
}