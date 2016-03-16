/*
 * (c) Copyright IBM Corp 2006 
 */

package javax.wsdl.extensions.soap12;

import javax.wsdl.extensions.*;

/**
 * Based on javax.wsdl.extensions.SOAPFault.
 */
public interface SOAP12Fault extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the name for this SOAP fault.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name for this SOAP fault.
   */
  public String getName();

  /**
   * Set the use for this SOAP fault.
   *
   * @param use the desired use
   */
  public void setUse(String use);

  /**
   * Get the use for this SOAP fault.
   */
  public String getUse();

  /**
   * Set the encodingStyle for this SOAP fault.
   *
   * @param encodingStyle the desired encodingStyle
   */
  public void setEncodingStyle(String encodingStyle);

  /**
   * Get the encodingStyle for this SOAP fault.
   */
  public String getEncodingStyle();

  /**
   * Set the namespace URI for this SOAP fault.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI);

  /**
   * Get the namespace URI for this SOAP fault.
   */
  public String getNamespaceURI();
}