/*
 * (c) Copyright IBM Corp 2006 
 */

package javax.wsdl.extensions.soap12;

import java.util.*;
import javax.wsdl.extensions.*;

/**
 * Based on javax.wsdl.extensions.SOAPBody.
 */
public interface SOAP12Body extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the parts for this SOAP body.
   *
   * @param parts the desired parts
   */
  public void setParts(List parts);

  /**
   * Get the parts for this SOAP body.
   */
  public List getParts();

  /**
   * Set the use for this SOAP body.
   *
   * @param use the desired use
   */
  public void setUse(String use);

  /**
   * Get the use for this SOAP body.
   */
  public String getUse();

  /**
   * Set the encodingStyle for this SOAP body.
   *
   * @param encodingStyle the desired encodingStyle
   */
  public void setEncodingStyle(String encodingStyle);

  /**
   * Get the encodingStyle for this SOAP body.
   */
  public String getEncodingStyle();

  /**
   * Set the namespace URI for this SOAP body.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI);

  /**
   * Get the namespace URI for this SOAP body.
   */
  public String getNamespaceURI();
}