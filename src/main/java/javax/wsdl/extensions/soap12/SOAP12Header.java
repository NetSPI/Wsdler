/*
 * (c) Copyright IBM Corp 2006 
 */

package javax.wsdl.extensions.soap12;

import java.util.*;
import javax.wsdl.extensions.*;
import javax.xml.namespace.*;

/**
 * Based on javax.wsdl.extensions.SOAPHeader.
 */
public interface SOAP12Header extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the message for this SOAP header.
   *
   * @param message the desired message
   */
  public void setMessage(QName message);

  /**
   * Get the message for this SOAP header.
   */
  public QName getMessage();

  /**
   * Set the part for this SOAP header.
   *
   * @param part the desired part
   */
  public void setPart(String part);

  /**
   * Get the part for this SOAP header.
   */
  public String getPart();

  /**
   * Set the use for this SOAP header.
   *
   * @param use the desired use
   */
  public void setUse(String use);

  /**
   * Get the use for this SOAP header.
   */
  public String getUse();

  /**
   * Set the encodingStyle for this SOAP header.
   *
   * @param encodingStyle the desired encodingStyle
   */
  public void setEncodingStyle(String encodingStyle);

  /**
   * Get the encodingStyle for this SOAP header.
   */
  public String getEncodingStyle();

  /**
   * Set the namespace URI for this SOAP header.
   *
   * @param namespaceURI the desired namespace URI
   */
  public void setNamespaceURI(String namespaceURI);

  /**
   * Get the namespace URI for this SOAP header.
   */
  public String getNamespaceURI();

  /**
   * Add a SOAP header fault.
   * 
   * @param soap12HeaderFault the SOAP Header fault to be added.
   */
  public void addSOAP12HeaderFault(SOAP12HeaderFault soap12HeaderFault);

  /**
   * Get a list of all SOAP header faults contained in this SOAP header.
   * 
   * @return a list of all SOAP header faults contained in this SOAP header.
   */
  public List getSOAP12HeaderFaults();

  /**
   * Remove a SOAP header fault.
   * 
   * @param soap12HeaderFault the SOAP header fault to be removed.
   * @return the SOAP header fault which was removed.
   */
  public SOAP12HeaderFault removeSOAP12HeaderFault(SOAP12HeaderFault soap12HeaderFault);
}