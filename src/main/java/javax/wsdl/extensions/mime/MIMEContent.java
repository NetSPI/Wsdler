/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions.mime;

import javax.wsdl.extensions.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface MIMEContent extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the part for this MIME content.
   *
   * @param part the desired part
   */
  public void setPart(String part);

  /**
   * Get the part for this MIME content.
   */
  public String getPart();

  /**
   * Set the type for this MIME content.
   *
   * @param type the desired type
   */
  public void setType(String type);

  /**
   * Get the type for this MIME content.
   */
  public String getType();
}