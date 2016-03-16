/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions.mime;

import javax.wsdl.extensions.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface MIMEMimeXml extends ExtensibilityElement, java.io.Serializable
{
  /**
   * Set the part for this MIME mimeXml.
   *
   * @param part the desired part
   */
  public void setPart(String part);

  /**
   * Get the part for this MIME mimeXml.
   */
  public String getPart();
}