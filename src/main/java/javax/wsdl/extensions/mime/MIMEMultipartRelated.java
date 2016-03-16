/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl.extensions.mime;

import java.util.*;
import javax.wsdl.extensions.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface MIMEMultipartRelated extends ExtensibilityElement,
                                              java.io.Serializable
{
  /**
   * Add a MIME part to this MIME multipart related.
   *
   * @param mimePart the MIME part to be added
   */
  public void addMIMEPart(MIMEPart mimePart);
  
  /**
   * Remove a MIME part to this MIME multipart related.
   *
   * @param mimePart the MIME part to be remove.
   * @return the MIME part which was removed.
   */
  public MIMEPart removeMIMEPart(MIMEPart mimePart);

  /**
   * Get all the MIME parts defined here.
   */
  public List getMIMEParts();
}