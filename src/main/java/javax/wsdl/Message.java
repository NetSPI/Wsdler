/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

import java.util.*;
import javax.xml.namespace.QName;

/**
 * This interface describes a message used for communication with an operation.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public interface Message extends WSDLElement
{
  /**
   * Set the name of this message.
   *
   * @param name the desired name
   */
  public void setQName(QName name);

  /**
   * Get the name of this message.
   *
   * @return the message name
   */
  public QName getQName();

  /**
   * Add a part to this message.
   *
   * @param part the part to be added
   */
  public void addPart(Part part);

  /**
   * Get the specified part.
   *
   * @param name the name of the desired part.
   * @return the corresponding part, or null if there wasn't
   * any matching part
   */
  public Part getPart(String name);

  /**
   * Remove the specified part.
   *
   * @param name the name of the part to be removed.
   * @return the part which was removed
   */
  public Part removePart(String name);

  /**
   * Get all the parts defined here.
   */
  public Map getParts();

  /**
   * Get an ordered list of parts as specified by the partOrder
   * argument.
   *
   * @param partOrder a list of strings, with each string referring
   * to a part by its name. If this argument is null, the parts are
   * returned in the order in which they were added to the message.
   * @return the list of parts
   */
  public List getOrderedParts(List partOrder);

  public void setUndefined(boolean isUndefined);

  public boolean isUndefined();
}