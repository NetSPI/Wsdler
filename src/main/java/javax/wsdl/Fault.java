/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents a fault message, and contains the name
 * of the fault and the message itself.
 *
 * @author Matthew J. Duftler
 */
public interface Fault extends WSDLElement
{
  /**
   * Set the name of this fault message.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this fault message.
   *
   * @return the fault message name
   */
  public String getName();

  public void setMessage(Message message);

  public Message getMessage();
}