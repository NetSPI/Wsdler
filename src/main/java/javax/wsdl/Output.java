/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents an output message, and contains the name
 * of the output and the message itself.
 *
 * @author Matthew J. Duftler
 */
public interface Output extends WSDLElement
{
  /**
   * Set the name of this output message.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this output message.
   *
   * @return the output message name
   */
  public String getName();

  public void setMessage(Message message);

  public Message getMessage();
}