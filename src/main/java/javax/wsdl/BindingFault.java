/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents a fault binding. That is, it contains
 * the information that would be specified in a fault element
 * contained within an operation element contained within a
 * binding element.
 *
 * @author Matthew J. Duftler
 */
public interface BindingFault extends WSDLElement
{
  /**
   * Set the name of this fault binding.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this fault binding.
   *
   * @return the fault binding name
   */
  public String getName();

}