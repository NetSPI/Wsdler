/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents an input binding. That is, it contains
 * the information that would be specified in an input element
 * contained within an operation element contained within a
 * binding element.
 *
 * @author Matthew J. Duftler
 */
public interface BindingInput extends WSDLElement
{
  /**
   * Set the name of this input binding.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this input binding.
   *
   * @return the input binding name
   */
  public String getName();

}