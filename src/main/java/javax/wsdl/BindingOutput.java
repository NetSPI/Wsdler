/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents an output binding. That is, it contains
 * the information that would be specified in an output element
 * contained within an operation element contained within a
 * binding element.
 *
 * @author Matthew J. Duftler
 */
public interface BindingOutput extends WSDLElement
{
  /**
   * Set the name of this output binding.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this output binding.
   *
   * @return the output binding name
   */
  public String getName();

}