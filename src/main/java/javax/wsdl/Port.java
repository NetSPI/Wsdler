/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

/**
 * This interface represents a port, an endpoint for the
 * functionality described by a particular port type.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public interface Port extends WSDLElement
{
  /**
   * Set the name of this port.
   *
   * @param name the desired name
   */
  public void setName(String name);

  /**
   * Get the name of this port.
   *
   * @return the port name
   */
  public String getName();

  /**
   * Set the binding this port should refer to.
   *
   * @param binding the desired binding
   */
  public void setBinding(Binding binding);

  /**
   * Get the binding this port refers to.
   *
   * @return the binding associated with this port
   */
  public Binding getBinding();
}