/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

import java.util.*;
import javax.xml.namespace.*;

/**
 * This interface represents a port type binding and describes the
 * protocol required for using operations in a port type.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public interface Binding extends WSDLElement
{
  /**
   * Set the name of this binding.
   *
   * @param name the desired name
   */
  public void setQName(QName name);

  /**
   * Get the name of this binding.
   *
   * @return the binding name
   */
  public QName getQName();

  /**
   * Set the port type this is a binding for.
   *
   * @param portType the port type associated with this binding
   */
  public void setPortType(PortType portType);

  /**
   * Get the port type this is a binding for.
   *
   * @return the associated port type
   */
  public PortType getPortType();

  /**
   * Add an operation binding to binding.
   *
   * @param bindingOperation the operation binding to be added
   */
  public void addBindingOperation(BindingOperation bindingOperation);
  
  /**
   * Get the specified operation binding. Note that operation names can
   * be overloaded within a PortType. In case of overloading, the
   * names of the input and output messages can be used to further
   * refine the search.
   * <p>
   * The search criteria will be the operation name parameter and any 
   * non-null input or output message name parameters. 
   * To exclude the input or output message name from the search criteria,
   * specify a null value for the input or output message name parameter.
   * To search for operations with unnamed input or output messages 
   * (i.e. &lt;input&gt; or &lt;output&gt; elements with the 'name' attribute omitted), 
   * specify the string "<code>:none</code>" for the input or output message name parameter.
   * <p>
   * Note: the use of a string value "<code>:none</code>" rather than null to search for 
   * unnamed input or output messages is necessary to retain backward compatibility
   * with earlier versions of the JWSDL API, which defined a null value to
   * mean 'ignore this parameter'.
   * The colon in "<code>:none</code>" is to avoid name clashes with input or output
   * message names, which must be of type NCName (i.e. they cannot contain colons). 
   *
   * @param name the name of the desired operation binding.
   * @param inputName the name of the input message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an input 
   * message without a name.
   * @param outputName the name of the output message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an output 
   * message without a name.
   * @return the corresponding operation binding, or null if there wasn't
   * any matching operation binding
   * 
   * @throws IllegalArgumentException if duplicate operations are found.
   */
  public BindingOperation getBindingOperation(String name,
                                              String inputName,
                                              String outputName);

  /**
   * Get all the operation bindings defined here.
   */
  public List getBindingOperations();

  /**
   * Remove the specified operation binding. Note that operation names can
   * be overloaded within a PortType. In case of overloading, the
   * names of the input and output messages can be used to further
   * refine the search.
   * <p>
   * Usage of the input and output message name parameters is as 
   * described for the <code>getBindingOperation</code> method.
   *
   * @param name the name of the operation binding to be removed.
   * @param inputName the name of the input message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an input 
   * message without a name.
   * @param outputName the name of the output message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an output 
   * message without a name.
   * @return the binding operation which was removed, or null if there wasn't
   * any matching operation
   * 
   * @throws IllegalArgumentException if duplicate operations are found.
   * 
   * @see #getBindingOperation(String, String, String) 
   */
  public BindingOperation removeBindingOperation(String name,
                                                 String inputName,
                                                 String outputName);

  public void setUndefined(boolean isUndefined);

  public boolean isUndefined();
}