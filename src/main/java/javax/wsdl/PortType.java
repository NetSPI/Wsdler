/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

import java.util.*;
import javax.xml.namespace.*;

/**
 * This interface represents a port type. It contains information about
 * operations associated with this port type.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public interface PortType extends WSDLElement
{
  /**
   * Set the name of this port type.
   *
   * @param name the desired name
   */
  public void setQName(QName name);

  /**
   * Get the name of this port type.
   *
   * @return the port type name
   */
  public QName getQName();

  /**
   * Add an operation to this port type.
   *
   * @param operation the operation to be added
   */
  public void addOperation(Operation operation);

  /**
   * Get the specified operation. Note that operation names can
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
   * @param name the name of the desired operation.
   * @param inputName the name of the input message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an input 
   * message without a name.
   * @param outputName the name of the output message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an output 
   * message without a name.
   * @return the corresponding operation, or null if there wasn't
   * any matching operation
   * 
   * @throws IllegalArgumentException if duplicate operations are found.
   */
  public Operation getOperation(String name,
                                String inputName,
                                String outputName);
  
  /**
   * Get all the operations defined here.
   */
  public List getOperations();

  /**
   * Remove the specified operation. Note that operation names can
   * be overloaded within a PortType. In case of overloading, the
   * names of the input and output messages can be used to further
   * refine the search.
   * <p>
   * Usage of the input and output message name parameters is as 
   * described for the <code>getOperation</code> method.
   * 
   * @param name the name of the desired operation.
   * @param inputName the name of the input message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an input 
   * message without a name.
   * @param outputName the name of the output message; if this is null
   * it will be ignored, if this is "<code>:none</code>" it means search for an output 
   * message without a name.
   * @return the operation which was removed, or null if there wasn't
   * any matching operation
   * 
   * @throws IllegalArgumentException if duplicate operations are found.
   * 
   * @see #getOperation(String, String, String) 
   */
  public Operation removeOperation(String name,
                                String inputName,
                                String outputName);

  public void setUndefined(boolean isUndefined);

  public boolean isUndefined();
}