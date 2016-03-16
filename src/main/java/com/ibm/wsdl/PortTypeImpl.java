/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl;

import java.util.*;
import javax.wsdl.*;
import javax.xml.namespace.*;

/**
 * This class represents a port type. It contains information about
 * operations associated with this port type.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public class PortTypeImpl extends AbstractWSDLElement implements PortType
{
  protected QName name = null;
  protected List operations = new Vector();
  protected List nativeAttributeNames =
    Arrays.asList(Constants.PORT_TYPE_ATTR_NAMES);
  protected boolean isUndefined = true;
  
  public static final long serialVersionUID = 1;

  /**
   * Set the name of this port type.
   *
   * @param name the desired name
   */
  public void setQName(QName name)
  {
    this.name = name;
  }

  /**
   * Get the name of this port type.
   *
   * @return the port type name
   */
  public QName getQName()
  {
    return name;
  }

  /**
   * Add an operation to this port type.
   *
   * @param operation the operation to be added
   */
  public void addOperation(Operation operation)
  {
    operations.add(operation);
  }

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
                                String outputName)
  {
    boolean found = false;
    Operation ret = null;
    Iterator opIterator = operations.iterator();

    while (opIterator.hasNext())
    {
      Operation op = (Operation)opIterator.next();
      String opName = op.getName();

      if (name != null && opName != null)
      {
        if (!name.equals(opName))
        {
          op = null;
        }
      }
      else if (name != null || opName != null)
      {
        op = null;
      }

      if (op != null && inputName != null)
      {
        OperationType opStyle = op.getStyle();
        String defaultInputName = opName;

        if (opStyle == OperationType.REQUEST_RESPONSE)
        {
          defaultInputName = opName + "Request";
        }
        else if (opStyle == OperationType.SOLICIT_RESPONSE)
        {
          defaultInputName = opName + "Solicit";
        }

        boolean specifiedDefault = inputName.equals(defaultInputName);
        
        Input input = op.getInput();

        if (input != null)
        {
          String opInputName = input.getName();

          if (opInputName == null)
          {
            if (!specifiedDefault && !inputName.equals(Constants.NONE))
            {
              op = null;
            }
          }
          else if (!opInputName.equals(inputName))
          {
            op = null;
          }
        }
        else
        {
          op = null;
        }
      }

      if (op != null && outputName != null)
      {
        OperationType opStyle = op.getStyle();
        String defaultOutputName = opName;

        if (opStyle == OperationType.REQUEST_RESPONSE
            || opStyle == OperationType.SOLICIT_RESPONSE)
        {
          defaultOutputName = opName + "Response";
        }

        boolean specifiedDefault = outputName.equals(defaultOutputName);
        
        Output output = op.getOutput();

        if (output != null)
        {
          String opOutputName = output.getName();

          if (opOutputName == null)
          {
            if (!specifiedDefault && !outputName.equals(Constants.NONE))
            {
              op = null;
            }
          }
          else if (!opOutputName.equals(outputName))
          {
            op = null;
          }
        }
        else
        {
          op = null;
        }
      }

      if (op != null)
      {
        if (found)
        {
          throw new IllegalArgumentException("Duplicate operation with " +
                                             "name=" + name +
                                             (inputName != null
                                              ? ", inputName=" + inputName
                                              : "") +
                                             (outputName != null
                                              ? ", outputName=" + outputName
                                              : "") +
                                             ", found in portType '" +
                                             getQName() + "'.");
        }
        else
        {
          found = true;
          ret = op;
        }
      }
    }  //end while loop

    return ret;
  }

  /**
   * Get all the operations defined here.
   */
  public List getOperations()
  {
    return operations;
  }

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
                                String outputName)
  {
    Operation op = getOperation(name,inputName,outputName);
    if(operations.remove(op))
    {
      return op;
    }
    else return null;
  }
  
  public void setUndefined(boolean isUndefined)
  {
    this.isUndefined = isUndefined;
  }

  public boolean isUndefined()
  {
    return isUndefined;
  }

  /**
   * Get the list of local attribute names defined for this element in
   * the WSDL specification.
   *
   * @return a List of Strings, one for each local attribute name
   */
  public List getNativeAttributeNames()
  {
    return nativeAttributeNames;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("PortType: name=" + name);

    if (operations != null)
    {
      Iterator opIterator = operations.iterator();

      while (opIterator.hasNext())
      {
        strBuf.append("\n" + opIterator.next());
      }
    }

    String superString = super.toString();
    if(!superString.equals(""))
    {
      strBuf.append("\n");
      strBuf.append(superString);
    }

    return strBuf.toString();
  }
}
