/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl;

import java.util.*;

import javax.wsdl.*;
import javax.xml.namespace.*;

/**
 * This class represents a port type binding and describes the
 * protocol required for using operations in a port type.
 *
 * @author Paul Fremantle
 * @author Nirmal Mukhi
 * @author Matthew J. Duftler
 */
public class BindingImpl extends AbstractWSDLElement implements Binding
{
  protected QName name = null;
  protected PortType portType = null;
  protected List bindingOperations = new Vector();
  protected List nativeAttributeNames =
    Arrays.asList(Constants.BINDING_ATTR_NAMES);
  protected boolean isUndefined = true;

  public static final long serialVersionUID = 1;

  /**
   * Set the name of this binding.
   *
   * @param name the desired name
   */
  public void setQName(QName name)
  {
    this.name = name;
  }

  /**
   * Get the name of this binding.
   *
   * @return the binding name
   */
  public QName getQName()
  {
    return name;
  }

  /**
   * Set the port type this is a binding for.
   *
   * @param portType the port type associated with this binding
   */
  public void setPortType(PortType portType)
  {
    this.portType = portType;
  }

  /**
   * Get the port type this is a binding for.
   *
   * @return the associated port type
   */
  public PortType getPortType()
  {
    return portType;
  }

  /**
   * Add an operation binding to binding.
   *
   * @param bindingOperation the operation binding to be added
   */
  public void addBindingOperation(BindingOperation bindingOperation)
  {
    bindingOperations.add(bindingOperation);
  }

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
                                              String outputName)
  {
    boolean found = false;
    BindingOperation ret = null;
    Iterator opBindingIterator = bindingOperations.iterator();

    while (opBindingIterator.hasNext())
    {
      BindingOperation op = (BindingOperation)opBindingIterator.next();
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
        PortType pt = getPortType();
        OperationType opStyle = null;

        if (pt != null)
        {
          Operation tempOp = pt.getOperation(name, inputName, outputName);

          if (tempOp != null)
          {
            opStyle = tempOp.getStyle();
          }
        }

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
        
        BindingInput input = op.getBindingInput();

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
        PortType pt = getPortType();
        OperationType opStyle = null;

        if (pt != null)
        {
          Operation tempOp = pt.getOperation(name, inputName, outputName);

          if (tempOp != null)
          {
            opStyle = tempOp.getStyle();
          }
        }

        String defaultOutputName = opName;

        if (opStyle == OperationType.REQUEST_RESPONSE
            || opStyle == OperationType.SOLICIT_RESPONSE)
        {
          defaultOutputName = opName + "Response";
        }

        boolean specifiedDefault = outputName.equals(defaultOutputName);
        
        BindingOutput output = op.getBindingOutput();

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
                                             ", found in binding '" +
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
   * Get all the operation bindings defined here.
   */
  public List getBindingOperations()
  {
    return bindingOperations;
  }

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
                                                 String outputName)
  {
    BindingOperation op = getBindingOperation(name,inputName,outputName);
    if(bindingOperations.remove(op))
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

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("Binding: name=");
    strBuf.append(name);

    if (portType != null)
    {
      strBuf.append("\n");
      strBuf.append(portType);
    }

    if (bindingOperations != null)
    {
      Iterator bindingOperationIterator = bindingOperations.iterator();

      while (bindingOperationIterator.hasNext())
      {
        strBuf.append("\n");
        strBuf.append(bindingOperationIterator.next());
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
}
