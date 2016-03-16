/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl;

import java.util.*;

import javax.wsdl.*;

/**
 * This class represents an input binding. That is, it contains
 * the information that would be specified in an input element
 * contained within an operation element contained within a
 * binding element.
 *
 * @author Matthew J. Duftler
 */
public class BindingInputImpl extends AbstractWSDLElement implements BindingInput
{
  protected String name = null;
  protected List nativeAttributeNames =
    Arrays.asList(Constants.BINDING_INPUT_ATTR_NAMES);

  public static final long serialVersionUID = 1;

  /**
   * Set the name of this input binding.
   *
   * @param name the desired name
   */
  public void setName(String name)
  {
    this.name = name;
  }

  /**
   * Get the name of this input binding.
   *
   * @return the input binding name
   */
  public String getName()
  {
    return name;
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("BindingInput: name=" + name);

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
