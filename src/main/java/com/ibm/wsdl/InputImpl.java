/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl;

import java.util.*;
import javax.wsdl.*;

/**
 * This class represents an input message, and contains the name
 * of the input and the message itself.
 *
 * @author Matthew J. Duftler
 */
public class InputImpl extends AbstractWSDLElement implements Input
{
  protected String name = null;
  protected Message message = null;
  protected List nativeAttributeNames =
    Arrays.asList(Constants.INPUT_ATTR_NAMES);

  public static final long serialVersionUID = 1;

  /**
   * Set the name of this input message.
   *
   * @param name the desired name
   */
  public void setName(String name)
  {
    this.name = name;
  }

  /**
   * Get the name of this input message.
   *
   * @return the input message name
   */
  public String getName()
  {
    return name;
  }

  public void setMessage(Message message)
  {
    this.message = message;
  }

  public Message getMessage()
  {
    return message;
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

    strBuf.append("Input: name=" + name);

    if (message != null)
    {
      strBuf.append("\n" + message);
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
