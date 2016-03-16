/*
 * (c) Copyright IBM Corp 2002, 2005 
 */

package com.ibm.wsdl.util.xml;

import javax.xml.namespace.*;
import org.w3c.dom.*;

public class QNameUtils
{
  public static boolean matches(QName qname, Node node)
  {
    return (node != null && qname.equals(newQName(node)));
  }

  public static QName newQName(Node node)
  {
    if (node != null)
    {
      return new QName(node.getNamespaceURI(), node.getLocalName());
    }
    else
    {
      return new QName(null, null);
    }
  }
}