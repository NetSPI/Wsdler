/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl;

import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.wsdl.WSDLElement;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

/**
 * Abstract super class for all WSDL Elements, providing some basic
 * common functionality.
 */
public abstract class AbstractWSDLElement implements WSDLElement
{  
  protected Element docEl;
  protected List extElements = new Vector();
  protected Map extensionAttributes = new HashMap();

  /**
   * Set the documentation element for this document. This dependency
   * on org.w3c.dom.Element should eventually be removed when a more
   * appropriate way of representing this information is employed.
   *
   * @param docEl the documentation element
   */
  public void setDocumentationElement(Element docEl)
  {
    this.docEl = docEl;
  }

  /**
   * Get the documentation element. This dependency on org.w3c.dom.Element
   * should eventually be removed when a more appropriate way of
   * representing this information is employed.
   *
   * @return the documentation element
   */
  public Element getDocumentationElement()
  {
    return docEl;
  }
  
  /**
   * Add an extensibility element.
   *
   * @param extElement the extensibility element to be added
   */
  public void addExtensibilityElement(ExtensibilityElement extElement)
  {
    extElements.add(extElement);
  }
  
  /**
   * Remove an extensibility element.
   *
   * @param extElement the extensibility element to be removed.
   * @return the extensibility element which was removed.
   */
  public ExtensibilityElement removeExtensibilityElement(ExtensibilityElement extElement)
  {
    if(extElements.remove(extElement))
    {
      return extElement;
    }
    else
    {
      return null;
    }
  }

  /**
   * Get all the extensibility elements defined here.
   */
  public List getExtensibilityElements()
  {
    return extElements;
  }
  
  /**
   * Set an extension attribute on this element. Pass in a null value to remove
   * an extension attribute.
   *
   * @param name the extension attribute name
   * @param value the extension attribute value. Can be a String, a QName, a
   * List of Strings, or a List of QNames.
   *
   * @see #getExtensionAttribute
   * @see #getExtensionAttributes
   * @see 
   *      javax.wsdl.extensions.ExtensionRegistry#registerExtensionAttributeType
   * @see 
   *      javax.wsdl.extensions.ExtensionRegistry#queryExtensionAttributeType
   */
  public void setExtensionAttribute(QName name, Object value)
  {
    if (value != null)
    {
      extensionAttributes.put(name, value);
    }
    else
    {
      extensionAttributes.remove(name);
    }
  }

  /**
   * Retrieve an extension attribute from this element. If the extension
   * attribute is not defined, null is returned.
   *
   * @param name the extension attribute name
   *
   * @return the value of the extension attribute, or null if
   * it is not defined. Can be a String, a QName, a List of Strings, or a List
   * of QNames.
   *
   * @see #setExtensionAttribute
   * @see #getExtensionAttributes
   * @see 
   *      javax.wsdl.extensions.ExtensionRegistry#registerExtensionAttributeType
   * @see 
   *      javax.wsdl.extensions.ExtensionRegistry#queryExtensionAttributeType
   */
  public Object getExtensionAttribute(QName name)
  {
    return extensionAttributes.get(name);
  }

  /**
   * Get the map containing all the extension attributes defined
   * on this element. The keys are the qnames of the attributes.
   *
   * @return a map containing all the extension attributes defined
   * on this element
   *
   * @see #setExtensionAttribute
   * @see #getExtensionAttribute
   */
  public Map getExtensionAttributes()
  {
    return extensionAttributes;
  }
  
  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    if (extElements.size() > 0)
    {
      Iterator extIterator = extElements.iterator();

      if(extIterator.hasNext())
      {
        strBuf.append(extIterator.next());
        
        while (extIterator.hasNext())
        {
          strBuf.append("\n");
          strBuf.append(extIterator.next());
        }
      }
    }
    
    if(extensionAttributes.size() > 0)
    {
      Iterator keys = extensionAttributes.keySet().iterator();
  
      if(keys.hasNext())
      {
        QName name = (QName)keys.next();
        
        strBuf.append("extension attribute: ");
        strBuf.append(name);
        strBuf.append("=");
        strBuf.append(extensionAttributes.get(name));
      
        while (keys.hasNext())
        {
          name = (QName)keys.next();
    
          strBuf.append("\n");
          strBuf.append("extension attribute: ");
          strBuf.append(name);
          strBuf.append("=");
          strBuf.append(extensionAttributes.get(name));
        }
      }
    }

    return strBuf.toString();
  }
}
