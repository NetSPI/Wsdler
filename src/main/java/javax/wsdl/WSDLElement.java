/*
 * (c) Copyright IBM Corp 2006 
 */

package javax.wsdl;

import javax.wsdl.extensions.AttributeExtensible;
import javax.wsdl.extensions.ElementExtensible;

import org.w3c.dom.Element;

/**
 * This interface represents all WSDL Elements
 */
public interface WSDLElement extends java.io.Serializable,
                                     AttributeExtensible,
                                     ElementExtensible
{
  /**
   * Set the documentation element for this document.
   *
   * @param docEl the documentation element
   */
  public void setDocumentationElement(Element docEl);

  /**
   * Get the documentation element.
   *
   * @return the documentation element
   */
  public Element getDocumentationElement();
}