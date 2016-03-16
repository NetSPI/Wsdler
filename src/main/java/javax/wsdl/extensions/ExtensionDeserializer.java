/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions;

import org.w3c.dom.*;
import javax.wsdl.*;
import javax.xml.namespace.*;

/**
 * This interface should be implemented by classes which deserialize
 * org.w3c.dom.Elements into extension-specific instances of
 * ExtensibilityElement.
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface ExtensionDeserializer
{
  /**
   * This method deserializes elements into instances of classes
   * which implement the ExtensibilityElement interface. The
   * return value should be explicitly cast to the more-specific
   * implementing type.
   *
   * @param parentType a class object indicating where in the WSDL
   * document this extensibility element was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this element was encountered as an immediate child of
   * a <wsdl:binding> element.
   * @param elementType the qname of the extensibility element
   * @param el the extensibility element to deserialize
   * @param def the definition this extensibility element was
   * encountered in
   * @param extReg the ExtensionRegistry to use (if needed again)
   */
  public ExtensibilityElement unmarshall(Class parentType,
                                         QName elementType,
                                         Element el,
                                         Definition def,
                                         ExtensionRegistry extReg)
                                           throws WSDLException;
}