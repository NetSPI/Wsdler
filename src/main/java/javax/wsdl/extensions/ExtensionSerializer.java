/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions;

import java.io.*;
import javax.wsdl.*;
import javax.xml.namespace.*;

/**
 * This interface should be implemented by classes which serialize
 * extension-specific instances of ExtensibilityElement into the
 * PrintWriter.
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public interface ExtensionSerializer
{
  /**
   * This method serializes extension-specific instances of
   * ExtensibilityElement into the PrintWriter.
   *
   * @param parentType a class object indicating where in the WSDL
   * definition this extension was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this extensibility element was found in the list of
   * extensibility elements belonging to a javax.wsdl.Binding.
   * @param elementType the qname of the extensibility element
   * @param extension the extensibility element to serialize
   * @param def the definition this extensibility element was
   * encountered in
   * @param extReg the ExtensionRegistry to use (if needed again)
   */
  public void marshall(Class parentType,
                       QName elementType,
                       ExtensibilityElement extension,
                       PrintWriter pw,
                       Definition def,
                       ExtensionRegistry extReg)
                         throws WSDLException;
}