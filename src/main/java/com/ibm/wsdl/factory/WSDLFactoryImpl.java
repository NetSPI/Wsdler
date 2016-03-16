/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.factory;

import javax.wsdl.*;
import javax.wsdl.extensions.*;
import javax.wsdl.factory.*;
import javax.wsdl.xml.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.extensions.*;
import com.ibm.wsdl.xml.*;

/**
 * This class is a concrete implementation of the abstract class
 * WSDLFactory. Some ideas used here have been shamelessly
 * copied from the wonderful JAXP and Xerces work.
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class WSDLFactoryImpl extends WSDLFactory
{
  /**
   * Create a new instance of a Definition, with an instance
   * of a PopulatedExtensionRegistry as its ExtensionRegistry.
   *
   * @see com.ibm.wsdl.extensions.PopulatedExtensionRegistry
   */
  public Definition newDefinition()
  {
    Definition def = new DefinitionImpl();
    ExtensionRegistry extReg = newPopulatedExtensionRegistry();

    def.setExtensionRegistry(extReg);

    return def;
  }

  /**
   * Create a new instance of a WSDLReader.
   */
  public WSDLReader newWSDLReader()
  {
    return new WSDLReaderImpl();
  }

  /**
   * Create a new instance of a WSDLWriter.
   */
  public WSDLWriter newWSDLWriter()
  {
    return new WSDLWriterImpl();
  }

  /**
   * Create a new instance of an ExtensionRegistry with pre-registered
   * serializers/deserializers for the SOAP, HTTP and MIME
   * extensions. Java extensionTypes are also mapped for all
   * the SOAP, HTTP and MIME extensions.
   */
  public ExtensionRegistry newPopulatedExtensionRegistry()
  {
    return new PopulatedExtensionRegistry();
  }
}