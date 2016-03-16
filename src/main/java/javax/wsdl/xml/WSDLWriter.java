/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.xml;

import java.io.*;
import org.w3c.dom.*;
import javax.wsdl.*;

/**
 * This interface describes a collection of methods
 * that allow a WSDL model to be written to a writer
 * in an XML format that follows the WSDL schema.
 *
 * @author Matthew J. Duftler
 */
public interface WSDLWriter
{
  /**
   * Sets the specified feature to the specified value.
   * <p>
   * There are no minimum features that must be supported.
   * <p>
   * All feature names must be fully-qualified, Java package style. All
   * names starting with javax.wsdl. are reserved for features defined
   * by the JWSDL specification. It is recommended that implementation-
   * specific features be fully-qualified to match the package name
   * of that implementation. For example: com.abc.featureName
   *
   * @param name the name of the feature to be set.
   * @param value the value to set the feature to.
   * @throws IllegalArgumentException if the feature name is not recognized.
   * @see #getFeature(String)
   */
  public void setFeature(String name, boolean value)
    throws IllegalArgumentException;

  /**
   * Gets the value of the specified feature.
   *
   * @param name the name of the feature to get the value of.
   * @return the value of the feature.
   * @throws IllegalArgumentException if the feature name is not recognized.
   * @see #setFeature(String, boolean)
   */
  public boolean getFeature(String name) throws IllegalArgumentException;

  /**
   * Return a document generated from the specified WSDL model.
   */
  public Document getDocument(Definition wsdlDef) throws WSDLException;

  /**
   * Write the specified WSDL definition to the specified Writer.
   *
   * @param wsdlDef the WSDL definition to be written.
   * @param sink the Writer to write the xml to.
   */
  public void writeWSDL(Definition wsdlDef, Writer sink)
    throws WSDLException;

  /**
   * Write the specified WSDL definition to the specified OutputStream.
   *
   * @param wsdlDef the WSDL definition to be written.
   * @param sink the OutputStream to write the xml to.
   */
  public void writeWSDL(Definition wsdlDef, OutputStream sink)
    throws WSDLException;
}