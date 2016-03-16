/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl.xml;

import org.w3c.dom.*;
import org.xml.sax.*;
import javax.wsdl.*;
import javax.wsdl.extensions.*;

/**
 * This interface describes a collection of methods
 * that enable conversion of a WSDL document (in XML,
 * following the WSDL schema described in the WSDL
 * specification) into a WSDL model.
 *
 * @author Matthew J. Duftler
 */
public interface WSDLReader
{
  /**
   * Sets the specified feature to the specified value.
   * <p>
   * The minimum features that must be supported are:
   * <p>
   * <table border=1>
   *   <tr>
   *     <th>Name</th>
   *     <th>Description</th>
   *     <th>Default Value</th>
   *   </tr>
   *   <tr>
   *     <td><center>javax.wsdl.verbose</center></td>
   *     <td>If set to true, status messages will be displayed.</td>
   *     <td><center>true</center></td>
   *   </tr>
   *   <tr>
   *     <td><center>javax.wsdl.importDocuments</center></td>
   *     <td>If set to true, imported WSDL documents will be
   *         retrieved and processed.</td>
   *     <td><center>true</center></td>
   *   </tr>
   * </table>
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
   * @return the value of feature
   * @throws IllegalArgumentException if the feature name is not recognized.
   * @see #setFeature(String, boolean)
   */
  public boolean getFeature(String name) throws IllegalArgumentException;

  /**
   * Set the extension registry to be used when reading
   * WSDL documents into a WSDL definition. If an
   * extension registry is set, that is the extension
   * registry that will be set as the extensionRegistry
   * property of the definitions resulting from invoking
   * readWSDL(...). Default is null.
   *
   * @param extReg the extension registry to use for new
   * definitions
   */
  public void setExtensionRegistry(ExtensionRegistry extReg);

  /**
   * Get the extension registry, if one was set. Default is
   * null.
   */
  public ExtensionRegistry getExtensionRegistry();

  /**
   * Set a different factory implementation to use for
   * creating definitions when reading WSDL documents.
   * As some WSDLReader implementations may only be
   * capable of creating definitions using the same
   * factory implementation from which the reader was
   * obtained, this method is optional. Default is null.
   *
   * @param factoryImplName the fully-qualified class name of the
   * class which provides a concrete implementation of the abstract
   * class WSDLFactory.
   * @throws UnsupportedOperationException if this method
   * is invoked on an implementation which does not
   * support it.
   */
  public void setFactoryImplName(String factoryImplName)
    throws UnsupportedOperationException;

  /**
   * Get the factoryImplName, if one was set. Default is null.
   */
  public String getFactoryImplName();

  /**
   * Read the WSDL document accessible via the specified
   * URI into a WSDL definition.
   *
   * @param wsdlURI a URI (can be a filename or URL) pointing to a
   * WSDL XML definition.
   * @return the definition.
   */
  public Definition readWSDL(String wsdlURI) throws WSDLException;

  /**
   * Read the WSDL document accessible via the specified
   * URI into a WSDL definition.
   *
   * @param contextURI the context in which to resolve the
   * wsdlURI, if the wsdlURI is relative. Can be null, in which
   * case it will be ignored.
   * @param wsdlURI a URI (can be a filename or URL) pointing to a
   * WSDL XML definition.
   * @return the definition.
   */
  public Definition readWSDL(String contextURI, String wsdlURI)
    throws WSDLException;

  /**
   * Read the specified &lt;wsdl:definitions&gt; element into a WSDL
   * definition.
   *
   * @param documentBaseURI the document base URI of the WSDL definition
   * described by the element. Will be set as the documentBaseURI
   * of the returned Definition. Can be null, in which case it
   * will be ignored.
   * @param definitionsElement the &lt;wsdl:definitions&gt; element
   * @return the definition described by the element.
   */
  public Definition readWSDL(String documentBaseURI,
                             Element definitionsElement)
                               throws WSDLException;
  
  /**
   * Read the specified &lt;wsdl:definitions&gt; element into a WSDL
   * definition. The WSDLLocator is used to provide the document
   * base URIs. The InputSource of the WSDLLocator is ignored, instead
   * the WSDL is parsed from the given Element. 
   *
   * @param locator A WSDLLocator object used to provide 
   * the document base URI of the WSDL definition described by the
   * element.
   * @param definitionsElement the &lt;wsdl:definitions&gt; element
   * @return the definition described by the element.
   */
  public Definition readWSDL(WSDLLocator locator,
                             Element definitionsElement)
                               throws WSDLException;

  /**
   * Read the specified WSDL document into a WSDL definition.
   *
   * @param documentBaseURI the document base URI of the WSDL definition
   * described by the document. Will be set as the documentBaseURI
   * of the returned Definition. Can be null, in which case it
   * will be ignored.
   * @param wsdlDocument the WSDL document, an XML 
   * document obeying the WSDL schema.
   * @return the definition described in the document.
   */
  public Definition readWSDL(String documentBaseURI, Document wsdlDocument)
    throws WSDLException;

  /**
   * Read a WSDL document into a WSDL definition.
   *
   * @param documentBaseURI the document base URI of the WSDL definition
   * described by the document. Will be set as the documentBaseURI
   * of the returned Definition. Can be null, in which case it
   * will be ignored.
   * @param inputSource an InputSource pointing to the
   * WSDL document, an XML document obeying the WSDL schema.
   * @return the definition described in the document pointed to
   * by the InputSource.
   */
  public Definition readWSDL(String documentBaseURI, InputSource inputSource)
    throws WSDLException;

  /**
   * Read a WSDL document into a WSDL definition.
   *
   * @param locator A WSDLLocator object used to provide InputSources
   * pointing to the wsdl file.
   * @return the definition described in the document
   */
  public Definition readWSDL(WSDLLocator locator) throws WSDLException;
}