/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package javax.wsdl.extensions;

import java.util.*;
import javax.xml.namespace.*;

/**
 * Classes that implement this interface can contain extensibility
 * attributes.
 *
 * @author Matthew J. Duftler
 * @author Paul Fremantle
 */
public interface AttributeExtensible
{
  public static final int NO_DECLARED_TYPE = -1;
  public static final int STRING_TYPE = 0;
  public static final int QNAME_TYPE = 1;
  public static final int LIST_OF_STRINGS_TYPE = 2;
  public static final int LIST_OF_QNAMES_TYPE = 3;

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
   * @see ExtensionRegistry#registerExtensionAttributeType
   * @see ExtensionRegistry#queryExtensionAttributeType
   */
  public void setExtensionAttribute(QName name, Object value);

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
   * @see ExtensionRegistry#registerExtensionAttributeType
   * @see ExtensionRegistry#queryExtensionAttributeType
   */
  public Object getExtensionAttribute(QName name);

  /**
   * Get the map containing all the extension attributes defined
   * on this element. The keys are the qnames of the attributes.
   *
   * @return a map containing all the extension attributes defined
   * on this element
   *
   * @see #setExtensionAttribute
   * @see #getExtensionAttribute
   * @see ExtensionRegistry#registerExtensionAttributeType
   * @see ExtensionRegistry#queryExtensionAttributeType
   */
  public Map getExtensionAttributes();

  /**
   * Get the list of local attribute names defined for this element in
   * the WSDL specification.
   *
   * @return a List of Strings, one for each local attribute name
   */
  public List getNativeAttributeNames();
}
