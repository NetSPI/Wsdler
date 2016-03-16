/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package javax.wsdl.extensions.schema;


/**
 * Represents an import element within a schema element.
 * Similar to an include or redefine, but includes a namespace.
 * 
 * @author Jeremy Hughes <hughesj@uk.ibm.com>
 */
public interface SchemaImport extends SchemaReference
{
  /**
   * @return Returns the namespace.
   */
  public abstract String getNamespaceURI();

  /**
   * @param namespace The namespace to set.
   */
  public abstract void setNamespaceURI(String namespace);
}