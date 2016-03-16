/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package com.ibm.wsdl.extensions.schema;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Vector;

import javax.wsdl.extensions.schema.Schema;
import javax.wsdl.extensions.schema.SchemaImport;
import javax.wsdl.extensions.schema.SchemaReference;

import javax.xml.namespace.QName;

import org.w3c.dom.Element;

/**
 * This class is used to wrap schema elements. It holds the DOM Element to the
 * <code>&lt;schema&gt;</code> element.
 * 
 * @see SchemaSerializer
 * @see SchemaDeserializer
 * 
 * @author Jeremy Hughes <hughesj@uk.ibm.com>
 */
public class SchemaImpl implements Schema
{
  protected QName elementType = null;
  // Uses the wrapper type so we can tell if it was set or not.
  protected Boolean required = null;
  protected Element element = null;

  public static final long serialVersionUID = 1;

  /*
   * imports is a Map of Lists with key of the import's namespace URI. Each List
   * contains the SchemaImport objects for that namespace. There can be more
   * than one SchemaImport in a List - one for each schemaLocation attribute
   * setting.
   */
  private Map imports = new HashMap();

  /*
   * includes is a List of Include objects for the targetNamespace of the
   * enclosing schema. There is one Include in the List for each <include>
   * element in the XML Schema.
   */
  private List includes = new Vector();

  /*
   * redefines is a list of Redefine obejcts for the targetNamespace of the
   * enclosing schema. There is one Redefine in the List for each <redefine>
   * element in the XML Schema.
   */
  private List redefines = new Vector();

  private String documentBaseURI = null;

  /**
   * Get a map of lists containing all the imports defined here. The map's keys
   * are Strings representing the namespace URIs, and the map's values are
   * lists. There is one list for each namespace URI for which imports have been
   * defined.
   * 
   * @return a Map of Lists of Import instances keyed off the import's namespace
   */
  public Map getImports()
  {
    return this.imports;
  }

  /**
   * Create a new schema import.
   * 
   * @return the newly created schema import
   */
  public SchemaImport createImport()
  {
    return new SchemaImportImpl();
  }

  /**
   * Add an import to this LightWeightSchema
   * 
   * @param importSchema the import to be added
   */
  public void addImport(SchemaImport importSchema)
  {
    String namespaceURI = importSchema.getNamespaceURI();
    List importList = (List) this.imports.get(namespaceURI);

    if (importList == null)
    {
      importList = new Vector();

      this.imports.put(namespaceURI, importList);
    }

    importList.add(importSchema);
  }

  /**
   * Get list of includes defined here.
   * 
   * @return a List of SchemaReference instances representing the schema
   *         includes.
   */

  public List getIncludes()
  {
    return this.includes;
  }

  public SchemaReference createInclude()
  {
    return new SchemaReferenceImpl();
  }

  public void addInclude(SchemaReference includeSchema)
  {
    this.includes.add(includeSchema);
  }

  public List getRedefines()
  {
    return this.redefines;
  }

  public SchemaReference createRedefine()
  {
    return new SchemaReferenceImpl();
  }

  public void addRedefine(SchemaReference redefineSchema)
  {
    this.redefines.add(redefineSchema);
  }

  public String toString()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("SchemaExtensibilityElement (" + this.elementType + "):");
    strBuf.append("\nrequired=" + this.required);

    if (this.element != null)
    {
      strBuf.append("\nelement=" + this.element);
    }

    return strBuf.toString();
  }

  /**
   * Set the type of this extensibility element.
   *
   * @param elementType the type
   */
  public void setElementType(QName elementType)
  {
    this.elementType = elementType;
  }

  /**
   * Get the type of this extensibility element.
   *
   * @return the extensibility element's type
   */
  public QName getElementType()
  {
    return elementType;
  }

  /**
   * Set whether or not the semantics of this extension
   * are required. Relates to the wsdl:required attribute.
   */
  public void setRequired(Boolean required)
  {
    this.required = required;
  }

  /**
   * Get whether or not the semantics of this extension
   * are required. Relates to the wsdl:required attribute.
   */
  public Boolean getRequired()
  {
    return required;
  }

  /**
   * Set the DOM Element that represents this schema element.
   *
   * @param element the DOM element representing this schema
   */
  public void setElement(Element element)
  {
    this.element = element;
  }

  /**
   * Get the DOM Element that represents this schema element.
   *
   * @return the DOM element representing this schema
   */
  public Element getElement()
  {
    return element;
  }

  /**
   * Set the document base URI of this schema definition. Can be used to
   * represent the origin of the schema, and can be exploited when resolving
   * relative URIs (e.g. in &lt;import&gt;s).
   * 
   * @param documentBaseURI the document base URI of this schema
   */
  public void setDocumentBaseURI(String documentBaseURI)
  {
    this.documentBaseURI = documentBaseURI;
  }

  /**
   * Get the document base URI of this schema
   * 
   * @return the document base URI
   */
  public String getDocumentBaseURI()
  {
    return this.documentBaseURI;
  }
}