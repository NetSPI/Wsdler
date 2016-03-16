/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package javax.wsdl.extensions.schema;

import java.io.Serializable;
import java.util.List;
import java.util.Map;

import javax.wsdl.extensions.ExtensibilityElement;

import org.w3c.dom.Element;

/**
 * Represents a schema element.
 * This is a lightweight schema wrapper that provides access to 
 * the schema DOM element, but does not parse the schema details. 
 * The implementor may provide alternative schema parsing if required.
 * 
 * @author Jeremy Hughes
 *
 */
public interface Schema extends ExtensibilityElement, Serializable 
{
    /**
     * Get a map of lists containing all the imports defined here.
     * The map's keys are the namespaceURIs, and the map's values
     * are lists. There is one list for each namespaceURI for which
     * imports have been defined.
     *
     * @return a map of lists of schema imports
     */
    public Map getImports();
    
    /**
     * Create a new schema import
     *
     * @return the newly created schema import
     */
    public SchemaImport createImport();
    
    /**
     * Add an import to this LightWeightSchema
     *
     * @param importSchema the import to be added
     */
    public void addImport(SchemaImport importSchema);
    
    /**
     * Get a list containing all of the includes defined here.
     * The list elements are schema references.
     * 
     * @return a list of schema references.
     */
    public List getIncludes();
    
    /**
     * Create a new schema reference to represent an include.
     *
     * @return the newly created SchemaReference
     */
    public SchemaReference createInclude();
    
    /**
     * Add an include to this LightWeightSchema
     *
     * @param includeSchema The include to be added, represented as a SchemaReference
     */
    public void addInclude(SchemaReference includeSchema);
    
    /**
     * Get a list containing all of the redefines defined here.
     * The list elements are schema references.
     * 
     * @return a list of schema references.
     */
    public List getRedefines();
    
    /**
     * Create a new schema reference to represent a redefine.
     *
     * @return the newly created SchemaReference
     */
    public SchemaReference createRedefine();
    
    /**
     * Add a redefine to this LightWeightSchema
     *
     * @param redefineSchema The redefine to be added, represented as a SchemaReference
     */
    public void addRedefine(SchemaReference redefineSchema);
    
    /**
     * Set the DOM Element that represents this schema element.
     *
     * @param element the DOM element representing this schema
     */
    public void setElement(Element element);

    /**
     * Get the DOM Element that represents this schema element.
     *
     * @return the DOM element representing this schema
     */
    public Element getElement();
    
    /**
     * Set the document base URI of this schema definition. Can be used to
     * represent the origin of the schema, and can be exploited
     * when resolving relative URIs (e.g. in &lt;import&gt;s).
     *
     * @param documentBaseURI the document base URI of this schema
     */
    public void setDocumentBaseURI(String documentBaseURI);

    /**
     * Get the document base URI of this schema
     *
     * @return the document base URI
     */
    public String getDocumentBaseURI();

}