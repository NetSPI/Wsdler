/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package com.ibm.wsdl.extensions.schema;

import java.io.Serializable;
import java.util.Hashtable;
import java.util.Map;

import javax.wsdl.Definition;
import javax.wsdl.WSDLException;
import javax.wsdl.extensions.ExtensibilityElement;
import javax.wsdl.extensions.ExtensionDeserializer;
import javax.wsdl.extensions.ExtensionRegistry;
import javax.wsdl.extensions.schema.Schema;
import javax.wsdl.extensions.schema.SchemaImport;
import javax.wsdl.extensions.schema.SchemaReference;
import javax.wsdl.xml.WSDLLocator;
import javax.xml.namespace.QName;

import org.w3c.dom.Element;

import com.ibm.wsdl.Constants;
import com.ibm.wsdl.extensions.schema.SchemaConstants;
import com.ibm.wsdl.util.xml.DOMUtils;
import com.ibm.wsdl.util.xml.QNameUtils;

/**
 * This class is used to deserialize <code>&lt;schema&gt;</code> elements into
 * Schema instances.
 * 
 * @see SchemaImpl
 * @see SchemaSerializer
 * 
 * @author Jeremy Hughes <hughesj@uk.ibm.com>
 */
public class SchemaDeserializer implements ExtensionDeserializer, Serializable
{

  // Need to set this since a Definition is serializable and it contains an
  // extension registry which contains one of these
  public static final long serialVersionUID = 1;

  private final Map allReferencedSchemas = new Hashtable();

  private static ThreadLocal wsdlLocator = new ThreadLocal();

  /**
   * Set the WSDLLocator to be used by the deserializer on this thread.
   * 
   * @param loc The WSDLLocator to be used.
   * 
   * @see WSDLLocator
   */
  public static void setLocator(WSDLLocator loc)
  {
    wsdlLocator.set(loc);
  }

  public ExtensibilityElement unmarshall(Class parentType,
                                         QName elementType,
                                         Element el,
                                         Definition def,
                                         ExtensionRegistry extReg)
      throws WSDLException
  {
    Schema schema = (Schema) extReg.createExtension(
        parentType, elementType);
    
    schema.setElementType(elementType);
    schema.setElement(el);
    schema.setDocumentBaseURI(def.getDocumentBaseURI());
    
    //TODO: check if the 'required' attribute needs to be set
    
    // Go through the schema Element looking for child schemas
    
    Element tempEl = DOMUtils.getFirstChildElement(el);

    for (; tempEl != null; tempEl = DOMUtils.getNextSiblingElement(tempEl))
    {
      QName tempElType = QNameUtils.newQName(tempEl);

      // Create the appropriate SchemaReference subclass to represent
      // an <import>, an <include> or a <redefine>

      SchemaReference sr = null;
      String locationURI = null;

      if (SchemaConstants.XSD_IMPORT_QNAME_LIST.contains(tempElType))
      {
        // Create a new import. Don't use the
        // ExtensionRegistry.createExtension()
        // method as a Schema import is not a WSDL import.
        SchemaImport im = schema.createImport();

        im.setId(DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_ID));
        im.setNamespaceURI(DOMUtils.getAttribute(tempEl, Constants.ATTR_NAMESPACE));

        locationURI = DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_SCHEMA_LOCATION);
        im.setSchemaLocationURI(locationURI);

        // Now the import is set up except for the point to the
        // referenced LWS, add the import to the LightWeightSchema.
        schema.addImport(im);
      }
      else
        if (SchemaConstants.XSD_INCLUDE_QNAME_LIST.contains(tempElType))
        {
          // Create a new include. Don't use the
          // ExtensionRegistry.createExtension()
          // method as a Schema include is not a WSDL import.
          sr = schema.createInclude();

          sr.setId(DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_ID));

          locationURI = DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_SCHEMA_LOCATION);

          sr.setSchemaLocationURI(locationURI);

          // Now the include is set up except for the pointer to the
          // referenced LWS, add the include to the LightWeightSchema.
          schema.addInclude(sr);
        }
        else
          if (SchemaConstants.XSD_REDEFINE_QNAME_LIST.contains(tempElType))
          {
            // Create a new redefine. Don't use the
            // ExtensionRegistry.createExtension() method as a Schema redefine
            // is not a WSDL import.
            sr = schema.createRedefine();

            sr.setId(DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_ID));

            locationURI = DOMUtils.getAttribute(tempEl, SchemaConstants.ATTR_SCHEMA_LOCATION);

            sr.setSchemaLocationURI(locationURI);

            // Now the redefine is set up except for the pointer to the
            // referenced LWS, add the redefine to the LightWeightSchema.
            schema.addRedefine(sr);
          }
          else
          {
            // The element isn't one we're interested in so look at the next
            // one
            continue;
          }
      
    } //end for  

    return schema;
  }

}