/*
 * (c) Copyright IBM Corp 2004, 2005 
 */

package javax.wsdl.extensions.schema;


import java.io.Serializable;

import javax.wsdl.extensions.schema.Schema;

/**
 * Represents an include or a redefine element within a schema element.
 * 
 * @author Jeremy Hughes <hughesj@uk.ibm.com>
 */
public interface SchemaReference extends Serializable
{
    /**
     * Gets the ID attribute of the referenced schema.
     * 
     * @return the id string 
     */
    public abstract String getId();

    /**
     * Sets the ID attribute of the referenced schema.
     * 
     * @param id The id string to set.
     */
    public abstract void setId(String id);

    /**
     * Gets the schemaLocation attribute of the referenced schema.
     * 
     * @return the schemaLocation string.
     */
    public abstract String getSchemaLocationURI();

    /**
     * Sets the schemaLocation attribute of the referenced schema.
     * 
     * @param schemaLocation The schemaLocation string to set.
     */
    public abstract void setSchemaLocationURI(String schemaLocation);

    /**
     * Gets the referenced schema, represented as a LightWeightSchema.
     * 
     * @return the referenced LightWeightSchema.
     */
    public abstract Schema getReferencedSchema();

    /**
     * Sets the referenced schema to a LightWeightSchema.
     * 
     * @param referencedSchema The LightWeightSchema to set.
     */
    public abstract void setReferencedSchema(Schema referencedSchema);
}