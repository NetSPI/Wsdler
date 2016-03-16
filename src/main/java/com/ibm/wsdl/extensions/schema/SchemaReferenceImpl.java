/*
 * (c) Copyright IBM Corp 2004, 2005
 */

package com.ibm.wsdl.extensions.schema;

import javax.wsdl.extensions.schema.Schema;
import javax.wsdl.extensions.schema.SchemaReference;

/**
 * @author Jeremy Hughes <hughesj@uk.ibm.com>
 */
public class SchemaReferenceImpl implements SchemaReference
{

  public static final long serialVersionUID = 1;

  private String id = null;

  private String schemaLocation = null;

  private Schema referencedSchema = null;

  /**
   * @return Returns the id.
   */
  public String getId()
  {
    return this.id;
  }

  /**
   * @param id The id to set.
   */
  public void setId(String id)
  {
    this.id = id;
  }

  /**
   * @return Returns the schemaLocation.
   */
  public String getSchemaLocationURI()
  {
    return this.schemaLocation;
  }

  /**
   * @param schemaLocation The schemaLocation to set.
   */
  public void setSchemaLocationURI(String schemaLocation)
  {
    this.schemaLocation = schemaLocation;
  }

  /**
   * @return Returns the importedSchema.
   */
  public Schema getReferencedSchema()
  {
    return this.referencedSchema;
  }

  /**
   * @param referencedSchema The importedSchema to set.
   */
  public void setReferencedSchema(Schema referencedSchema)
  {
    this.referencedSchema = referencedSchema;
  }
}