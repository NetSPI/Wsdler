/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl;

import java.io.ObjectStreamException;

/**
 * This class represents an operation type which can
 * be one of request-response, solicit response, one way or
 * notification. This represents a safe way to prevent usage
 * of invalid values since the only objects of this class available
 * are the public static instances declared within the class.
 * Need to figure out if this should be made into an interface.
 */
public class OperationType implements java.io.Serializable
{
  private final String id;
  private final int intId;
  
  private static int counter = 0;
  
  public static final long serialVersionUID = 1;

  public static OperationType ONE_WAY =
    new OperationType("ONE_WAY");
  public static OperationType REQUEST_RESPONSE =
    new OperationType("REQUEST_RESPONSE");
  public static OperationType SOLICIT_RESPONSE =
    new OperationType("SOLICIT_RESPONSE");
  public static OperationType NOTIFICATION =
    new OperationType("NOTIFICATION");
  //If new values of op type are ever added (highly unlikely) 
  //they must be added here, after the existing values. Otherwise
  //readResolve will return the wrong instances at deserialization.

  private static final OperationType[] INSTANCES = 
      {ONE_WAY, REQUEST_RESPONSE, SOLICIT_RESPONSE, NOTIFICATION};

  private OperationType(String id)
  {
	  this.id = id;
	  this.intId = counter++;
  }  

  private String getId()
  {
	  return id;
  }  

  /* The following equals method is not used within wsdl4j but
   * it is historically part of the jsr110 jwsdl API, so it 
   * will not likely be removed. Although it overloads the 
   * Object.equals method (i.e. it has a different arg) it does 
   * not override it, so Object.equals will still be used by
   * the readResolve method at deserialization.   
   */
  public boolean equals(OperationType operationType)
  {
    return operationType != null && id.equals(operationType.getId());
  }

  public String toString()
  {
    return id + "," + intId;
  }
  
  /* The readResolve method has been added because this class
   * implements a typesafe enumeration and it is serializable. 
   * This method will ensure that at deserialization the orginal
   * instances of the enumeration are used, so that Object.equals 
   * and the '==' operator behave as expected.  
   */
  private Object readResolve() throws ObjectStreamException {
      return INSTANCES[intId];
  }
  
}