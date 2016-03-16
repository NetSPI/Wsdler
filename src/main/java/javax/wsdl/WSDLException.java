/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl;

public class WSDLException extends Exception
{
  public static final long serialVersionUID = 1;

  public static final String INVALID_WSDL = "INVALID_WSDL";
  public static final String PARSER_ERROR = "PARSER_ERROR";
  public static final String OTHER_ERROR = "OTHER_ERROR";
  public static final String CONFIGURATION_ERROR = "CONFIGURATION_ERROR";
  public static final String UNBOUND_PREFIX = "UNBOUND_PREFIX";
  public static final String NO_PREFIX_SPECIFIED = "NO_PREFIX_SPECIFIED";

  private String faultCode = null;
  private Throwable targetThrowable = null;
  private String location = null;

  public WSDLException(String faultCode, String msg, Throwable t)
  {
    super(msg, t);
    setFaultCode(faultCode);    
  }

  public WSDLException(String faultCode, String msg)
  {
    this(faultCode, msg, null);
  }

  public void setFaultCode(String faultCode)
  {
    this.faultCode = faultCode;
  }

  public String getFaultCode()
  {
    return faultCode;
  }

  public void setTargetException(Throwable targetThrowable)
  {
    this.targetThrowable = targetThrowable;
  }

  public Throwable getTargetException()
  {
    if(targetThrowable == null) return getCause();
    else return targetThrowable;
  }

  /**
   * Set the location using an XPath expression. Used for error messages.
   *
   * @param location an XPath expression describing the location where
   * the exception occurred.
   */
  public void setLocation(String location)
  {
    this.location = location;
  }

  /**
   * Get the location, if one was set. Should be an XPath expression which
   * is used for error messages.
   */
  public String getLocation()
  {
    return location;
  }

  public String getMessage()
  {
    StringBuffer strBuf = new StringBuffer();

    strBuf.append("WSDLException");

    if (location != null)
    {
      try
      {
        strBuf.append(" (at " + location + ")");
      }
      catch (IllegalArgumentException e)
      {
      }
    }

    if (faultCode != null)
    {
      strBuf.append(": faultCode=" + faultCode);
    }

    String thisMsg = super.getMessage();
    String targetMsg = null;
    String targetName = null;
    if(getTargetException() != null)
    {
      targetMsg = getTargetException().getMessage();
      targetName = getTargetException().getClass().getName();
    }

    if (thisMsg != null
        && (targetMsg == null || !thisMsg.equals(targetMsg)))
    {
      strBuf.append(": " + thisMsg);
    }

    if (targetName != null)
    {
      strBuf.append(": " + targetName);
    }
    
    if (targetMsg != null)
    {
      strBuf.append(": " + targetMsg);
    }

    return strBuf.toString();
  }
}