/*
 * (c) Copyright IBM Corp 2002, 2006 
 */

package javax.xml.namespace;

import java.io.*;

/**
 * <code>QName</code> class represents the value of a qualified name
 * as specified in <a href="http://www.w3.org/TR/xmlschema-2/#QName">XML
 * Schema Part2: Datatypes specification</a>.
 * <p>
 * The value of a QName contains a <b>namespaceURI</b> and a <b>localPart</b>.
 * The localPart provides the local part of the qualified name. The
 * namespaceURI is a URI reference identifying the namespace.
 *
 * Note: Some of this impl code was taken from Axis.
 *
 * @author axis-dev
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class QName implements Serializable
{
  // Comment/shared empty string.
  private static final String emptyString = "";

  // Field namespaceURI.
  private String namespaceURI;

  // Field localPart.
  private String localPart;
  
  // Field prefix.
  private String prefix;

  private static final long serialVersionUID = -9120448754896609940L;

  /**
   * Constructor for the QName.
   *
   * @param localPart Local part of the QName
   */
  public QName(String localPart)
  {
    this.namespaceURI = emptyString;
    this.localPart    = (localPart == null)
                        ? emptyString
                        : localPart.intern();
    this.prefix       = emptyString;
  }

  /**
   * Constructor for the QName.
   *
   * @param namespaceURI Namespace URI for the QName
   * @param localPart Local part of the QName.
   */
  public QName(String namespaceURI, String localPart)
  {
    this.namespaceURI = (namespaceURI == null)
                        ? emptyString
                        : namespaceURI.intern();
    this.localPart    = (localPart == null)
                        ? emptyString
                        : localPart.intern();
    this.prefix       = emptyString;
  }

  /**
   * Constructor for the QName.
   *
   * @param namespaceURI Namespace URI for the QName
   * @param localPart Local part of the QName.
   * @param prefix the xmlns-declared prefix for this namespaceURI
   */
  public QName(String namespaceURI, String localPart, String prefix)
  {
    this.namespaceURI = (namespaceURI == null)
                        ? emptyString
                        : namespaceURI.intern();
    this.localPart    = (localPart == null)
                        ? emptyString
                        : localPart.intern();
    this.prefix       = (prefix == null)
                        ? emptyString
                        : prefix.intern();
  }
  
  /**
   * Gets the Namespace URI for this QName
   *
   * @return Namespace URI
   */
  public String getNamespaceURI()
  {
    return namespaceURI;
  }

  /**
   * Gets the Local part for this QName
   *
   * @return Local part
   */
  public String getLocalPart()
  {
    return localPart;
  }
  
  /**
   * Gets the prefix for this QName
   * 
   * @return prefix of this QName
   */
  public String getPrefix()
  {
      return prefix;
  }

  /**
   * Returns a string representation of this QName
   *
   * @return a string representation of the QName
   */
  public String toString()
  {
    return ((namespaceURI == emptyString)
            ? localPart
            : '{' + namespaceURI + '}' + localPart);
  }

  /**
   * Tests this QName for equality with another object.
   * <p>
   * If the given object is not a QName or is null then this method
   * returns <tt>false</tt>.
   * <p>
   * For two QNames to be considered equal requires that both
   * localPart and namespaceURI must be equal. This method uses
   * <code>String.equals</code> to check equality of localPart
   * and namespaceURI. Any class that extends QName is required
   * to satisfy this equality contract.
   * <p>
   * This method satisfies the general contract of the <code>Object.equals</code> method.
   *
   * @param obj the reference object with which to compare
   *
   * @return <code>true</code> if the given object is identical to this
   *      QName: <code>false</code> otherwise.
   */
  public final boolean equals(Object obj)
  {
    if (obj == this)
    {
      return true;
    }

    if (!(obj instanceof QName))
    {
      return false;
    }

    if ((namespaceURI == ((QName)obj).namespaceURI)
        && (localPart == ((QName)obj).localPart))
    {
      return true;
    }

    return false;
  }

  /**
   * Returns a QName holding the value of the specified String.
   * <p>
   * The string must be in the form returned by the QName.toString()
   * method, i.e. "{namespaceURI}localPart", with the "{namespaceURI}"
   * part being optional.
   * <p>
   * This method doesn't do a full validation of the resulting QName.
   * In particular, it doesn't check that the resulting namespace URI
   * is a legal URI (per RFC 2396 and RFC 2732), nor that the resulting
   * local part is a legal NCName per the XML Namespaces specification.
   *
   * @param s the string to be parsed
   * @throws java.lang.IllegalArgumentException If the specified String
   * cannot be parsed as a QName
   * @return QName corresponding to the given String
   */
  public static QName valueOf(String s)
  {
    if ((s == null) || s.equals(""))
    {
      throw new IllegalArgumentException("Invalid QName literal.");
    }

    if (s.charAt(0) == '{')
    {
      int i = s.indexOf('}');

      if (i == -1)
      {
        throw new IllegalArgumentException("Invalid QName literal.");
      }

      if (i == s.length() - 1)
      {
        throw new IllegalArgumentException("Invalid QName literal.");
      }
      else
      {
        return new QName(s.substring(1, i), s.substring(i + 1));
      }
    }
    else
    {
      return new QName(s);
    }
  }

  /**
   * Returns a hash code value for this QName object. The hash code
   * is based on both the localPart and namespaceURI parts of the
   * QName. This method satisfies the  general contract of the
   * <code>Object.hashCode</code> method.
   *
   * @return a hash code value for this Qname object
   */
  public final int hashCode()
  {
    return namespaceURI.hashCode() ^ localPart.hashCode();
  }

  private void readObject(ObjectInputStream in) throws IOException,
                                                       ClassNotFoundException
  {
    in.defaultReadObject();

    namespaceURI = namespaceURI.intern();
    localPart    = localPart.intern();
    if(prefix == null)
    {
        //The serialized object did not have a 'prefix'.
        //i.e. it was serialized from an old version of QName.
        prefix = emptyString;
    }
    else
    {
        prefix = prefix.intern();
    }
  }
}