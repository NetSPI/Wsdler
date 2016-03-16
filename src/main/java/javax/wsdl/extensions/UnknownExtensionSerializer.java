/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package javax.wsdl.extensions;

import java.io.*;
import javax.wsdl.*;
import javax.xml.namespace.*;
import com.ibm.wsdl.util.xml.*;

/**
 * This class is used to serialize UnknownExtensibilityElement instances
 * into the PrintWriter.
 *
 * @see UnknownExtensibilityElement
 * @see UnknownExtensionDeserializer
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class UnknownExtensionSerializer implements ExtensionSerializer,
                                                   Serializable
{
  public static final long serialVersionUID = 1;

  public void marshall(Class parentType,
                       QName elementType,
                       ExtensibilityElement extension,
                       PrintWriter pw,
                       Definition def,
                       ExtensionRegistry extReg)
                         throws WSDLException
  {
    UnknownExtensibilityElement unknownExt =
      (UnknownExtensibilityElement)extension;

    pw.print("    ");

    DOM2Writer.serializeAsXML(unknownExt.getElement(), def.getNamespaces(), pw);

    pw.println();
  }
}