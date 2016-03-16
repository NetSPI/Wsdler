/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.extensions.mime;

import javax.xml.namespace.*;
import com.ibm.wsdl.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class MIMEConstants
{
  // Namespace URIs.
  public static final String NS_URI_MIME =
    "http://schemas.xmlsoap.org/wsdl/mime/";

  // Element names.
  public static final String ELEM_CONTENT = "content";
  public static final String ELEM_MULTIPART_RELATED = "multipartRelated";
  public static final String ELEM_MIME_XML = "mimeXml";

  // Qualified element names.
  public static final QName Q_ELEM_MIME_CONTENT =
    new QName(NS_URI_MIME, ELEM_CONTENT);
  public static final QName Q_ELEM_MIME_MULTIPART_RELATED =
    new QName(NS_URI_MIME, ELEM_MULTIPART_RELATED);
  public static final QName Q_ELEM_MIME_PART =
    new QName(NS_URI_MIME, Constants.ELEM_PART);
  public static final QName Q_ELEM_MIME_MIME_XML =
    new QName(NS_URI_MIME, ELEM_MIME_XML);

  // Attribute names.
  public static final String ATTR_PART = "part";
}