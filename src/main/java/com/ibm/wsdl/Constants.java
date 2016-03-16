/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl;

import javax.xml.namespace.*;

/**
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class Constants
{
  // Namespace URIs.
  public static final String NS_URI_WSDL =
    "http://schemas.xmlsoap.org/wsdl/";
  public static final String NS_URI_XMLNS =
    "http://www.w3.org/2000/xmlns/";

  // Top-level element names.
  public static final String ELEM_DEFINITIONS = "definitions";
  public static final String ELEM_IMPORT = "import";
  public static final String ELEM_TYPES = "types";
  public static final String ELEM_MESSAGE = "message";
  public static final String ELEM_PORT_TYPE = "portType";
  public static final String ELEM_BINDING = "binding";
  public static final String ELEM_SERVICE = "service";

  // Non top-level element names.
  public static final String ELEM_PART = "part";
  public static final String ELEM_OPERATION = "operation";
  public static final String ELEM_INPUT = "input";
  public static final String ELEM_OUTPUT = "output";
  public static final String ELEM_FAULT = "fault";
  public static final String ELEM_PORT = "port";
  public static final String ELEM_DOCUMENTATION = "documentation";

  // Top-level qualified element names.
  public static final QName Q_ELEM_DEFINITIONS =
    new QName(NS_URI_WSDL, ELEM_DEFINITIONS);
  public static final QName Q_ELEM_IMPORT =
    new QName(NS_URI_WSDL, ELEM_IMPORT);
  public static final QName Q_ELEM_TYPES =
    new QName(NS_URI_WSDL, ELEM_TYPES);
  public static final QName Q_ELEM_MESSAGE =
    new QName(NS_URI_WSDL, ELEM_MESSAGE);
  public static final QName Q_ELEM_PORT_TYPE =
    new QName(NS_URI_WSDL, ELEM_PORT_TYPE);
  public static final QName Q_ELEM_BINDING =
    new QName(NS_URI_WSDL, ELEM_BINDING);
  public static final QName Q_ELEM_SERVICE =
    new QName(NS_URI_WSDL, ELEM_SERVICE);

  // Non top-level qualified element names.
  public static final QName Q_ELEM_PART =
    new QName(NS_URI_WSDL, ELEM_PART);
  public static final QName Q_ELEM_OPERATION =
    new QName(NS_URI_WSDL, ELEM_OPERATION);
  public static final QName Q_ELEM_INPUT =
    new QName(NS_URI_WSDL, ELEM_INPUT);
  public static final QName Q_ELEM_OUTPUT =
    new QName(NS_URI_WSDL, ELEM_OUTPUT);
  public static final QName Q_ELEM_FAULT =
    new QName(NS_URI_WSDL, ELEM_FAULT);
  public static final QName Q_ELEM_PORT =
    new QName(NS_URI_WSDL, ELEM_PORT);
  public static final QName Q_ELEM_DOCUMENTATION =
    new QName(NS_URI_WSDL, ELEM_DOCUMENTATION);

  // Attribute names.
  public static final String ATTR_NAME = "name";
  public static final String ATTR_TARGET_NAMESPACE = "targetNamespace";
  public static final String ATTR_ELEMENT = "element";
  public static final String ATTR_TYPE = "type";
  public static final String ATTR_MESSAGE = "message";
  public static final String ATTR_PARAMETER_ORDER = "parameterOrder";
  public static final String ATTR_BINDING = "binding";
  public static final String ATTR_XMLNS = "xmlns";
  public static final String ATTR_NAMESPACE = "namespace";
  public static final String ATTR_LOCATION = "location";
  public static final String ATTR_REQUIRED = "required";

  // Lists of native attribute names.
  public static final String[] DEFINITION_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_TARGET_NAMESPACE};
  public static final String[] PART_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_TYPE, ATTR_ELEMENT};
  public static final String[] BINDING_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_TYPE};
  public static final String[] BINDING_FAULT_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] BINDING_INPUT_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] BINDING_OPERATION_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] BINDING_OUTPUT_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] FAULT_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_MESSAGE};
  public static final String[] IMPORT_ATTR_NAMES =
    new String[]{ATTR_NAMESPACE, ATTR_LOCATION};
  public static final String[] INPUT_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_MESSAGE};
  public static final String[] MESSAGE_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] OPERATION_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_PARAMETER_ORDER};
  public static final String[] OUTPUT_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_MESSAGE};
  public static final String[] PORT_ATTR_NAMES =
    new String[]{ATTR_NAME, ATTR_BINDING};
  public static final String[] PORT_TYPE_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] SERVICE_ATTR_NAMES =
    new String[]{ATTR_NAME};
  public static final String[] TYPES_ATTR_NAMES =
    new String[]{};

  // Qualified attribute names.
  public static final QName Q_ATTR_REQUIRED =
    new QName(NS_URI_WSDL, ATTR_REQUIRED);

  // XML Declaration string.
  public static final String XML_DECL_DEFAULT = "UTF-8";
  public static final String XML_DECL_START =
    "<?xml version=\"1.0\" encoding=\"";
  public static final String XML_DECL_END = "\"?>";

  // Feature names.
  public static final String FEATURE_VERBOSE = "javax.wsdl.verbose";
  public static final String FEATURE_IMPORT_DOCUMENTS =
    "javax.wsdl.importDocuments";
  public static final String FEATURE_PARSE_SCHEMA =
      "com.ibm.wsdl.parseXMLSchemas";

  // Other
  public static final String NONE = ":none";
}
