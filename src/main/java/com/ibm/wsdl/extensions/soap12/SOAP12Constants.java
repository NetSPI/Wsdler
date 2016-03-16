/*
 * (c) Copyright IBM Corp 2006 
 */

package com.ibm.wsdl.extensions.soap12;

import javax.xml.namespace.*;
import com.ibm.wsdl.*;

/**
 * Based on com.ibm.wsdl.extensions.soap.SOAPConstants
 */
public class SOAP12Constants
{
  // Namespace URIs.
  public static final String NS_URI_SOAP12 =
    "http://schemas.xmlsoap.org/wsdl/soap12/";

  // Element names.
  public static final String ELEM_BODY = "body";
  public static final String ELEM_HEADER = "header";
  public static final String ELEM_HEADER_FAULT = "headerfault";
  public static final String ELEM_ADDRESS = "address";

  // Qualified element names.
  public static final QName Q_ELEM_SOAP_BINDING =
    new QName(NS_URI_SOAP12, Constants.ELEM_BINDING);
  public static final QName Q_ELEM_SOAP_BODY =
    new QName(NS_URI_SOAP12, ELEM_BODY);
  public static final QName Q_ELEM_SOAP_HEADER =
    new QName(NS_URI_SOAP12, ELEM_HEADER);
  public static final QName Q_ELEM_SOAP_HEADER_FAULT =
    new QName(NS_URI_SOAP12, ELEM_HEADER_FAULT);
  public static final QName Q_ELEM_SOAP_ADDRESS =
    new QName(NS_URI_SOAP12, ELEM_ADDRESS);
  public static final QName Q_ELEM_SOAP_OPERATION =
    new QName(NS_URI_SOAP12, Constants.ELEM_OPERATION);
  public static final QName Q_ELEM_SOAP_FAULT =
    new QName(NS_URI_SOAP12, Constants.ELEM_FAULT);

  // Attribute names.
  public static final String ATTR_TRANSPORT = "transport";
  public static final String ATTR_STYLE = "style";
  public static final String ATTR_SOAP_ACTION = "soapAction";
  public static final String ATTR_SOAP_ACTION_REQUIRED = "soapActionRequired";
  public static final String ATTR_PARTS = "parts";
  public static final String ATTR_USE = "use";
  public static final String ATTR_ENCODING_STYLE = "encodingStyle";
  public static final String ATTR_PART = "part";
}