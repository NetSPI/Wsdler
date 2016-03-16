/*
 * (c) Copyright IBM Corp 2001, 2010 
 */

package com.ibm.wsdl.util.xml;

import java.io.*;
import java.util.*;
import org.w3c.dom.*;
import com.ibm.wsdl.*;
import com.ibm.wsdl.util.*;

/**
 * This class is a utility to serialize a DOM node as XML. This class
 * uses the <code>DOM Level 2</code> APIs.
 * The main difference between this class and DOMWriter is that this class
 * generates and prints out namespace declarations.
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 * @author Joseph Kesselman
 */
public class DOM2Writer
{
  /**
   * The namespaceURI represented by the prefix <code>xmlns</code>.
   */
  private static String NS_URI_XMLNS = "http://www.w3.org/2000/xmlns/";

  /**
   * The namespaceURI represented by the prefix <code>xml</code>.
   */
  private static String NS_URI_XML = "http://www.w3.org/XML/1998/namespace";

  private static Map xmlEncodingMap = new HashMap();

  static
  {
    xmlEncodingMap.put(null, Constants.XML_DECL_DEFAULT);
    xmlEncodingMap.put(System.getProperty("file.encoding"),
                       Constants.XML_DECL_DEFAULT);
    xmlEncodingMap.put("UTF8", "UTF-8");
    xmlEncodingMap.put("UTF-16", "UTF-16");
    xmlEncodingMap.put("UnicodeBig", "UTF-16");
    xmlEncodingMap.put("UnicodeLittle", "UTF-16");
    xmlEncodingMap.put("ASCII", "US-ASCII");
    xmlEncodingMap.put("ISO8859_1", "ISO-8859-1");
    xmlEncodingMap.put("ISO8859_2", "ISO-8859-2");
    xmlEncodingMap.put("ISO8859_3", "ISO-8859-3");
    xmlEncodingMap.put("ISO8859_4", "ISO-8859-4");
    xmlEncodingMap.put("ISO8859_5", "ISO-8859-5");
    xmlEncodingMap.put("ISO8859_6", "ISO-8859-6");
    xmlEncodingMap.put("ISO8859_7", "ISO-8859-7");
    xmlEncodingMap.put("ISO8859_8", "ISO-8859-8");
    xmlEncodingMap.put("ISO8859_9", "ISO-8859-9");
    xmlEncodingMap.put("ISO8859_13", "ISO-8859-13");
    xmlEncodingMap.put("ISO8859_15_FDIS", "ISO-8859-15");
    xmlEncodingMap.put("GBK", "GBK");
    xmlEncodingMap.put("Big5", "Big5");
  }
  
  /**
   * Return a string containing this node serialized as XML.
   */
  public static String nodeToString(Node node)
  {
    return nodeToString(node, new HashMap());
  }
  
  /**
   * Return a string containing this node serialized as XML.
   * The specified Map associates prefixes with namespace URLs.
   */
  public static String nodeToString(Node node, Map namespaces)
  {
    StringWriter sw = new StringWriter();

    serializeAsXML(node, namespaces, sw);

    return sw.toString();
  }


  /**
   * Print an XML declaration before serializing the element.
   */
  public static void serializeElementAsDocument(Element el, Writer writer)
  {
    serializeElementAsDocument(el, new HashMap(), writer);
  }

  /**
   * Print an XML declaration before serializing the element.
   * The specified Map associates prefixes with namespace URLs.
   */
  public static void serializeElementAsDocument(Element el, Map namespaces, Writer writer)
  {
    PrintWriter pw = new PrintWriter(writer);
    String javaEncoding = (writer instanceof OutputStreamWriter)
                ? ((OutputStreamWriter) writer).getEncoding()
                : null;
                
    String xmlEncoding = java2XMLEncoding(javaEncoding);                
    
    if (xmlEncoding != null)
    { 
      pw.println(Constants.XML_DECL_START +
                 xmlEncoding +
                 Constants.XML_DECL_END);
    }
    else
    {
      pw.println("<?xml version=\"1.0\"?>");
    }

    serializeAsXML(el, namespaces, writer);
  }
  
  /**
  * Serialize this node into the writer as XML.
  */
  public static void serializeAsXML(Node node, Writer writer)
  {
    serializeAsXML(node, new HashMap(), writer);
  }
  
  /**
  * Serialize this node into the writer as XML.
  * The specified Map associates prefixes with namespace URLs.
  */
  public static void serializeAsXML(Node node, Map namespaces, Writer writer)
  {
    ObjectRegistry namespaceStack = new ObjectRegistry(namespaces);

    namespaceStack.register("xml", NS_URI_XML);

    PrintWriter pw = new PrintWriter(writer);
    String javaEncoding = (writer instanceof OutputStreamWriter)
                ? ((OutputStreamWriter) writer).getEncoding()
                : null;

    print(node, namespaceStack, pw, java2XMLEncoding(javaEncoding));
  }

  private static void print(Node node, ObjectRegistry namespaceStack,
                            PrintWriter out, String xmlEncoding)
  {
    if (node == null)
    {
      return;
    }

    boolean hasChildren = false;
    int type = node.getNodeType();

    switch (type)
    {
      case Node.DOCUMENT_NODE :
      {
        if (xmlEncoding != null)
        { 
          out.println(Constants.XML_DECL_START +
                     xmlEncoding +
	                 Constants.XML_DECL_END);
        }
        else
        {
          out.println("<?xml version=\"1.0\"?>");
        }

        Node child = node.getFirstChild();
        while (child != null)
        {
          print(child,namespaceStack, out, xmlEncoding);
          child = child.getNextSibling();
        }
        break;
      }

      case Node.ELEMENT_NODE :
      {
        namespaceStack = new ObjectRegistry(namespaceStack);

        out.print('<' + node.getNodeName());

        String elPrefix = node.getPrefix();
        String elNamespaceURI = node.getNamespaceURI();

        if (elPrefix != null && elNamespaceURI != null)
        {
          boolean prefixIsDeclared = false;

          try
          {
            String namespaceURI = (String)namespaceStack.lookup(elPrefix);

            if (elNamespaceURI.equals(namespaceURI))
            {
              prefixIsDeclared = true;
            }
          }
          catch (IllegalArgumentException e)
          {
            // ignore this and carry on
          }

          if (!prefixIsDeclared)
          {
            printNamespaceDecl(node, namespaceStack, out);
          }
        }

        NamedNodeMap attrs = node.getAttributes();
        int len = (attrs != null) ? attrs.getLength() : 0;

        for (int i = 0; i < len; i++)
        {
          Attr attr = (Attr)attrs.item(i);

          out.print(' ' + attr.getNodeName() +"=\"" +
                    normalize(attr.getValue()) + '\"');

          String attrPrefix = attr.getPrefix();
          String attrNamespaceURI = attr.getNamespaceURI();

          if (attrPrefix != null && attrNamespaceURI != null)
          {
            boolean prefixIsDeclared = false;

            try
            {
              String namespaceURI = (String)namespaceStack.lookup(attrPrefix);

              if (attrNamespaceURI.equals(namespaceURI))
              {
                prefixIsDeclared = true;
              }
            }
            catch (IllegalArgumentException e)
            {
              // ignore this and carry on
            }

            if (!prefixIsDeclared)
            {
              printNamespaceDecl(attr, namespaceStack, out);
            }
          }
        }

        Node child = node.getFirstChild();
        if (child != null)
        {
          hasChildren = true;
          out.print('>');
          
          while (child != null) 
          {   
            print(child, namespaceStack, out, xmlEncoding);
            child = child.getNextSibling();
          }
        }
        else 
        {
          hasChildren = false;
          out.print("/>");
        }
        break;
      }

      case Node.ENTITY_REFERENCE_NODE :
      {
        out.print('&');
        out.print(node.getNodeName());
        out.print(';');
        break;
      }

      case Node.CDATA_SECTION_NODE :
      {
        out.print("<![CDATA[");
        out.print(node.getNodeValue());
        out.print("]]>");
        break;
      }

      case Node.TEXT_NODE :
      {
        out.print(normalize(node.getNodeValue()));
        break;
      }

      case Node.COMMENT_NODE :
      {
        out.print("<!--");
        out.print(node.getNodeValue());
        out.print("-->");
        break;
      }

      case Node.PROCESSING_INSTRUCTION_NODE :
      {
        out.print("<?");
        out.print(node.getNodeName());

        String data = node.getNodeValue();

        if (data != null && data.length() > 0)
        {
          out.print(' ');
          out.print(data);
        }

        out.println("?>");
        break;
      }
    }

    if (type == Node.ELEMENT_NODE && hasChildren == true)
    {
      out.print("</");
      out.print(node.getNodeName());
      out.print('>');
      hasChildren = false;
    }
  }

  public static String java2XMLEncoding(String javaEnc)
  {
    return (String)xmlEncodingMap.get(javaEnc);
  }

  
  private static void printNamespaceDecl(Node node,
                                         ObjectRegistry namespaceStack,
                                         PrintWriter out)
  {
    switch (node.getNodeType())
    {
      case Node.ATTRIBUTE_NODE :
      {
        printNamespaceDecl(((Attr)node).getOwnerElement(), node,
                           namespaceStack, out);
        break;
      }

      case Node.ELEMENT_NODE :
      {
        printNamespaceDecl((Element)node, node, namespaceStack, out);
        break;
      }
    }
  }

  private static void printNamespaceDecl(Element owner, Node node,
                                         ObjectRegistry namespaceStack,
                                         PrintWriter out)
  {
    String namespaceURI = node.getNamespaceURI();
    String prefix = node.getPrefix();

    if (!(namespaceURI.equals(NS_URI_XMLNS) && prefix.equals("xmlns")))
    {
      if (DOMUtils.getAttributeNS(owner, NS_URI_XMLNS, prefix) == null)
      {
        out.print(" xmlns:" + prefix + "=\"" + namespaceURI + '\"');
      }
    }
    else
    {
      prefix = node.getLocalName();
      namespaceURI = node.getNodeValue();
    }

    namespaceStack.register(prefix, namespaceURI);
  }

  private static String normalize(String s)
  {
    StringBuffer str = new StringBuffer();
    int len = (s != null) ? s.length() : 0;

    for (int i = 0; i < len; i++)
    {
      char ch = s.charAt(i);

      switch (ch)
      {
        case '<' :
        {
          str.append("&lt;");
          break;
        }
        case '>' :
        {
          str.append("&gt;");
          break;
        }
        case '&' :
        {
          str.append("&amp;");
          break;
        }
        case '"' :
        {
          str.append("&quot;");
          break;
        }
        case '\n' :
        {
          if (i > 0)
          {
            char lastChar = str.charAt(str.length() - 1);

            if (lastChar != '\r')
            {
              str.append(StringUtils.lineSeparator);
            }
            else
            {
              str.append('\n');
            }
          }
          else
          {
            str.append(StringUtils.lineSeparator);
          }
          break;
        }
        default :
        {
          str.append(ch);
        }
      }
    }

    return (str.toString());
  }
}