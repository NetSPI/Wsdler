/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package javax.wsdl.extensions;

import java.util.*;
import javax.wsdl.*;
import javax.xml.namespace.*;

/**
 * This class is used to associate serializers, deserializers, and
 * Java implementation types with extensibility elements.
 *
 * @author Matthew J. Duftler (duftler@us.ibm.com)
 */
public class ExtensionRegistry implements java.io.Serializable
{
  public static final long serialVersionUID = 1;

  /**
   * Creates the extension registry, and sets the defaultSerializer
   * and defaultDeserializer properties to instances of an
   * UnknownExtensionSerializer, and an UnknownExtensionDeserializer,
   * respectively.
   */
  public ExtensionRegistry()
  {
    setDefaultSerializer(new UnknownExtensionSerializer());
    setDefaultDeserializer(new UnknownExtensionDeserializer());
  }

  /*
    This is a Map of Maps. The top-level Map is keyed by (Class)parentType,
    and the inner Maps are keyed by (QName)elementType.
  */
  protected Map serializerReg = new Hashtable();
  /*
    This is a Map of Maps. The top-level Map is keyed by (Class)parentType,
    and the inner Maps are keyed by (QName)elementType.
  */
  protected Map deserializerReg = new Hashtable();
  /*
    This is a Map of Maps. The top-level Map is keyed by (Class)parentType,
    and the inner Maps are keyed by (QName)elementType.
  */
  protected Map extensionTypeReg = new Hashtable();
  protected ExtensionSerializer defaultSer = null;
  protected ExtensionDeserializer defaultDeser = null;
  /*
    This is a Map of Maps. The top-level Map is keyed by (Class)parentType,
    and the inner Maps are keyed by (QName)attrName.
  */
  protected Map extensionAttributeTypeReg = new Hashtable();

  /**
   * Set the serializer to be used when none is found for an extensibility
   * element. Set this to null to have an exception thrown when
   * unexpected extensibility elements are encountered. Default value is
   * an instance of UnknownExtensionSerializer.
   *
   * @see UnknownExtensionSerializer
   */
  public void setDefaultSerializer(ExtensionSerializer defaultSer)
  {
    this.defaultSer = defaultSer;
  }

  /**
   * Get the serializer to be used when none is found for an extensibility
   * element. Default value is an instance of UnknownExtensionSerializer.
   *
   * @see UnknownExtensionSerializer
   */
  public ExtensionSerializer getDefaultSerializer()
  {
    return defaultSer;
  }

  /**
   * Set the deserializer to be used when none is found for an encountered
   * element. Set this to null to have an exception thrown when
   * unexpected extensibility elements are encountered. Default value is
   * an instance of UnknownExtensionDeserializer.
   *
   * @see UnknownExtensionDeserializer
   */
  public void setDefaultDeserializer(ExtensionDeserializer defaultDeser)
  {
    this.defaultDeser = defaultDeser;
  }

  /**
   * Get the deserializer to be used when none is found for an encountered
   * element. Default value is an instance of UnknownExtensionDeserializer.
   *
   * @see UnknownExtensionDeserializer
   */
  public ExtensionDeserializer getDefaultDeserializer()
  {
    return defaultDeser;
  }

  /**
   * Declare that the specified serializer should be used to serialize
   * all extensibility elements with a qname matching elementType, when
   * encountered as children of the specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * definition this extension was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this extensibility element was found in the list of
   * extensibility elements belonging to a javax.wsdl.Binding.
   * @param elementType the qname of the extensibility element
   * @param es the extension serializer to use
   *
   * @see #querySerializer(Class, QName)
   */
  public void registerSerializer(Class parentType,
                                 QName elementType,
                                 ExtensionSerializer es)
  {
    Map innerSerializerReg = (Map)serializerReg.get(parentType);

    if (innerSerializerReg == null)
    {
      innerSerializerReg = new Hashtable();

      serializerReg.put(parentType, innerSerializerReg);
    }

    innerSerializerReg.put(elementType, es);
  }

  /**
   * Declare that the specified deserializer should be used to deserialize
   * all extensibility elements with a qname matching elementType, when
   * encountered as immediate children of the element represented by the
   * specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * document this extensibility element was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this element was encountered as an immediate child of
   * a &lt;wsdl:binding&gt; element.
   * @param elementType the qname of the extensibility element
   * @param ed the extension deserializer to use
   *
   * @see #queryDeserializer(Class, QName)
   */
  public void registerDeserializer(Class parentType,
                                   QName elementType,
                                   ExtensionDeserializer ed)
  {
    Map innerDeserializerReg = (Map)deserializerReg.get(parentType);

    if (innerDeserializerReg == null)
    {
      innerDeserializerReg = new Hashtable();

      deserializerReg.put(parentType, innerDeserializerReg);
    }

    innerDeserializerReg.put(elementType, ed);
  }

  /**
   * Look up the serializer to use for the extensibility element with
   * the qname elementType, which was encountered as a child of the
   * specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * definition this extension was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this extensibility element was found in the list of
   * extensibility elements belonging to a javax.wsdl.Binding.
   * @param elementType the qname of the extensibility element
   *
   * @return the extension serializer, if one was found. If none was
   * found, the behavior depends on the value of the defaultSerializer
   * property. If the defaultSerializer property is set to a non-null
   * value, that value is returned; otherwise, a WSDLException is
   * thrown.
   *
   * @see #registerSerializer(Class, QName, ExtensionSerializer)
   * @see #setDefaultSerializer(ExtensionSerializer)
   */
  public ExtensionSerializer querySerializer(Class parentType,
                                             QName elementType)
                                               throws WSDLException
  {
    Map innerSerializerReg = (Map)serializerReg.get(parentType);
    ExtensionSerializer es = null;

    if (innerSerializerReg != null)
    {
      es = (ExtensionSerializer)innerSerializerReg.get(elementType);
    }

    if (es == null)
    {
      es = defaultSer;
    }

    if (es == null)
    {
      throw new WSDLException(WSDLException.CONFIGURATION_ERROR,
                              "No ExtensionSerializer found " +
                              "to serialize a '" + elementType +
                              "' element in the context of a '" +
                              parentType.getName() + "'.");
    }

    return es;
  }

  /**
   * Look up the deserializer for the extensibility element with the
   * qname elementType, which was encountered as an immediate child
   * of the element represented by the specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * document this extensibility element was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this element was encountered as an immediate child of
   * a &lt;wsdl:binding&gt; element.
   * @param elementType the qname of the extensibility element
   *
   * @return the extension deserializer, if one was found. If none was
   * found, the behavior depends on the value of the defaultDeserializer
   * property. If the defaultDeserializer property is set to a non-null
   * value, that value is returned; otherwise, a WSDLException is thrown.
   *
   * @see #registerDeserializer(Class, QName, ExtensionDeserializer)
   * @see #setDefaultDeserializer(ExtensionDeserializer)
   */
  public ExtensionDeserializer queryDeserializer(Class parentType,
                                                 QName elementType)
                                                   throws WSDLException
  {
    Map innerDeserializerReg = (Map)deserializerReg.get(parentType);
    ExtensionDeserializer ed = null;

    if (innerDeserializerReg != null)
    {
      ed = (ExtensionDeserializer)innerDeserializerReg.get(elementType);
    }

    if (ed == null)
    {
      ed = defaultDeser;
    }

    if (ed == null)
    {
      throw new WSDLException(WSDLException.CONFIGURATION_ERROR,
                              "No ExtensionDeserializer found " +
                              "to deserialize a '" + elementType +
                              "' element in the context of a '" +
                              parentType.getName() + "'.");
    }

    return ed;
  }

  /**
   * Returns a set of QNames representing the extensibility elements
   * that are allowed as children of the specified parent type.
   * Basically, this method returns the keys associated with the set
   * of extension deserializers registered for this parent type.
   * Returns null if no extension deserializers are registered for
   * this parent type.
   */
  public Set getAllowableExtensions(Class parentType)
  {
    Map innerDeserializerReg = (Map)deserializerReg.get(parentType);

    return (innerDeserializerReg != null)
           ? innerDeserializerReg.keySet()
           : null;
  }

  /**
   * Declare that the specified extensionType is the concrete
   * class which should be used to represent extensibility elements
   * with qnames matching elementType, that are intended to exist as
   * children of the specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * definition this extension would exist. For example,
   * javax.wsdl.Binding.class would be used to indicate
   * this extensibility element would be added to the list of
   * extensibility elements belonging to a javax.wsdl.Binding,
   * after being instantiated.
   * @param elementType the qname of the extensibility element
   * @param extensionType the concrete class which should be instantiated
   *
   * @see #createExtension(Class, QName)
   */
  public void mapExtensionTypes(Class parentType,
                                QName elementType,
                                Class extensionType)
  {
    Map innerExtensionTypeReg = (Map)extensionTypeReg.get(parentType);

    if (innerExtensionTypeReg == null)
    {
      innerExtensionTypeReg = new Hashtable();

      extensionTypeReg.put(parentType, innerExtensionTypeReg);
    }

    innerExtensionTypeReg.put(elementType, extensionType);
  }

  /**
   * Create an instance of the type which was declared to be used to
   * represent extensibility elements with qnames matching elementType,
   * when intended to exist as children of the specified parentType.
   * This method allows a user to instantiate an extensibility element
   * without having to know the implementing type.
   *
   * @param parentType a class object indicating where in the WSDL
   * definition this extension will exist. For example,
   * javax.wsdl.Binding.class would be used to indicate
   * this extensibility element is going to be added to the list of
   * extensibility elements belonging to a javax.wsdl.Binding,
   * after being instantiated.
   * @param elementType the qname of the extensibility element
   *
   * @return a new instance of the type used to represent the
   * specified extension
   *
   * @see #mapExtensionTypes(Class, QName, Class)
   */
  public ExtensibilityElement createExtension(Class parentType,
                                              QName elementType)
                                                throws WSDLException
  {
    Map innerExtensionTypeReg = (Map)extensionTypeReg.get(parentType);
    Class extensionType = null;

    if (innerExtensionTypeReg != null)
    {
      extensionType = (Class)innerExtensionTypeReg.get(elementType);
    }

    if (extensionType == null)
    {
      throw new WSDLException(WSDLException.CONFIGURATION_ERROR,
                              "No Java extensionType found " +
                              "to represent a '" + elementType +
                              "' element in the context of a '" +
                              parentType.getName() + "'.");
    }
    else if (!(ExtensibilityElement.class.isAssignableFrom(extensionType)))
    {
      throw new WSDLException(WSDLException.CONFIGURATION_ERROR,
                              "The Java extensionType '" +
                              extensionType.getName() + "' does " +
                              "not implement the ExtensibilityElement " +
                              "interface.");
    }

    try
    {
      ExtensibilityElement ee = (ExtensibilityElement)extensionType.newInstance();
      
      if (ee.getElementType() == null)
      {
        ee.setElementType(elementType);
      }
      
      return ee;
    }
    catch (Exception e)
    {
      /*
        Catches:
                 InstantiationException
                 IllegalAccessException
      */
      throw new WSDLException(WSDLException.CONFIGURATION_ERROR,
                              "Problem instantiating Java " +
                              "extensionType '" + extensionType.getName() +
                              "'.",
                              e);
    }
  }

  /**
   * Declare that the type of the specified extension attribute, when it occurs
   * as an attribute of the specified parent type, should be assumed to be
   * attrType.
   *
   * @param parentType a class object indicating where in the WSDL
   * document this extensibility attribute was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this attribute was defined on a &lt;wsdl:binding> element.
   * @param attrName the qname of the extensibility attribute
   * @param attrType one of the constants defined on the AttributeExtensible
   * class
   *
   * @see #queryExtensionAttributeType(Class, QName)
   * @see AttributeExtensible
   */
  public void registerExtensionAttributeType(Class parentType,
                                             QName attrName,
                                             int attrType)
  {
    Map innerExtensionAttributeTypeReg =
      (Map)extensionAttributeTypeReg.get(parentType);

    if (innerExtensionAttributeTypeReg == null)
    {
      innerExtensionAttributeTypeReg = new Hashtable();

      extensionAttributeTypeReg.put(parentType, innerExtensionAttributeTypeReg);
    }

    innerExtensionAttributeTypeReg.put(attrName, new Integer(attrType));
  }

  /**
   * Look up the type of the extensibility attribute with the qname attrName,
   * which was defined on an element represented by the specified parentType.
   *
   * @param parentType a class object indicating where in the WSDL
   * document this extensibility attribute was encountered. For
   * example, javax.wsdl.Binding.class would be used to indicate
   * this attribute was defined on a &lt;wsdl:binding> element.
   * @param attrName the qname of the extensibility attribute
   *
   * @return one of the constants defined on the AttributeExtensible class
   *
   * @see #registerExtensionAttributeType(Class, QName, int)
   * @see AttributeExtensible
   */
  public int queryExtensionAttributeType(Class parentType, QName attrName)
  {
    Map innerExtensionAttributeTypeReg =
      (Map)extensionAttributeTypeReg.get(parentType);
    Integer attrType = null;

    if (innerExtensionAttributeTypeReg != null)
    {
      attrType = (Integer)innerExtensionAttributeTypeReg.get(attrName);
    }

    if (attrType != null)
    {
      return attrType.intValue();
    }
    else
    {
      return AttributeExtensible.NO_DECLARED_TYPE;
    }
  }
}