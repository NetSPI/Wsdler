/*
 * (c) Copyright IBM Corp 2001, 2006 
 */

package com.ibm.wsdl.util;

import java.util.*;

/**
 * The <em>ObjectRegistry</em> is used to do name-to-object reference lookups.
 * If an <em>ObjectRegistry</em> is passed as a constructor argument, then this
 * <em>ObjectRegistry</em> will be a cascading registry: when a lookup is
 * invoked, it will first look in its own table for a name, and if it's not
 * there, it will cascade to the parent <em>ObjectRegistry</em>.
 * All registration is always local. [??]
 * 
 * @author   Sanjiva Weerawarana
 * @author   Matthew J. Duftler
 */
public class ObjectRegistry {
  Hashtable      reg    = new Hashtable ();
  ObjectRegistry parent = null;

  public ObjectRegistry () {
  }
  
  public ObjectRegistry (Map initialValues) {
    if(initialValues != null)
    {
      Iterator itr = initialValues.keySet().iterator();
      while(itr.hasNext())
      {
        String name = (String) itr.next();
        register(name, initialValues.get(name));
      }
    }
  }

  public ObjectRegistry (ObjectRegistry parent) {
    this.parent = parent;
  }

  // register an object
  public void register (String name, Object obj) {
    reg.put (name, obj);
  }

  // unregister an object (silent if unknown name)
  public void unregister (String name) {
    reg.remove (name);
  }

  // lookup an object: cascade up if needed
  public Object lookup (String name) throws IllegalArgumentException {
    Object obj = reg.get (name);

    if (obj == null && parent != null) {
      obj = parent.lookup (name);
    }

    if (obj == null) {
      throw new IllegalArgumentException ("object '" + name + "' not in registry");
    }

    return obj;
  }
}