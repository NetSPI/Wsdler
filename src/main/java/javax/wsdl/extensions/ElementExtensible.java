/*
 * (c) Copyright IBM Corp 2004, 2006 
 */

package javax.wsdl.extensions;

import java.util.*;
import javax.wsdl.extensions.ExtensibilityElement;

/**
 * Classes that implement this interface can contain extensibility
 * elements.
 * 
 * @author John Kaputin
 */
public interface ElementExtensible {
    
    /**
     * Add an extensibility element.
     *
     * @param extElement the extensibility element to be added
     */
    public void addExtensibilityElement(ExtensibilityElement extElement);
    
    /**
     * Remove an extensibility element.
     *
     * @param extElement the extensibility element to be removed
     * @return the extensibility element which was removed
     */
    public ExtensibilityElement removeExtensibilityElement(ExtensibilityElement extElement);

    /**
     * Get all the extensibility elements defined here.
     */
    public List getExtensibilityElements();


}
