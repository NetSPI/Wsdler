/*
 * (c) Copyright IBM Corp 2001, 2005 
 */

package com.ibm.wsdl.util;

import java.io.*;

/**
 * This file is a collection of input/output utilities.
 * 
 * @author   Sanjiva Weerawarana
 * @author   Matthew J. Duftler
 */
public class IOUtils {
  // debug flag - generates debug stuff if true
  static boolean debug = false;

  //////////////////////////////////////////////////////////////////////////

  public static String getStringFromReader (Reader reader) throws IOException {
    BufferedReader bufIn = new BufferedReader(reader);
    StringWriter   swOut = new StringWriter();
    PrintWriter    pwOut = new PrintWriter(swOut);
    String         tempLine;

    while ((tempLine = bufIn.readLine()) != null) {
      pwOut.println(tempLine);
    }

    pwOut.flush();

    return swOut.toString();
  }
}

