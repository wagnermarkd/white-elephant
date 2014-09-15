package com.linkedin.whiteelephant.parsing;

import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.Test;

public class TestParsing {

  private static String quotedTextPattern = "\"([^\"]+)\"";
  private static String timestampPattern = "([^ ]+ [^ ]+)";
  private static Pattern parameterPattern = Pattern.compile("(.+)="
      + quotedTextPattern);
  private static Pattern auditLinePattern = Pattern.compile(String
      .format("%s INFO FSNamesystem.audit: ugi=([^\\t]*)\\tip=([^\\t]*)\\tcmd=([^\\t]*)\\tsrc=([^\\t]*)\\tdst=([^\\t]*)\\tperm=([^\\t]*)", timestampPattern,
          parameterPattern));

  @Test
  public void testParse() throws ParseException {
    String line =
        "2014-05-01 23:59:59,985 INFO FSNamesystem.audit: ugi=search via azkaban/eat1-magicaz01.grid.linkedin.com@GRID.LINKEDIN.COM\tip=/172.20.158.27\tcmd=create\tsrc=/tmp/temp-1522806959/tmp1711089800/ds-udf-pig-0.3.4.jar\tdst=null\tperm=search:users:rw-r--r--";
    Matcher paramMatcher = auditLinePattern.matcher(line);
    if (paramMatcher.find()) {
      System.out.println(paramMatcher.groupCount());
      String stamp = paramMatcher.group(1);
      DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");
      System.out.println(format.parse(stamp).getTime());
      System.out.println(paramMatcher.group(1));
      System.out.println(paramMatcher.group(2));
      System.out.println(paramMatcher.group(3));
      System.out.println(paramMatcher.group(4));
      System.out.println(paramMatcher.group(5));
      System.out.println(paramMatcher.group(6));
      System.out.println(paramMatcher.group(7));
    }
  }
}
