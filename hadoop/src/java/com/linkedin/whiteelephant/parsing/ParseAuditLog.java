/*
 * Copyright 2012 LinkedIn, Inc
 * 
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */

package com.linkedin.whiteelephant.parsing;

import java.io.IOException;
import java.text.DateFormat;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.Properties;
import java.util.TimeZone;
import java.util.concurrent.ExecutionException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.avro.mapred.AvroKey;
import org.apache.avro.mapred.AvroWrapper;
import org.apache.avro.mapreduce.AvroJob;
import org.apache.avro.mapreduce.AvroKeyOutputFormat;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.fs.FileStatus;
import org.apache.hadoop.fs.FileSystem;
import org.apache.hadoop.fs.Path;
import org.apache.hadoop.io.BytesWritable;
import org.apache.hadoop.io.LongWritable;
import org.apache.hadoop.io.NullWritable;
import org.apache.hadoop.io.Text;
import org.apache.hadoop.mapreduce.Mapper;
import org.apache.hadoop.mapreduce.lib.input.CombineFileInputFormat;
import org.apache.log4j.Logger;

import com.linkedin.whiteelephant.mapreduce.lib.input.CombinedTextInputFormat;
import com.linkedin.whiteelephant.mapreduce.lib.job.StagedOutputJob;
import com.linkedin.whiteelephant.mapreduce.lib.job.StagedOutputJobExecutor;
import com.linkedin.whiteelephant.util.JobStatsProcessing;
import com.linkedin.whiteelephant.util.JobStatsProcessing.ProcessingTask;

public class ParseAuditLog
{
  private final Logger _log;
  private final Properties _props;
  private final FileSystem _fs;
  private final String _name;

  private final String _jobsAuditPathRoot;
  private final String _logsRoot;
  private final String _clusterNames;
  private final int _numDays;
  private final int _numDaysForced;
  private final boolean _incremental;

  public ParseAuditLog(String name, Properties props) throws IOException
  {
    _log = Logger.getLogger(name);
    _name = name;
    _props = props;

    Configuration conf = StagedOutputJob.createConfigurationFromProps(_props);

    System.out.println("fs.default.name: " + conf.get("fs.default.name"));

    _fs = FileSystem.get(conf);

    if (_props.get("cluster.names") == null) {
      throw new IllegalArgumentException("cluster.names is not specified.");
    }

    if (_props.get("jobs.output.path") == null) {
      throw new IllegalArgumentException("attempts.output.path is not specified.");
    }

    if (_props.get("num.days") == null) {
      throw new IllegalArgumentException("num.days is not specified");
    }

    if (_props.get("num.days.forced") == null) {
      throw new IllegalArgumentException("num.days.forced is not specified");
    }

    if (_props.get("incremental") == null) {
      throw new IllegalArgumentException("incremental is not specified.");
    }

    if (_props.get("logs.root") == null) {
      throw new IllegalArgumentException("logs.root is not specified.");
    }

    _jobsAuditPathRoot = (String)_props.get("audit.output.path");
    _logsRoot = (String)_props.get("audit.root");
    _clusterNames = (String)_props.get("cluster.names");
    _numDays = Integer.parseInt((String)_props.get("num.days"));
    _numDaysForced = Integer.parseInt((String)_props.get("num.days.forced"));
    _incremental = Boolean.parseBoolean((String)_props.get("incremental"));
  }

  public void execute(StagedOutputJobExecutor executor) throws IOException, InterruptedException, ExecutionException
  {
    for (String clusterName : _clusterNames.split(","))
    {
      System.out.println("Processing cluster " + clusterName);

      List<JobStatsProcessing.ProcessingTask> processingTasks = getTasks(_fs, _logsRoot, clusterName, _jobsAuditPathRoot, _incremental, _numDays, _numDaysForced);

      for (JobStatsProcessing.ProcessingTask task : processingTasks)
      {
        List<String> inputPaths = new ArrayList<String>();
        inputPaths.add(task.inputPathFormat);

        String outputPath = task.outputPath;

        final StagedOutputJob job = StagedOutputJob.createStagedJob(
            _props,
            _name + "-parse-audit-" + task.id,
            inputPaths,
            "/tmp" + outputPath,
            outputPath,
            _log);

        job.getConfiguration().setLong("mapreduce.input.fileinputformat.split.maxsize", 1024*1024*1024);

        job.getConfiguration().set("jobs.output.path", _jobsAuditPathRoot);
        job.getConfiguration().set("logs.cluster.name", clusterName);

        job.setOutputKeyClass(BytesWritable.class);
        job.setOutputValueClass(NullWritable.class);

        job.setInputFormatClass(CombinedTextInputFormat.class);
        job.setOutputFormatClass(AvroKeyOutputFormat.class);

        AvroJob.setOutputKeySchema(job, AuditLogData.SCHEMA$);

        job.setNumReduceTasks(0);

        job.setMapperClass(TheMapper.class);

        executor.submit(job);
      }

      executor.waitForCompletion();
    }
  }

  public static class TheMapper extends Mapper<LongWritable, Text, AvroWrapper<AuditLogData>, NullWritable>
  {

    private static String timestampPattern = "([^ ]+ [^ ]+)";
    private static Pattern auditLinePattern = Pattern.compile(String
        .format("%s INFO FSNamesystem.audit: ugi=([^\\t]*)\\tip=([^\\t]*)\\tcmd=([^\\t]*)\\tsrc=([^\\t]*)\\tdst=([^\\t]*)\\tperm=([^\\t]*)", timestampPattern));
    private static Pattern permPattern = Pattern.compile("([^:]*):([^:]*):(.*)");

    String _clusterName;
    int logged = 0;
    Logger mapLogger = Logger.getLogger(getClass());

    @Override
    protected void setup(Context context)
    {
      _clusterName = context.getConfiguration().get("logs.cluster.name");
    }

    @Override
    protected void map(LongWritable row, Text value, Context context)
        throws IOException, InterruptedException {
      AuditLogData data = new AuditLogData();
      data.setCluster(_clusterName);

      String line = value.toString();
      AuditEntry entry = new AuditEntry();
      Matcher paramMatcher = auditLinePattern.matcher(line);
      if (paramMatcher.find()) {
        System.out.println(paramMatcher.groupCount());
        String stamp = paramMatcher.group(1);
        DateFormat format = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss,SSS");
        try {
          entry.setTime(format.parse(stamp).getTime());
        } catch (ParseException e) {
          throw new RuntimeException(e);
        }
        entry.setUgi(paramMatcher.group(2));
        entry.setIp(paramMatcher.group(3));
        entry.setCmd(FileCommand.valueOf(paramMatcher.group(4).toUpperCase()));
        entry.setSrc(paramMatcher.group(5));
        entry.setDst(paramMatcher.group(6));
        entry.setPerm(parsePermission(paramMatcher.group(7)));
      } else {
        if (logged < 1000){
          mapLogger.info("Line did not conform to schema: \"" + line + "\"");
          logged++;
        }
        // just skip this line
        return;
      }

      data.setEntry(entry);
      context.write(new AvroKey<AuditLogData>(data), NullWritable.get());
    }

    private Permission parsePermission(String permString) {
      if (permString == null || permString.equals("null"))
        return null;
      else {
        Matcher permMatcher = permPattern.matcher(permString);
        permMatcher.find();
        Permission perm =
            new Permission(permMatcher.group(1), permMatcher.group(2),
                permMatcher.group(3));
        return perm;
      }
    }
  }
  public static List<ProcessingTask> getTasks(FileSystem fs, String logsRoot, String clusterName, String outputPathRoot, boolean incremental, int numDays, int numDaysForced) throws IOException
  {
    TimeZone timeZone = TimeZone.getTimeZone("GMT");
    Calendar cal = Calendar.getInstance(timeZone);

    SimpleDateFormat yearFormat = new SimpleDateFormat("yyyy");
    SimpleDateFormat monthFormat = new SimpleDateFormat("MM");
    SimpleDateFormat dayFormat = new SimpleDateFormat("dd");
    SimpleDateFormat idFormat = new SimpleDateFormat("yyyy-MM-dd");

    yearFormat.setTimeZone(timeZone);
    dayFormat.setTimeZone(timeZone);
    idFormat.setTimeZone(timeZone);

    List<ProcessingTask> processingTasks = new ArrayList<ProcessingTask>();

    numDays = Math.max(numDays, numDaysForced);

    // Start processing previous day of data since current day isn't yet finished.  Unless we are aggregating hourly data there is no point.
    cal.add(Calendar.DAY_OF_MONTH, -1);

    int numPaths = 0;
    long totalLength = 0;
    for (int i=0; i<numDays; i++, cal.add(Calendar.DAY_OF_MONTH, -1))
    {
      Date date = cal.getTime();

      String pathFormat = String.format("%s/%s/daily/%s/%s/*%s",logsRoot,clusterName,yearFormat.format(date),monthFormat.format(date),idFormat.format(date));
      FileStatus[] stats = fs.globStatus(new Path(pathFormat));
      StringBuilder msg = new StringBuilder(pathFormat + " => " + stats.length + " files");

      String outputPathForDay = String.format("%s/%s/%s/%s/%s",outputPathRoot,clusterName,yearFormat.format(date), monthFormat.format(date), dayFormat.format(date));

      if (stats.length > 0)
      {
        if (!incremental || !fs.exists(new Path(outputPathForDay)) || i<numDaysForced)
        {
          for (FileStatus stat : stats)
          {
            totalLength += stat.getLen();
            numPaths++;
          }

          String id = clusterName + "-" + idFormat.format(date);

          System.out.println(msg);

          processingTasks.add(new ProcessingTask(id,pathFormat,outputPathForDay, totalLength));
        }
        else if (incremental && fs.exists(new Path(outputPathForDay)))
        {
          msg.append(" (skipping)");
          System.out.println(msg);
        }
      }
    }

    System.out.println("Found " + numPaths + " paths to process, totalling " + totalLength + " bytes (" + (totalLength/(1024*1024*1024)) + " gigabytes)");

    return processingTasks;
  }


}

