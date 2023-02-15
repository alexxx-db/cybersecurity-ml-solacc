# Databricks notebook source
# MAGIC %md
# MAGIC # Initialize Tables, Delete Any Existing Data

# COMMAND ----------

# DBTITLE 1,Base Configuration
base_path = "/opt/bots_tables"

# COMMAND ----------

# DBTITLE 1,Drop and Recreate Tables
try:
  dbutils.fs.rm("{}/silver/bots_silver_process_launch".format(base_path), recurse=True)
except Exception as e:
  print("Received an error deleting {}/silver/bots_silver_process_launch: {}".format(base_path, str(e)))  

try:
  dbutils.fs.mkdirs("{}/silver/bots_silver_process_launch".format(base_path))
except Exception as e:
  print("Received an error creating {}/silver/bots_silver_process_launch: {}".format(base_path, str(e)))
  
  
spark.sql("DROP TABLE IF EXISTS bots_silver_process_launch")
spark.sql("CREATE TABLE bots_silver_process_launch (time TIMESTAMP, source STRING, source_detail STRING, host STRING, process_authentihash STRING, process_cmd STRING, process_cpu_load DOUBLE, process_cwd STRING, process_image STRING, process_image_company STRING, process_image_description STRING, process_image_file_version STRING, process_image_product STRING, process_imphash STRING, process_integrity STRING, process_is_hidden STRING, process_is_rare STRING, process_logon_guid STRING, process_guid STRING, process_md5 STRING, process_mem_used DOUBLE, process_name STRING, process_os STRING, process_parent_cmd STRING, process_parent_cwd STRING, process_parent_image STRING, process_parent_guid STRING, process_parent_md5 STRING, process_parent_name STRING, process_parent_path STRING, process_parent_sha1 STRING, process_parent_sha256 STRING, process_path STRING, process_pgid STRING, process_pid STRING, process_ppid STRING, process_priority STRING, process_sha1 STRING, process_sha256 STRING, process_start TIMESTAMP, process_term_sess_id STRING, process_threadid STRING, process_title STRING, process_uid STRING, process_auid STRING, process_uptime INT, process_user STRING, process_level STRING) USING delta LOCATION '{}/silver/bots_silver_process_launch'".format(base_path))


# COMMAND ----------

# MAGIC %md
# MAGIC # Ingest Datasets

# COMMAND ----------

# DBTITLE 1,BOTSv1
import os
from pyspark.sql.functions import col, unix_timestamp, from_unixtime, lit
from pyspark.sql.types import StructType, StructField, BooleanType, IntegerType, StringType, DateType, TimestampType

try:
  dbutils.fs.mkdirs("{}/tmp".format(base_path))
except Exception as e:
  print("Received an error creating {}/t,p: {}".format(base_path, str(e)))
  
result = os.system('/usr/bin/wget https://s3.amazonaws.com/botsdataset/botsv1/json-by-sourcetype/botsv1.XmlWinEventLog-Microsoft-Windows-Sysmon-Operational.json.gz -O /tmp/bots-v1-sysmon.json.gz')
print(result)

dbutils.fs.mv("file:/tmp/bots-v1-sysmon.json.gz", "dbfs:{}/tmp/bots-v1-sysmon.json.gz".format(base_path))
# display(dbutils.fs.ls('{}/tmp'.format(base_path)))

df=spark.read.json("{}/tmp/bots-v1-sysmon.json.gz".format(base_path))
spark.sql("set spark.sql.caseSensitive=true")


newDF=df.filter("result.EventCode = 1").select(
  unix_timestamp('result._time', "yyyy-MM-dd HH:mm:ss.SSS z").cast(TimestampType()).alias("time"), 
  lit("sysmon").alias("source"), 
  col("result.EventCode")           .alias("source_detail"), 
  col("result.Computer")            .alias("host"), 
  col("result.ProcessGuid")         .alias("process_guid"), 
  col("result.ParentProcessGuid")   .alias("process_parent_guid"), 
  col("result.CommandLine")         .alias("process_cmd"), 
  col("result.User")                .alias("process_user"), 
  col("result.ParentCommandLine")   .alias("process_parent_cmd"), 
  col("result.ParentProcessId")     .alias("process_ppid"),
  col("result.ProcessId")           .alias("process_pid"), 
  col("result.CurrentDirectory")    .alias("process_cwd"), 
  col("result.SHA1")                .alias("process_sha1"), 
  col("result.SHA256")              .alias("process_sha256"), 
  col("result.IMPHASH")             .alias("process_imphash"), 
  col("result.MD5")                 .alias("process_md5"), 
  col("result.Image")               .alias("process_image"), 
  col("result.ParentImage")         .alias("process_parent_image"), 
  col("result.Level")               .alias("process_level"), 
  col("result.SecurityID")          .alias("process_uid"))
newDF.write.mode("APPEND").format("delta").save("{}/silver/bots_silver_process_launch".format(base_path))


# COMMAND ----------

# MAGIC %sql
# MAGIC 
# MAGIC select count(*), year(time) from bots_silver_process_launch group by 2 

# COMMAND ----------

# DBTITLE 1,Mount dv-db-personalbucket for v2 and v3
try:
  dbutils.fs.mount("s3a://dv-db-personalbucket", "/mnt/dv-db-personalbucket")
except: 
  do="nothing"

# COMMAND ----------

# MAGIC %sh
# MAGIC 
# MAGIC ls -l /dbfs/mnt/dv-db-personalbucket/bots_datasets

# COMMAND ----------

# DBTITLE 1,BOTS v2
import os
from pyspark.sql.functions import col, unix_timestamp, from_unixtime, lit
from pyspark.sql.types import StructType, StructField, BooleanType, IntegerType, StringType, DateType, TimestampType

spark.sql("set spark.sql.caseSensitive=true")
df=spark.read.json("/mnt/dv-db-personalbucket/bots_datasets/botsv2_sysmon_process-launch.json.gz")

newDF=df.filter("EventCode = 1").select(unix_timestamp('_time', "yyyy-MM-dd HH:mm:ss.SSS z").cast(TimestampType()).alias("time"), lit("sysmon").alias("source"), col("EventCode").alias("source_detail"), col("Computer").alias("host"), col("ProcessGuid").alias("process_guid"), col("ParentProcessGuid").alias("process_parent_guid"), col("CommandLine").alias("process_cmd"), col("User").alias("process_user"), col("ParentCommandLine").alias("process_parent_cmd"), col("ParentProcessId").alias("process_ppid"), col("ProcessId").alias("process_pid"), col("CurrentDirectory").alias("process_cwd"), col("SHA1").alias("process_sha1"), col("SHA256").alias("process_sha256"), col("MD5").alias("process_md5"), col("Image").alias("process_image"), col("ParentImage").alias("process_parent_image"), col("Level").alias("process_level"), col("SecurityID").alias("process_uid"))
# display(newDF)
newDF.write.mode("APPEND").format("delta").save("{}/silver/bots_silver_process_launch".format(base_path))

# COMMAND ----------

# DBTITLE 1,BOTS v3
import os
from pyspark.sql.functions import col, unix_timestamp, from_unixtime, lit
from pyspark.sql.types import StructType, StructField, BooleanType, IntegerType, StringType, DateType, TimestampType

spark.sql("set spark.sql.caseSensitive=true")
df=spark.read.json("/mnt/dv-db-personalbucket/bots_datasets/botsv3_sysmon_process-launch.json.gz")

newDF=df.filter("EventCode = 1").select(unix_timestamp('_time', "yyyy-MM-dd HH:mm:ss.SSS z").cast(TimestampType()).alias("time"), lit("sysmon").alias("source"), col("EventCode").alias("source_detail"), col("Computer").alias("host"), col("ProcessGuid").alias("process_guid"), col("ParentProcessGuid").alias("process_parent_guid"), col("CommandLine").alias("process_cmd"), col("User").alias("process_user"), col("ParentCommandLine").alias("process_parent_cmd"), col("ParentProcessId").alias("process_ppid"), col("ProcessId").alias("process_pid"), col("CurrentDirectory").alias("process_cwd"), col("SHA256").alias("process_sha256"), col("MD5").alias("process_md5"), col("Image").alias("process_image"), col("ParentImage").alias("process_parent_image"), col("Level").alias("process_level"), col("SecurityID").alias("process_uid"))
# display(newDF)
newDF.write.mode("APPEND").format("delta").save("{}/silver/bots_silver_process_launch".format(base_path))

# COMMAND ----------


