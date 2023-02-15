# Databricks notebook source
# # Intro

# This notebook is intended to be integrated into a notebook, and is a collection of behavioral detections. Each cell will run a different detection and then return any alerts.

# Requirements:

# * In your calling notebook, you should pass in the argument with the name of a globalTempView that contains the dataset you wish to analyze. No baseline is required for these signatures, so this would typically be the last hour of data (since last running), or last 5 min, or last day, etc. 
# * As this notebook exits, it will return the name of a globalTempView that contains a list of alerts triggered on the dataset.

# Example:

#     import random
#     tableName = ''.join([random.choice(string.ascii_letters + string.digits) for n in xrange(32)])
#     spark.sql("select * from process_launch where date > date_add(current_date(), -1) ").createOrReplaceGlobalTempView("my_data")
#     result = dbutils.notebook.run("notebook_1", 600,{ "db_name" : tableName)
#     print("We have {} results stored in table {}".format(result['count'], result['table_name']))
#     myAlerts = spark.sql("select * from {}".format(result['table_name']))

# COMMAND ----------

# Initialize MLflow for tracking our detections

import mlflow

# Import Pyspark Functions and Types
from pyspark.sql.types import *
from pyspark.sql.functions import mean, stddev, col, lit, when, struct, to_json, window, collect_list, count, collect_set, first

# Define an MLflow Experiment to track everything from this notebook
mlflow.set_experiment("/Users/david.veuve@databricks.com/BOTS Security Demo/Process Launch Detections - Behavioral")
    
    

# COMMAND ----------

# DBTITLE 1,First Time Seen

# Start the Detections
alerts = runFirstTimeSeen_HISTORICAL("process_image", "host", "First Process Launch on Host", "New processes could be updates, or new applications, but they could also be malware.", 5, df_filter="YEAR(time) == 2017", dataframe=events, alerts=alerts, params=params)
alerts = runFirstTimeSeen_HISTORICAL("process_user", "host", "First Active User on Host", "New users are typically system administrators, however they could be users created to persist on systems.", 5, df_filter="YEAR(time) == 2017", dataframe=events, alerts=alerts, params=params)
alerts = runFirstTimeSeen_HISTORICAL("process_md5", "process_image", "New MD5 for process path", "When a new MD5 is created it is often an indication of a software update, but malware does also like to replace key windows binaries.", 5, df_filter="YEAR(time) == 2017", dataframe=events, alerts=alerts, params=params)


# COMMAND ----------

# DBTITLE 1,Time Series Spikes

# Unusually long CLI Strings
alert_name = "Unusually Long Command Line"
detection_description = "This detection looks at the avg and stdev of the command line strings executed per system, and then alerts for any CLI strings that are more than six stdevs above the average. Unusually long CLI strings can occur when trying to pack as much code as possible into the command line string, such as inline commands or instructions to reach out to command and control. This is a low fidelity indicator, as it will often indicate normal administrative activities."
risk_score = 40
df_filter = """process_image NOT LIKE '%chrome.exe' AND process_image NOT LIKE '%firefox.exe'"""
mitre=""
with mlflow.start_run(run_name=alert_name): 
  mlflow.set_tag("mode", params['mode'])
  mlflow.set_tag("analytic_type", "Time Series Spikes")
  if len(params['root_query'])>=500:
    with open("root_query.txt", "w") as f:
      f.write(params['root_query'])
      mlflow.log_artifact("root_query.txt")
  else:    
    mlflow.log_param("root_query", params['root_query'])
  if len(df_filter)>=500:
    with open("filter.txt", "w") as f:
      f.write(df_filter)
      mlflow.log_artifact("filter.txt")
  else:    
    mlflow.log_param("filter", df_filter)
  
  filtered = events.filter(df_filter)
  mlflow.log_metric("incoming_events", filtered.count())
  length_base = filtered.filter("isnotnull(process_cmd)").groupBy("host", "process_user", "process_image", "process_cmd").agg(count("host").alias("count"), min("time").alias("firstTime"), max("time").alias("lastTime"), length("process_cmd").alias("process_cmd_length"))
  length_baselines = length_base.groupBy("host").agg(mean(col("process_cmd_length")).alias("avg"), stddev(col("process_cmd_length")).alias("stdev"))
  length_outliers = length_base.join(length_baselines, "host", "left").filter("process_cmd_length > avg + 6 * stdev")
  length_outliers.cache()
  toAlert = length_outliers.select(col("lastTime").alias("time"), col("host").alias("object"), lit(risk_score).alias("risk_score"), lit(alert_name).alias("detection_name"), lit(detection_description).alias("description"), to_json(struct([when(col(x)!="  ",length_outliers[x]).otherwise(None).alias(x) for x in length_outliers.columns])).alias("json_detail") , lit("").alias("mitre") )
  toAlert.toPandas().to_csv('alerts.csv')
  mlflow.log_artifact("alerts.csv")
  mlflow.log_metric("alerts", toAlert.count())
  if toAlert.count() > 0:
    alerts = alerts.union(toAlert.select(col("time").alias("time"), col("object"), lit(risk_score).alias("risk_score"), lit(alert_name).alias("detection_name"), lit(detection_description).alias("description"), col("json_detail"), lit(mitre)))
    

