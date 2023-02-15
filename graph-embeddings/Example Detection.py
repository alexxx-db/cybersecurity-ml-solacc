# Databricks notebook source
# DBTITLE 1,Detection Info
detection_name = "Encoded Powershell"
description = "Though it can be used for benign purposes, encoded powershell is often associated with malware because it makes detection and investigation more complicated."
risk_score = 60
references = "T1086"

# COMMAND ----------

# DBTITLE 1,Detection Logic
query = "select * from bots_silver_process_launch"
df_filter = """((process_image LIKE "%powershell.exe") AND (lower(process_cmd) LIKE "%-enc%") )"""
objectCol = "host"
mode = "development"

# COMMAND ----------

from pyspark.sql.functions import to_json, lit, col, struct, when

import mlflow

with mlflow.start_run(run_name=alert_name):
  # Define Tags and Parameters in MLflow
  mlflow.set_tag("mode", mode)
  mlflow.set_tag("analytic_type", "Signatures")
  mlflow.log_param("root_query", query)
  mlflow.log_param("filter", df_filter)
  
  # Grab Base Dataset
  dataframe = spark.sql(query)
  mlflow.log_metric("incoming_events", dataframe.count())

  # Filter to matching events
  matching_events = dataframe.filter(df_filter)
  alerts = (matching_events
            .withColumn("json_detail", to_json(struct([when(col(x)!="  ",dataframe[x]).otherwise(None).alias(x) for x in dataframe.columns])))
            .select(col("time").alias("time"), col(objectCol).alias("object"), lit(risk_score).alias("risk_score"), lit(detection_name).alias("detection_name"), lit(description).alias("description"), col("json_detail"), lit(references).alias("references"))
           )

  # Record alerts in MLflow
  alerts.toPandas().to_csv('alerts.csv')
  mlflow.log_artifact("alerts.csv")
  mlflow.log_metric("alerts", alerts.count())
