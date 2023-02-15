# Databricks notebook source
# DBTITLE 1,Helper Functions
# MAGIC %run "./Helper Functions"

# COMMAND ----------

from mlflow.tracking import MlflowClient
from pyspark.sql.functions import col, lit
from pyspark.sql.types import LongType

expPath = "/Users/david.veuve@databricks.com/BOTS Security Demo/Process Launch Detections - Behavioral"

mlflow = MlflowClient()
expId = mlflow.get_experiment_by_name(expPath).experiment_id
df = spark.read.format("mlflow-experiment").load(expId).withColumn("analytic_type", col("tags.analytic_type")).withColumn("runDuration", col("end_time").cast(LongType()) - col("start_time").cast(LongType())).withColumn("mode", col("tags.mode")).withColumn("detection_name", col("tags.`mlflow.runName`")).withColumn("alerts", col("metrics.alerts")).withColumn("incoming_events", col("metrics.incoming_events")).withColumn("experiment", lit(expPath))

handleUpsert("bots_mlflow_experiments", df, "run_id", ["start_time", "end_time", "status", "run_id", "mode", "detection_name", "incoming_events", "alerts"], "/opt/bots_tables/gold/bots_mlflow_experiments")

expPath = "/Users/david.veuve@databricks.com/BOTS Security Demo/Process Launch Detections - Signatures"

mlflow = MlflowClient()
expId = mlflow.get_experiment_by_name(expPath).experiment_id
df = spark.read.format("mlflow-experiment").load(expId).withColumn("analytic_type", col("tags.analytic_type")).withColumn("runDuration", col("end_time").cast(LongType()) - col("start_time").cast(LongType())).withColumn("mode", col("tags.mode")).withColumn("detection_name", col("tags.`mlflow.runName`")).withColumn("alerts", col("metrics.alerts")).withColumn("incoming_events", col("metrics.incoming_events")).withColumn("experiment", lit(expPath))

handleUpsert("bots_mlflow_experiments", df, "run_id", ["start_time", "end_time", "status", "run_id", "mode", "detection_name", "incoming_events", "alerts"], "/opt/bots_tables/gold/bots_mlflow_experiments")


display(df)
