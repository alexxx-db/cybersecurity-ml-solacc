# Databricks notebook source
# # Intro

# This notebook is intended to be integrated into a notebook, and is a collection of individual explicit signatures. Each cell will run a different detection and then return any alerts.

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
mlflow.set_experiment("/Users/david.veuve@databricks.com/BOTS Security Demo/Process Launch Detections - Signatures")
    
    
# Start the Detections

# Reg.exe called from Command Shell
# https://car.mitre.org/analytics/CAR-2013-03-001/
alerts = runSignature(df_filter="""((process_image LIKE "%reg.exe") AND (process_parent_image LIKE "%cmd.exe"))""", 
                      objectCol="host", 
                      alert_name="Reg.exe called from Command Shell", 
                      alert_description="reg.exe is used for programmatic registry access. It's unusual for this to occur from cmd.exe", 
                      risk_score=10, 
                      mitre="CAR-2013-03-001;T1012;T1112;T1547;T1574", 
                      dataframe=events, alerts=alerts, params=params)

# Clearing Windows Event Log
alerts = runSignature(df_filter="""process_image LIKE '%wevtutil%' AND process_cmd RLIKE '.*cl.*(System|Security|Setup|Application).*' """, 
                      objectCol="host", 
                      alert_name="wevtutil clearing event log", 
                      alert_description="Though used earlier, Wannacry made this detection a breakaway success.", 
                      risk_score=80, 
                      mitre="T1551", 
                      dataframe=events, alerts=alerts, params=params)

# Encoded Powershell
alerts = runSignature(df_filter="""((process_image LIKE "%powershell.exe") AND (lower(process_cmd) LIKE "%-enc%") )""", 
                      objectCol="host", 
                      alert_name="Encoded Powershell", 
                      alert_description="Though it can be used for benign purposes, encoded powershell is often associated with malware because it makes detection and investigation more complicated.", 
                      risk_score=60, 
                      mitre="T1086", 
                      dataframe=events, alerts=alerts, params=params)

# Quick execution of a series of suspicious commands
# https://car.mitre.org/analytics/CAR-2013-04-002/
quick_executions_filter = """process_image LIKE "%arp.exe" OR process_image LIKE "%at.exe" OR process_image LIKE "%attrib.exe" OR process_image LIKE "%cscript.exe" OR process_image LIKE "%dsquery.exe" OR process_image LIKE "%hostname.exe" OR process_image LIKE "%ipconfig.exe" OR process_image LIKE "%mimikatz.exe" OR process_image LIKE "%nbstat.exe" OR process_image LIKE "%net.exe" OR process_image LIKE "%netsh.exe" OR process_image LIKE "%nslookup.exe" OR process_image LIKE "%ping.exe" OR process_image LIKE "%quser.exe" OR process_image LIKE "%qwinsta.exe" OR process_image LIKE "%reg.exe" OR process_image LIKE "%runas.exe" OR process_image LIKE "%sc.exe" OR process_image LIKE "%schtasks.exe" OR process_image LIKE "%ssh.exe" OR process_image LIKE "%systeminfo.exe" OR process_image LIKE "%taskkill.exe" OR process_image LIKE "%telnet.exe" OR process_image LIKE "%tracert.exe" OR process_image LIKE "%wscript.exe" OR process_image LIKE "%xcopy.exe" """
groupedEvents = events.filter(quick_executions_filter).groupBy("host", window("time", "5 minutes")).agg(collect_set("process_image").alias("unique_processes"), collect_set("process_cmd").alias("unique_cmd_lines"), count("host").alias("count")).select(col("window.start").alias("time"), "host", "count", to_json("window").alias("window"), to_json("unique_processes").alias("unique_processes"), to_json("unique_cmd_lines").alias("unique_cmd_lines"))

alerts = runSignature(df_filter="""count > 5""", 
                      objectCol="host", 
                      alert_name="Quick execution of a series of suspicious commands", 
                      alert_description="Certain commands are frequently used by malicious actors and infrequently used by normal users. By looking for execution of these commands in short periods of time, we can not only see when a malicious user was on the system but also get an idea of what they were doing.", 
                      risk_score=40, 
                      mitre="CAR-2013-04-002;T1003;T1069;T1057;T1021;T1543;T1112;T1574;T1018;T1569;T1053;T1029;T1033;T1007;T1082;T1049;T1016;T1010;T1518;T1046;T1562;T1098;T1059;T1012", 
                      dataframe=groupedEvents, alerts=alerts, 
                      params={"mode": params['mode'], "root_query": params['root_query'] + "; Then filtered via: {}; then grouped by host w/ 5 min time intervals".format(quick_executions_filter)})

