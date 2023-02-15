# Databricks notebook source


CONFIG = {
  "splunk_host": "35.165.86.40",
  "hec_port": 8088,
  "secret_scope_name": "splunk_env",
  "secret_hec_token_key": "risk_events_hec_token",
  "index": "risk",
  "sourcetype": "databricks:risk",
  "source": "databricks:risk",
  "host": "mycompany.cloud.databricks.com"
}

TOKEN = dbutils.secrets.get(CONFIG['secret_scope_name'], CONFIG['secret_hec_token_key'])

from splunk_http_event_collector import http_event_collector
import traceback
import sys
import time
import json
import datetime
import logging

def sendRiskEventManually(time, risk_score, risk_object, risk_object_type, json_detail=None):
  event = {}
  if json_detail == None:
    event = json_detail
  event['time'] = time
  event['risk_score'] = risk_score
  event['risk_object'] = risk_object
  event['risk_object_type'] = risk_object_type
  payload.update({"event":event})
  hec.sendEvent(payload)

def sendRiskDataframe(dataframe, override_risk_score=None, override_risk_object=None, override_risk_object_type=None):
  obj = dataframe.toPandas().to_dict("records")
  for row in obj:
    if override_risk_score != None:
      row['risk_score'] = override_risk_score
    if override_risk_object != None:
      row['risk_object'] = override_risk_object
    if override_risk_object_type != None:
      row['risk_object_type'] = override_risk_object_type
    hec.batchEvent({"event": row})
  hec.flushBatch()


hec = http_event_collector(TOKEN, CONFIG['splunk_host'], http_event_port=CONFIG['hec_port'])

# perform a HEC reachable check
hec_reachable = hec.check_connectivity()
if not hec_reachable:
  print("HEC Not Reachable")
  sys.exit(1)

# Set to pop null fields.  Always a good idea
hec.popNullFields = True
# set logging to DEBUG for example
hec.log.setLevel(logging.DEBUG)

# Start event payload and add the metadata information
payload = {}
payload.update({"index":CONFIG['index']})
payload.update({"sourcetype":CONFIG['sourcetype']})
payload.update({"source":CONFIG['source']})
payload.update({"host":CONFIG['host']})


dbutils.widgets.text("tableName", "", "Table Name")
incomingTableName = dbutils.widgets.get("tableName")

alerts = spark.sql("select * from global_temp.{}".format(incomingTableName))

sendRiskDataframe(alerts,override_risk_object_type="system")
