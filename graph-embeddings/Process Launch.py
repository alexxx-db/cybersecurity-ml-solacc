# Databricks notebook source
# DBTITLE 1,Load Libraries
# MAGIC %run "./Helper Functions"

# COMMAND ----------

# DBTITLE 1,Collect Risky Events
import random
import string
import json

# Configuration
params = {
  "root_query": "select * from bots_silver_process_launch",
  "mode": "development"
}

# Pull Base Dataset
events = spark.sql(params['root_query'])
events.cache()

alerts = initializeAlertsDataframe()


# COMMAND ----------

# MAGIC %run "./Lib - Process Launch - Signatures"

# COMMAND ----------

# MAGIC %run "./Lib - Process Launch - Behavioral"

# COMMAND ----------

from pyspark.sql.functions import md5, coalesce, unix_timestamp, lit
signals = alerts.withColumn("signal_id", md5(coalesce(unix_timestamp("time"), "object", "detection_name"))).withColumn("references", resolveReferences("mitre")).drop("mitre")


# Send alerts to Splunk as risky events
# print("Collected risky events stored in global_temp.{}".format(alert_table_name))
# dbutils.notebook.run("Send Risk Events to Splunk", 600,{ "tableName" : alert_table_name})


handleUpsert("bots_signals", signals, "signal_id", ["time", "object", "signal_id", "detection_name", "description", "risk_score", "json_detail", "references"], "/opt/bots_tables/gold/bots_signals")

# Display them in this notebook
display(signals)




# COMMAND ----------

# DBTITLE 1,Visualize Entities Surrounding High Risk Objects
max_risk = 150

from pyspark.sql.functions import sum, col, concat, from_json, collect_set, min, max
from pyspark.sql.types import *

sum_risk_by_object = (signals
                      .select("time", "object", "risk_score", "signal_id", "references", "detection_name")
                      .groupBy("object")
                      .agg(min("time").alias("earliest"), max("time").alias("latest"), sum("risk_score").alias("total_risk"), collect_set("signal_id").alias("signal_id"), collect_set("references").alias("references"), collect_set("detection_name").alias("detection_name"))
                      .filter(col("total_risk") > max_risk)
                      .withColumn("alert_id", md5(concat(unix_timestamp("earliest"), "object"))))

handleUpsert("bots_alerts", sum_risk_by_object, "alert_id", ["earliest", "object", "signal_id", "detection_name", "total_risk"], "/opt/bots_tables/gold/bots_alerts")

enriched_alerts = signals.join(sum_risk_by_object, "object")


output = enriched_alerts.filter("isnotnull(total_risk)").withColumn("entities", extractEntities("json_detail")).collect()

from pyvis.network import Network
import pandas as pd

got_net = Network(height="1500px", width="100%", bgcolor="#ffffff", notebook=True, font_color="black")

# set the physics layout of the network
got_net.barnes_hut()
got_net.options.groups = {
            "ip": {
                "shape": 'icon',
                "icon": {
                    "face": 'FontAwesome',
                    "code": '\uf6ff',
                    "size": 80,
                    "color": 'green'
                }
            },
            "host": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf109',
                  "size": 80,
                  "color": 'green'
                }
            },
              "file": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf15b',
                  "size": 80,
                  "color": 'purple'
                }
            },
              "user": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf007',
                  "size": 80,
                  "color": 'orange'
                }
            },
              "url": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf0e8',
                  "size": 80,
                  "color": 'blue'
                }
            },
              "domain": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf57d',
                  "size": 80,
                  "color": 'blue'
                }
            },
              "event": {                 
              "shape": 'icon',
              "icon": {
                  "face": 'FontAwesome',
                  "code": '\uf0c9',
                  "size": 80,
                  "color": 'black'
                }
            }
        }
valid_nodes = {}

# print(json.dumps(nodes))
idNum = 0

def dict_to_html_table(in_dict):  
  tbl_fmt = '''
  <table> {}
  </table>'''

  row_fmt  = '''
    <tr>
      <td>{}</td>
      <td>{}</td>
    </tr>'''

  return tbl_fmt.format(''.join([row_fmt.format(k,v) for k,v in in_dict.iteritems()]))

for row in output:
  idNum += 1
  eventHover = "Time: {}<br/>Object: {}<br/>Alert: {}<br/>Alert Description: {}".format(row['time'], row['object'], row['detection_name'], row['description'])
  
  try:
    eventHover += "<br />" + dict_to_html_table(json.loads(row['json_detail']))
  except:
    do="nothing"
  
  try:
    got_net.add_node("eventID-{}".format(idNum), process_guid=json.loads(row['json_detail'])['process_guid'], shape="icon", group="event", label="{}: {}".format(row['object'], row['detection_name']), title=eventHover)
#     print("Got a valid process_guid {}".format(str(json.loads(row['json_detail'])['process_guid'])))
  except Exception as e:
#     print("Exception trying to do the thing {}".format(str(e)))
    got_net.add_node("eventID-{}".format(idNum), shape="icon", group="event", label="{}: {}".format(row['object'], row['detection_name']), title=eventHover)
  
#   got_net.add_node("eventID-{}".format(idNum), shape="icon", group="event", label="{}: {}".format(row['object'], row['detection_name']), title=eventHover)
  valid_nodes["eventID-{}".format(idNum)] = True
  for entity in row['entities']:
    if entity['entity_id'] not in valid_nodes:
      valid_nodes[entity['entity_id']] = True
      got_net.add_node(entity['entity_id'], shape="icon", group=entity['entity_type'], label=entity['entity_title'], title=entity['entity_hover'])
    attrs = {"value": row['risk_score'],
            "from": "eventID-{}".format(idNum)}
    got_net.add_edge("eventID-{}".format(idNum), entity['entity_id'], **attrs)

got_net.show("alert_map.html")
html_str = got_net.html.replace(
  '<head>',
  '<head><link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/font-awesome/4.7.0/css/font-awesome.min.css" type="text/css"/><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery/3.0.0/jquery.min.js"></script><script src="https://cdnjs.cloudflare.com/ajax/libs/jquery-modal/0.9.1/jquery.modal.min.js"></script><link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/jquery-modal/0.9.1/jquery.modal.min.css" />'
).replace(
  'return network;',
  """
  
        function copyToClipboard(textToCopy, alertValue) {
            /* Get the text field */
            $("body").append($('<input type="text" id="copyToClipboardInput">').val(textToCopy));
            var copyText = document.getElementById("copyToClipboardInput");

            /* Select the text field */
            copyText.select();
            copyText.setSelectionRange(0, 99999); /*For mobile devices*/

            /* Copy the text inside the text field */
            document.execCommand("copy");

            /* Alert the copied text */
            if(alertValue && alertValue != ""){
                myId = "alertModal-" + textToCopy.replace(/[^a-zA-Z0-9\\-]/g, "")
                let myModal = $("<div>").attr("id", myId).addClass("modal dvModal").append($("<p>").text(alertValue), $("<pre>").text(copyText.value));$("body").append(myModal);
                $("#" + myId).modal({"blockerClass": "dvModalBlocker"});
            }
            $("#copyToClipboardInput").remove();
            
        }

        network.on("click", function(params) {
            console.log("Got a click", arguments)
            if (params.nodes.length === 0) {
            console.log("No node click");
            }
            else {
                if(nodes['_data'][params.nodes[0]] && nodes['_data'][params.nodes[0]]['process_guid']){
                    copyToClipboard(nodes['_data'][params.nodes[0]]['process_guid'], "Copied the process GUID to your clipboard:");         
                }else if(nodes['_data'][params.nodes[0]]['group'] && nodes['_data'][params.nodes[0]]['group']=="event"){
                    let myModal = $("<div>").attr("id", "alertModal").addClass("modal dvModal").append($("<p>").text("No Drilldown Value Found"));$("body").append(myModal);
                    $("#alertModal").modal({"blockerClass": "dvModalBlocker"});
                }
            }
        })
        return network;"""
)
# print(html_str)
displayHTML(html_str)
