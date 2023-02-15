# Databricks notebook source
# DBTITLE 1,Background Processing
import json

guid = dbutils.widgets.get("processGUID")

print("Looking up Process GUID: {}".format(guid))
  
## Process Hierarchy
parent_process = None
sibling_processes = None
grand_parent_process = None
cousin_processes = None
great_grand_parent_process = None
second_cousin_processes = None


def harvestValue(collect, field):
  if len(collect)>0 and field in collect[0]:
    return collect[0][field]
  else:
    return None

nodes = []

process = spark.sql("select * from bots_silver_process_launch where process_guid='{}' limit 1".format(guid)).fillna("") #toPandas().to_json(orient="records"))[0]
process_collect = process.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect()
process_guid = process_collect[0]['process_guid']
nodes.extend(process_collect)



child_processes = spark.sql("select * from bots_silver_process_launch where process_parent_guid='{}'".format(process_guid)).fillna("")
nodes.extend(child_processes.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect())

grandchild_processes = spark.sql("select * from bots_silver_process_launch where process_parent_guid in (select process_guid as process_parent_guid from bots_silver_process_launch where process_parent_guid='{}')".format(process_guid)).fillna("")
nodes.extend(grandchild_processes.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect())

parent_process_guid = harvestValue(process_collect,'process_parent_guid')

if parent_process_guid != None:
  parent_process = spark.sql("select * from bots_silver_process_launch where process_guid='{}' limit 1".format(parent_process_guid)).fillna("") #toPandas().to_json(orient="records"))[0]
  parent_process_collect = parent_process.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect()
  nodes.extend(parent_process_collect)
  sibling_processes = spark.sql("select * from bots_silver_process_launch where process_parent_guid='{}' AND process_guid!='{}'".format(parent_process_guid, process_guid)).fillna("")
  nodes.extend(sibling_processes.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect())
  
  grand_parent_process_guid = harvestValue(parent_process_collect, 'process_parent_guid')  
  if grand_parent_process_guid != None:
    grand_parent_process = spark.sql("select * from bots_silver_process_launch where process_guid='{}' limit 1".format(grand_parent_process_guid)).fillna("") #toPandas().to_json(orient="records"))[0]
    grand_parent_process_collect = grand_parent_process.collect()
    nodes.extend(grand_parent_process_collect)

    cousin_processes = spark.sql("select * from bots_silver_process_launch where process_guid!='{}' AND process_parent_guid!='{}' AND process_parent_guid in (select process_guid as process_parent_guid from bots_silver_process_launch where process_parent_guid='{}')".format(process_guid, parent_process_guid, grand_parent_process_guid)).fillna("")
    nodes.extend(cousin_processes.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect())

    great_grand_parent_process_guid = harvestValue(grand_parent_process_collect, 'process_parent_guid')
    
    if great_grand_parent_process_guid != None:
      great_grand_parent_process = spark.sql("select * from bots_silver_process_launch where process_guid='{}' limit 1".format(great_grand_parent_process_guid)).fillna("") #toPandas().to_json(orient="records"))[0]
      great_grand_parent_process_collect = great_grand_parent_process.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect()
      nodes.extend(great_grand_parent_process_collect)
      second_cousin_processes = spark.sql("select * from bots_silver_process_launch where process_guid!='{}' AND process_parent_guid!='{}' AND process_parent_guid in (select process_guid as process_parent_guid from bots_silver_process_launch where process_parent_guid!='{}' AND process_parent_guid in (select process_guid as process_parent_guid from bots_silver_process_launch where process_parent_guid='{}'))".format(process_guid, parent_process_guid, grand_parent_process_guid, great_great_grand_parent_process_guid)).fillna("")
      nodes.extend(second_cousin_processes.select("process_parent_guid", "process_guid", "process_image", "process_cmd", "process_parent_cmd").collect())
#       great_great_grand_parent_process_guid = harvestValue(great_grand_parent_process_collect, 'process_parent_guid')
#       if great_great_grand_parent_process_guid != None:
        

  
## Top Users of This System
host = process.select("host").collect()[0]['host']
top_users = spark.sql("select process_user, count(*) from bots_silver_process_launch where host='{}' group by process_user".format(host))

try:
  from pyvis.network import Network
except:
  dbutils.library.installPyPI('pyvis')
  dbutils.library.restartPython()
  from pyvis.network import Network

from pyvis.network import Network
import pandas as pd

got_net = Network(height="750px", width="100%", bgcolor="#ffffff", font_color="black", directed=True)

# set the physics layout of the network
got_net.barnes_hut()

valid_nodes = {}

# print(json.dumps(nodes))

for node in nodes:
  title = "Command Line String:<br />{}".format(node['process_cmd'])
  title += "<br/><br/>Parent Command Line String:<br/>{}".format(node['process_parent_cmd'])
  got_net.add_node(node['process_guid'], label=node['process_image'], title=title)
  valid_nodes[node['process_guid']] = True
for node in nodes:
    if node['process_parent_guid'] not in valid_nodes:
      continue
      print("Could not find parent node {}".format(node['process_parent_guid']))
    elif node['process_guid'] not in valid_nodes:
      continue
      print("Could not find child node {}".format(node['process_guid']))
    else:
      attrs = {"value": 5,
              "from": node['process_parent_guid']}
      got_net.add_edge(node['process_parent_guid'], node['process_guid'], **attrs)

got_net.show("process_map.html")

displayHTML(got_net.html)

# COMMAND ----------

# DBTITLE 1,Process

guid = dbutils.widgets.get("processGUID")
display(process)

# COMMAND ----------

# DBTITLE 1,Child Processes

display(child_processes)

# COMMAND ----------

# DBTITLE 1,Grandchild Processes

display(grandchild_processes)

# COMMAND ----------

# DBTITLE 1,Parent Process

display(parent_process)

# COMMAND ----------

# DBTITLE 1,Sibling Processes

display(sibling_processes)


# COMMAND ----------

# DBTITLE 1,Grandparent Process

display(grand_parent_process)

# COMMAND ----------

# DBTITLE 1,Cousin Processes

display(cousin_processes)

# COMMAND ----------

# DBTITLE 1,Great Grandparent Process

display(great_grand_parent_process)

# COMMAND ----------

# DBTITLE 1,Second Cousin Processes

display(second_cousin_processes)

# COMMAND ----------

# DBTITLE 1,Top Users
display(top_users)

# COMMAND ----------


