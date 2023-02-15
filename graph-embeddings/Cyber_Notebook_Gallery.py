# Databricks notebook source
# MAGIC %md 
# MAGIC 
# MAGIC ##<img src="https://databricks.com/wp-content/themes/databricks/assets/images/databricks-logo.png" alt="logo" width="240"/> 
# MAGIC 
# MAGIC ## Cybersecurity Notebook Gallery
# MAGIC 
# MAGIC #### Cybersecurity Architecture, DGA, PowerShell Empire, Detections, DNS

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC <table style="background-color:#ffffe0" style="border:10px solid black">
# MAGIC <tr>
# MAGIC   <td style="border:10px solid black">
# MAGIC   <a href="https://databricks.com/blog/2020/05/13/fighting-cyber-threats-in-the-public-sector-with-scalable-analytics-and-ai.html" target="_blank" rel="noopener">
# MAGIC       <span style="font-size:14pt;">Building a SIEM with Databricks <br/><img width="50px" src="https://spark.apache.org/docs/latest/img/spark-logo-hd.png"> __+__ <img width="95px" src="https://docs.delta.io/latest/_static/delta-lake-logo.png"> <br/>
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/4654491" target="_blank"> Part 1__ |
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/4654523" target="_blank"> Part 2__ |
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/4654675" target="_blank"> Part 3__ |
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/4654660" target="_blank"> Part 4__ |
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/4654632" target="_blank"> Part 5__ |
# MAGIC     <br/><br/>
# MAGIC       <img src="https://demo.cloud.databricks.com/files/arun/cyber/Slide3.png" width=390/>
# MAGIC     </a>
# MAGIC   </td>
# MAGIC   <td style="border:10px solid black">
# MAGIC     <a href="https://databricks.com/blog/2020/05/13/fighting-cyber-threats-in-the-public-sector-with-scalable-analytics-and-ai.html" target="_blank">
# MAGIC       Train a DGA detection model <br> <img width="50px" src="https://spark.apache.org/docs/latest/img/spark-logo-hd.png"> <br>
# MAGIC       __<a href="https://demo.cloud.databricks.com/#notebook/4654716/command/4654718" target="_blank"> Part 1__ 
# MAGIC       <br/><br/>
# MAGIC       <img src="files/images/dga.png" width="390"/>
# MAGIC     </a>
# MAGIC   </td>
# MAGIC   <td valign="top" align="center">
# MAGIC     <a href="https://demo.cloud.databricks.com/#notebook/7677243/command/7677244" target="_blank">
# MAGIC       Powershell Empire Demo<br/>
# MAGIC     __<a href="https://demo.cloud.databricks.com/#notebook/7677243/command/7677244" target="_blank"> Notebook__
# MAGIC       <br/><br/>
# MAGIC       <img src="files/images/redash_cyber.png" width=390/>
# MAGIC     </a>    
# MAGIC     <td style="border:10px solid black">
# MAGIC   </td>
# MAGIC </tr>
# MAGIC </table>

# COMMAND ----------

# MAGIC %md
# MAGIC #### Data Collection

# COMMAND ----------

# MAGIC %md
# MAGIC <table style="background-color:#ffffe0" style="border:10px solid black">
# MAGIC <tr>
# MAGIC   <td style="border:10px solid black">
# MAGIC   <a href="https://demo.cloud.databricks.com/#notebook/4654523" target="_blank" rel="noopener">
# MAGIC       <span style="font-size:14pt;">Ingesting Bro Logs into Delta Lake <br/><img width="50px" src="https://spark.apache.org/docs/latest/img/spark-logo-hd.png"> __+__ <img width="95px" src="https://docs.delta.io/latest/_static/delta-lake-logo.png"> <br/>
# MAGIC     <br/><br/>
# MAGIC       <img src="files/images/bro_logs.png" width=330/>
# MAGIC     </a>
# MAGIC   </td>
# MAGIC   <td style="border:10px solid black">
# MAGIC   <a href="https://demo.cloud.databricks.com/#notebook/7677249/command/7677250" target="_blank" rel="noopener">
# MAGIC       <span style="font-size:14pt;">Ingesting BOTS Sysmon Data <br/><img width="50px" src="https://spark.apache.org/docs/latest/img/spark-logo-hd.png"> __+__ <img width="95px" src="https://docs.delta.io/latest/_static/delta-lake-logo.png"> <br/>
# MAGIC     <br/><br/>
# MAGIC       <img src="https://docs.microsoft.com/en-us/media/landing/sysinternals/event-screen-optimized.png" width=330/>
# MAGIC     </a>
# MAGIC   </td>
# MAGIC </tr>
# MAGIC </table>

# COMMAND ----------

# MAGIC %md
# MAGIC #### Triage & Investigations

# COMMAND ----------

# MAGIC %md
# MAGIC 
# MAGIC <table style="background-color:#ffffe0" style="border:10px solid black">
# MAGIC <tr>
# MAGIC   <td style="border:10px solid black">
# MAGIC   <a href="https://demo.cloud.databricks.com/#notebook/7677281/command/7677282" target="_blank" rel="noopener">
# MAGIC       <span style="font-size:14pt;">Process Investigator <br/><img width="50px" src="https://spark.apache.org/docs/latest/img/spark-logo-hd.png"> __+__ <img width="95px" src="https://docs.delta.io/latest/_static/delta-lake-logo.png"> <br/>
# MAGIC         __<a href="https://demo.cloud.databricks.com/#notebook/7677281/command/7677282"> Part 1__ 
# MAGIC     <br/><br/>
# MAGIC       <img src="files/images/process_investigator.png" width=390/>
# MAGIC     </a>
# MAGIC   </td>
# MAGIC </tr>
# MAGIC </table>

# COMMAND ----------

# MAGIC %md
# MAGIC #### Cyber Machine Learning

# COMMAND ----------

# MAGIC %md 
# MAGIC <table style="background-color:#ffffe0" style="border:10px solid black">
# MAGIC   <tr>
# MAGIC    <td valign="top" align="center">
# MAGIC     <a href="https://demo.cloud.databricks.com/#notebook/8425762/" target="_blank">
# MAGIC       Detect the Agent Tesla RAT via detection of domain generation algorithms (DGA), <br>
# MAGIC       typosquatting and threat intel enrichments from URLhaus.<br>
# MAGIC       Analytics against years worth of log data for true 
# MAGIC       impact analysis and protect organization from phishing risks<br/>
# MAGIC       <a href="https://drive.google.com/file/d/1Nkt6V7Px8zcR_Z5iNyNPbgrxWdPjHEdm/view?usp=sharing" target="_blank"> 
# MAGIC      <img src="https://databricks-knowledge-repo-images.s3.us-east-2.amazonaws.com/PubSec/video-icon.png" width=25/> 
# MAGIC     </a>
# MAGIC     <a href="https://demo.cloud.databricks.com/#notebook/8425762/" target="_blank">
# MAGIC       <img src="https://databricks-knowledge-repo-images.s3.us-east-2.amazonaws.com/HLS/notebook.png" width=75/>
# MAGIC       <br/><br/>
# MAGIC       <img src="http://drive.google.com/uc?export=view&id=1Pa9hM4GJQdDXhFyfZoNTBTGJr0JMTB53" width=500/>
# MAGIC     </a>    
# MAGIC    </td> 
# MAGIC      <td style="border:10px solid black">
# MAGIC     </td> 
# MAGIC   </tr>   
# MAGIC   
# MAGIC </table>  
