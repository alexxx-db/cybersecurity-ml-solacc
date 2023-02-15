# Databricks notebook source
# MAGIC %sql
# MAGIC 
# MAGIC -- Inspiration: https://www.carbonblack.com/2015/08/14/how-to-detect-powershell-empire-with-carbon-black/
# MAGIC -- cmdline:”powershell.exe -NoP -NonI -W Hidden -Enc”
# MAGIC -- cmdline:” -s -NoLogo -NoProfile” AND process_name:powershell.exe
# MAGIC -- ALTERNATE:
# MAGIC -- cmdline:””C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe” -s -NoLogo -NoProfile”
# MAGIC 
# MAGIC select * from bots_silver_process_launch where source='sysmon' AND (process_image LIKE "%powershell.exe") AND ( (process_cmd LIKE "%-NoP%" AND process_cmd LIKE '%-NonI%' AND process_cmd LIKE '%-enc%' AND process_cmd RLIKE '.*-W\\s*Hidden.*') OR (process_cmd LIKE '%-s%' AND process_cmd LIKE '%-NoLogo%' AND process_cmd LIKE '%-NoProfile%') )

# COMMAND ----------

# MAGIC %sql
# MAGIC 
# MAGIC select * from bots_silver_process_launch where host='wrk-btun.frothly.local' AND date(time)='2017-08-24' 

# COMMAND ----------

# MAGIC %sql
# MAGIC 
# MAGIC select * from bots_silver_process_launch where host='wrk-btun.frothly.local' AND date(time)='2017-08-24' 
# MAGIC     AND process_cmd   NOT IN (select process_cmd   from (select count(1), process_cmd   from bots_silver_process_launch group by process_cmd   order by count(1) desc limit 500 )) 
# MAGIC     AND process_image NOT IN (select process_image from (select count(1), process_image from bots_silver_process_launch group by process_image order by count(1) desc limit 20  ))
# MAGIC  ORDER BY time asc

# COMMAND ----------

# MAGIC %sql select * from bots_silver_process_launch where process_cmd like '%Temp1_invoice.zip%'

# COMMAND ----------

# MAGIC %sql select * from bots_silver_process_launch where process_cmd like '%invoice.doc%'
