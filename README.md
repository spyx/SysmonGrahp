# SysmonGraph

Sysmon Graph is project to visualize sysmon logs.

![](https://github.com/spyx/SysmonGrahp/blob/main/screenshot/screenshot.png?raw=true)

You can quickly get overview of relations between processes, file creation, DNS requests or Network connection. 
It should help speed process our with manual threat hunting. 

### Instalation

##### Option 1.

Download project. Navigate to docker file and lunch this command. 

```bash
docker-compose up
```

Docker will create 2 instances. Neo4J and Web server to server our front UI on port 8888

##### Option 2.

Just lunch this docker command to create noe4j container and open index.html from docker/www in your browser. 

##### Option 3.

If you host Noe4J Database just edit index.html file with proper IP addresses.  


### Collect Logs

For collection logs there is simple powershell script. Script simply output all results to screen. If you require collect more logs you can change it at begginig of file. By default script collect process createtion, DNS request, file creation and network conncetion. All Sysmon-ID/Nodes are available.

```powershell

```

### Usage

If you are using first option just navigate to http://localhost:8888 or open index.html. It provide simple UI to see all possible relation between logs. All syslog information are also available for each node
inside our UI. Folder example contains example I used in BSides Talk. Project still in alpha stage. 


