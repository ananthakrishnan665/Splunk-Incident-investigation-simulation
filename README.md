# Splunk-Incident-investigation-simulation
This project simulates a real-world incident where the website of Wayne Enterprises (imreallynotbatman.com) was defaced by cyber attackers. As a SOC Analyst, my role was to investigate how the attackers gained access using Splunk by analyzing logs stored in index "botsv1"
We followed the Cyber Kill Chain model to map each stage of the attack from reconnaissance to exploitation and beyond. When necessary, we used OSINT to fill in gaps and enrich the investigation.

`Scenario`: An incident where the website of Wayne Enterprises (imreallynotbatman.com) was defaced by cyber attackers.

## In Reconnaissance Phase
In this phase, the attackers are trying to collect maximum information about the server. So we need to cover some log sources covering Network traffic (we can capture all things try to communicate with our server.
So we need to search for traces:
* SEARCH:`index=botsv1 imreallynotbatman.com`
<img>

From sourcetype field, we saw that the following log sources contain the traces of this search term
<img>

We can look at the web traffic first that's how we know what is incoming so:
* SEARCH: `index=botsv1 imreallynotbatman.com sourcetype=stream:http`
<img>

From src_ip we could understand two ip created logs But the first ip create more suspicious look at its count.
<img>

Need to validate the IP is suspicious. If possible it may trigger in an IDS so lets look suricata:
 * SEARCH: `index=botsv1 imreallynotbatman.com src=40.80.148.42 sourcetype=suricata`
   <img>

So we got some answers
 *  **Joomla** is the CMS our web server is using.
     <img>

 * **Acunetix** is the web scanner, the attacker used to perform the scanning attempts.
<img>

 * **192.168.250.70** is the IP address of the server imreallynotbatman.com
<img>

This information are important for attackers as well as us while investigating.

## In Exploitation Phase

Now we need to focus on to our Webserver (192.168.250.70).
* SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70"`
This helps us to know about the incoming request to our server.
<img>
Got 3 iP address check count and also check `http_methods` field we can see the methods used. suspicious level of Post-requests
* Narrow search on Method post
* SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST`
<img>
 Included some interesting fields containing valuable information in screenshot below:
<img>
<img>

* Noticed Joomla (CMS) included in some search terms
* Identified admin login page of the Joomla CMS `/joomla/administrator/index.php` (search on google).
* Suspecting Brute-force attack because it is admin page
<img>
* search needed for the request sent to the login portal
* SEARCH: index=botsv1 imreallynotbatman.com sourcetype=stream:http dest_ip="192.168.250.70"  uri="/joomla/administrator/index.php"
* Look at the form_data field to view requests.
  <img>

  * Narrow down search to form_data because suspect attackers tried multiple credential to gain access.
  * SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" | table _time uri src_ip dest_ip form_data`
    <img>
  * | table _time uri src_ip dest_ip form_data`( For table view)
    
  Look at the table we can see that `user`, `passwd` multiple times from an `IP 23.22.63.114`, that's a sign of a Brute-force attempt with the help of Automated tools (Look at the attempt in such a short time).

  To show the user and pass values we use **regex** (Regular Expressions):
  * SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data`
    <img>
  * Further extracr passwd values only:
  * SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)"  | table src_ip creds`  <img>

  Now examine **http_user_agent** field which shows the attacker used a Python script to automate Brute-force, but one request from Mozilla.
  So narrow down to **http_user_agent**.
  * SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST form_data=*username*passwd* | rex field=form_data "passwd=(?<creds>\w+)" |table _time src_ip uri http_user_agent creds`
  <img>
  Yes Continious Brute-force attack from `IP 23.22.63.114` and one password attempt from `IP 40.80.148.42` Password is **batman**
so we have
* `/joomla/administrator/index.php` - url faced brute-force
  
* `admin` - Attempt made against user
  
* `batman` - password for admin access to CMS running  imreallynotbatman.com
  
* `412`- Brute force attempts (1 passed)
 
* `23.22.63.114` - IP conducted brute-force
* 
* `40.80.148.42` - IP used for successfull login

## In Installation Phase

At this stage we need to investigate  the attacker dropped anything in our server to maintain his access (like a backdoor).
* Look for .exe extensions
* SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" *.exe`
  <img>
  Look ate the **part_filename{}** field and found an executable file **3791.exe** and a PHP file **agent.php**
<img>

Now we need to check these files have any relation with the suspected IP addresses
* SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" "part_filename{}"="3791.exe"`
  <img>
  Yes, we got a match
  Now investigate the file was executed on server or not
  * SEARCH: `index=botsv1 "3791.exe"`
  <img>
  Host-centric log source found the traces of **.exe**
  So we need to look into sysmon log and Event Id for evidence (ID =1 means process creation).
* SEARCH: `index=botsv1 "3791.exe" sourcetype="XmlWinEventLog" EventCode=1`
  <img>
  From **CommandLine** field we can understand **3791.exe** is executed on server
  The evidence is also in the other logs.
  From the screen you can collect its Md5 hash, user executed and use search hash on VirusTotal.
  <img>
  <img>
  what we get
  md5 hash: AAE3F5A29935E6ABCC2C2754D12A9AF0
  user executed: NT AUTHORITY\IUSR
  Other name of 3791: ab.exe

  ## In Action On Objective

  The attacker successfully defaced our website so find how it happened.
  * Point to Suricata logs to know any detections there.
  * SEARCH: `index=botsv1 dest=192.168.250.70 sourcetype=suricata`
    <img>
    Not detected. Now search for our server initiated communications.
    *  `index=botsv1 src=192.168.250.70 sourcetype=suricata`
      <img>
      Yes here the suspicious IP addresses are shown that our server communicated with them.
      So lets check the communication with that IP
   * SEARCH: `index=botsv1 src=192.168.250.70 sourcetype=suricata dest_ip=23.22.63.114`
     <img>
  Look for that JPEG file looks suspicious.
* SEARCH:  `index=botsv1 url="/poisonivy-is-coming-for-you-batman.jpeg" dest_ip="192.168.250.70" | table _time src dest_ip http.hostname url`
  <img>
  That jpeg came from the attacker host **prankglassinebracket.jumpingcrab.com**
  <img>

  **poisonivy-is-coming-for-you-batman.jpeg**- file defaced our website
  **HTTP.URI.SQL.Injection**- Detected by forgitate firewall on IP 40.80.148.42

  ## In Command & Control Phase

  Before defacing the attacker uploaded the file in the server. so attacker used Dynamic Dns to resolve the malicious IP (Dynamic DNS is a service that lets attackers use a fixed domain   name (prankglassinebracket.jumpingcrab.com) that always points to their changing IP address.
  Let investigate on communication start from fortigate_utm (firewall logs).
  * SEARCH:  `index=botsv1 sourcetype=fortigate_utm"poisonivy-is-coming-for-you-batman.jpeg"`
    <img>
    Look on the fields  Source IP, destination IP, and URL
    <img>
    <img>
    Lets look on stream:http log
    * SEARCH `index=botsv1 sourcetype=stream:http dest_ip=23.22.63.114 "poisonivy-is-coming-for-you-batman.jpeg" src_ip=192.168.250.70`
   Now this points out to the suspicious domain is a command & control


  
