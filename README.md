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

  To show the user and pass values:
  * SEARCH: `index=botsv1 sourcetype=stream:http dest_ip="192.168.250.70" http_method=POST uri="/joomla/administrator/index.php" form_data=*username*passwd* | table _time uri src_ip dest_ip form_data`
    <img>
    
  
