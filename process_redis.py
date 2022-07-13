# some code from: https://blog.devgenius.io/how-to-use-redis-pub-sub-in-your-python-application-b6d5e11fc8de
# don't use this in prod. it doesn't even have error handling...
import redis
import json
import psycopg2

r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
ps = r.pubsub()
ps.subscribe('alerts')

conn = psycopg2.connect("dbname='alert_data' user='postgres' host='localhost' password='password'")
cursor = conn.cursor()

def add_event(mal_ip, ts, sig):
    if "SURICATA" not in sig: #sigs/alerts containing SURICATA is not something i care about
        cursor.execute("INSERT INTO alerts (mal_ip, ts, sig) VALUES(%s, %s, %s)", (mal_ip, ts, sig))
        conn.commit()

for message in ps.listen():
    if message is not None and isinstance(message, dict):
        alert = message.get('data')
        if alert != 1: #there is 1 that gets printed, idk why exactly
            alert_json = json.loads(alert)
            if alert_json['src_ip'] in ['127.0.0.1', 'internal ips', 'and your external ips']:
                mal_ip = alert_json['dest_ip']
            else:
                mal_ip = alert_json['src_ip']
            
            add_event(mal_ip, alert_json['timestamp'], alert_json['alert']['signature'])
