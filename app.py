import subprocess
from flask import Flask, request, jsonify, render_template
from datetime import datetime
from celery.result import AsyncResult
from celery import Celery
import nmap
import sqlite3
import csv



app = Flask(__name__)
app.config['CELERY_RESULT_BACKEND'] = 'rpc://' # Use RabbitMQ as result backend
celery = Celery(app.name, broker='pyamqp://guest@localhost//')
celery.conf.update(app.config)

# Database setup
def init_db():
 try:
    with app.app_context():
        db = sqlite3.connect('scanner.db')
        cursor = db.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS scans(
                id INTEGER PRIMARY KEY, 
                domain TEXT UNIQUE, 
                result TEXT,
                mx_records TEXT,
                a_records TEXT,
                txt_records TEXT,
                ns_records TEXT,
                sslyze_result TEXT, 
                scan_date TIMESTAMP)''')
        db.commit()
        print("Database initialized!") # Debugging print statement
 except sqlite3.Error as e:
        print("SQLite error:", e)
init_db()

if __name__ == '__main__':
    app.run(debug=True)

@app.route('/')
def index():
    return render_template('frontend.html')

@app.route('/scan', methods=['POST'])
def schedule_scan():
    domain = request.form['domain']
    result = scan_domain.apply_async(args=[domain])
    return jsonify({"status": "Scan scheduled!", "task_id": result.id})


def get_dns_records(domain):
    records = {}
    records['MX'] = subprocess.getoutput(f'dig MX {domain} +short').split('\n')
    records['A'] = subprocess.getoutput(f'dig A {domain} +short').split('\n')
    records['TXT'] = subprocess.getoutput(f'dig TXT {domain} +short').split('\n')
    records['NS'] = subprocess.getoutput(f'dig NS {domain} +short').split('\n')
    for record_type in ['MX', 'A', 'TXT', 'NS']:
       if records[record_type] == ['']:
           records[record_type] = ["No record"]
    
    
    return records
    
def run_sslyze(domain):
    #command = ["sslyze", "sslyze --heartbleed", "sslyze --ccs-injection", domain]
    command = ["sslyze", domain]
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode()
    
    

@celery.task(bind=True)
def scan_domain(self, domain):
    nm = nmap.PortScanner()
    nm.scan(domain, arguments='-F') #added fast scan option # this scanning is for testing

    # nm.scan(domain, arguments='--open')  # this scanning is for testing

#    arguments = '-v --host-timeout=28800s -Pn -T4 -sT --webxml --max-retries=1 --open -p0-65355'
#    nm.scan(domain, arguments=arguments) # this is actual

    result = nm.csv()
    print("Raw CSV output:", result)

    # Get DNS records
    dns_records = get_dns_records(domain)
    print("DNS Records:", dns_records)###

    sslyze_result = run_sslyze(domain)
    print("SSLyze Result:", sslyze_result)

    # Get the current date and time
    scan_date = datetime.now()
    

    # Connect to the database
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()

    # Check if the domain already exists in the database
    cursor.execute("SELECT id FROM scans WHERE domain=?", (domain,))
    existing_entry = cursor.fetchone()


    if existing_entry:
        # If domain exists, update the result
     cursor.execute("UPDATE scans SET result=?, mx_records=?, a_records=?, txt_records=?, ns_records=?, sslyze_result=?, scan_date=? WHERE domain=?", 
                    (result, ','.join(dns_records['MX']), ','.join(dns_records['A']), ','.join(dns_records['TXT']), ','.join(dns_records['NS']), sslyze_result, scan_date,domain))
    else:
        # If domain doesn't exist, insert a new entry
     cursor.execute("INSERT INTO scans (domain, result, mx_records, a_records, txt_records, ns_records, sslyze_result, scan_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", 
                    (domain, result, ','.join(dns_records['MX']), ','.join(dns_records['A']), ','.join(dns_records['TXT']), ','.join(dns_records['NS']), sslyze_result, scan_date))
    # Commit changes and close the connection
    conn.commit()
    conn.close()

    return result


from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas



def generate_pdf(results, filename):
    c = canvas.Canvas(filename, pagesize=letter)
    width, height = letter
    y_position = height - 100

    # Split the results by newline characters
    lines = results.split('\n')

    c.drawString(100, y_position, "SSLyze Results:")
    y_position -= 12

    for line in lines:
        if y_position < 50:  # Threshold to create a new page
            c.showPage()    # Create a new page
            y_position = height - 100  # Reset y_position

        c.drawString(100, y_position, line)  # Adjust the vertical spacing as needed
        y_position -= 12

    c.save()

from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas
import io
import json


def parse_nmap_csv(csv_string):
    results = []
    seen = set()
    csv_reader = csv.DictReader(csv_string.strip().split("\n"), delimiter=';')

    # Print all the available keys
    print("Keys (Headers):", csv_reader.fieldnames)

    for row in csv_reader:
        print("Row:", row) # Print each row
        domain = row["hostname"]
        port = row["port"]
    # Skip this row if we've seen this combination of domain and port before
        if (domain, port) in seen:
            continue

        # Otherwise, add this combination to the set of seen combinations
        seen.add((domain, port))

        result = {
            "domain":domain,
            "port": port,
            "host": row["host"],
            "state": row["state"],
            "service": row["name"],
            "reason": row["reason"],
#            "version": row["version"],
#            "extrainfo": row["extrainfo"]  # Modify as per actual CSV structure for OS info
        }
        results.append(result)
    return results


@app.route('/results', methods=['GET'])
def get_results():
    domain = request.args.get('domain')
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    cursor.execute("SELECT result, mx_records, a_records, txt_records, ns_records, scan_date FROM scans WHERE domain=?", (domain,))
    raw_results, mx_records, a_records, txt_records, ns_records, scan_date = cursor.fetchone() # Fixed here
    dns_records = {
        'MX': (mx_records or '').split(','),
        'A': (a_records or '').split(','),
        'TXT': (txt_records or '').split(','),
        'NS': (ns_records or '').split(',')

    }
    conn.close()

    if raw_results:
        results = parse_nmap_csv(raw_results)
    else:
        results = []    


    return render_template('results.html', domain=domain, results=results, dns_records=dns_records, scan_date=scan_date)

@app.route('/scanned_domains')
def scanned_domains():
    conn = sqlite3.connect('scanner.db')
    cursor = conn.cursor()
    cursor.execute("SELECT DISTINCT domain FROM scans")
    domains = [row[0] for row in cursor.fetchall()]
    conn.close()
    return render_template('domains.html', domains=domains)

@app.route('/scan_status/<task_id>', methods=['GET'])
def scan_status(task_id):
   # task = AsyncResult(task_id, app=celery)
    task = scan_domain.AsyncResult(task_id)
    return jsonify({"status": task.status, "result": task.result})

from flask import send_file

@app.route('/view_pdf/<domain>', methods=['GET'])
def view_pdf(domain):
    cursor = sqlite3.connect('scanner.db').cursor()
    cursor.execute("SELECT sslyze_result FROM scans WHERE domain=?", (domain,))
    sslyze_result = cursor.fetchone()[0]
    pdf_filename = f"{domain}_sslyze.pdf"
    generate_pdf(sslyze_result, pdf_filename)
    return send_file(pdf_filename, as_attachment=False) # Open in browser

from flask import Response



