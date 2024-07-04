import requests
import http.client

import pandas as pd
import smtplib
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText

try:
    #Fetch auth token
    url = 'https://login.keka.com/connect/token'
    
    payload = {
    'apikey': 'VEN9qCsBp46MXhEBzdRt/4WspoVL4OqW5cG7vH28U8Y=',
    'client_secret': 'fQnoJHPmogxHoqfpgdFG',
    'client_id': 'a16f2c89-393f-4d99-91a9-b31f8aa6d63d',
    'scope': 'kekaapi',
    'grant_type': 'kekaapi'
    }
    
    headers = {
        "User-Agent": "curl/8.6.0", # without this it wont work using python
        'Content-Type': 'application/x-www-form-urlencoded'
    }
    
    response = requests.post(url, headers=headers, data=payload)
    response.raise_for_status()
    access_token = response.json()["access_token"]
    print("Auth token fetched successfully.")

    # Fetch data
    url_data = 'https://plumhq.keka.com/api/v1/hris/employees?inNoticePeriod=true'
    headers_data = {'Authorization': f'Bearer {access_token}'}
    response_data = requests.get(url_data, headers=headers_data)
    response_data.raise_for_status()
    data = response_data.json()
    print("Data fetched.")
    

    filtered_data = []

    for item in data['data']:
        extracted_date = datetime.strptime(item['resignationSubmittedDate'], "%Y-%m-%dT%H:%M:%S.%fZ").date()
        current_date = datetime.now().date()
        if extracted_date >= current_date:
            for group in item['groups']:
                if group['title'] == 'Engineering' or group['title'] == 'Product' or group['title'] == 'Design':
                    filtered_data.append(item)
                    break
    print("Data filtered.")

    if len(filtered_data) > 0:
        csv_file_path = "resign.csv"
        df = pd.DataFrame(filtered_data)
        df.to_csv(csv_file_path, index=False)
        print("Data converted to CSV successfully.")

        # Send email with attachment
        print("Sending email...")
        from_email = "ankitpandey2708@gmail.com"
        password = "uvul mqfu nhil maym" #https://myaccount.google.com/apppasswords
        to  = ['ankitpandey2708@gmail.com']
        cc  = ['ankit.pandey@plumhq.com']
        subject = "Daily IPO Data"
        body = ""
        
        msg = MIMEMultipart()
        msg['From'] = from_email
        msg['To'] = ', '.join(to)
        msg['Subject'] = subject
        msg['Cc'] = ', '.join(cc)
        msg.attach(MIMEText(body, 'plain'))

        with open(csv_file_path, "rb") as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header('Content-Disposition', f'attachment; filename= {csv_file_path}')
            msg.attach(part)

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(from_email, password)
        server.sendmail(from_email, to+cc, msg.as_string())
        server.quit()
        print("Email sent successfully.")


    # Convert to CSV
    

except Exception as e:
    print(f"An error occurred: {e}")
