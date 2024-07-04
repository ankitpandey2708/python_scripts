import requests
from bs4 import BeautifulSoup
from lxml import etree
from datetime import datetime
import pandas as pd
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.base import MIMEBase
from email import encoders
from email.mime.text import MIMEText

# Function to scrape data using the provided XPath expression
def scrape_data(url, xpath):
    # Send a GET request to the URL
    response = requests.get(url)
    
   
    soup = BeautifulSoup(response.text, 'html.parser')
    tree = etree.HTML(str(soup))
    # Find elements using the provided XPath expression
    table = tree.xpath(xpath)
    

    data = table[0]
    # print(etree.tostring(data).decode("utf-8"))
    rows = data.findall('.//tr')
    
    
    values = []

    # for row in rows:
    #     columns = []
    #     for td in row.findall('.//td'):
    #         text = ''.join(td.xpath('text()')).strip()
    #         a = td.find('.//a')
    #         if a is not None and a.text and text == "":
    #             text = a.text.strip()
           
    #         columns.append(text)
    #     columns = [columns[i] for i in range(len(columns)) if i not in [7,8]]
    #     values.append(columns)
    
    # ipo_data = []
    # keys = ["Name", "Open_Date", "Close_Date","Listing_Date","Issue_Price","Issue_Size(in cr)","Lot_Size"]

    # for value in values:
    #     entry = dict(zip(keys, value))
    #     ipo_data.append(entry)
    # print("Data fetched.")
    
    # filtered_data = []

    # for ipo in ipo_data:
    #     ipo_close_date =   datetime.strptime(ipo['Close_Date'], '%b %d, %Y').date() if ipo['Close_Date'] else None
    #     if ipo_close_date and ipo_close_date >= datetime.now().date():
    #         filtered_data.append(ipo)
    # print("Data filtered.")


    for row in rows:
        fourth_td = row.findall('.//td')[3]
        if fourth_td.text.strip() != "–" :
            
            columns = []
            for td in row.findall('.//td'):
                text = ''.join(td.xpath('text()')).strip()
                span = td.find('.//span')
                if span is not None and span.text and text == "":
                    text = span.text.strip()
               
                columns.append(text)
            columns = [columns[i] for i in range(len(columns)) if i not in [0, 4,5,6]]
            values.append(columns)
    
    
    
    ipo_data = []
    keys = ["Name", "IPO_Last_Date", "Listing_Date"]

    for value in values:
        entry = dict(zip(keys, value))
        ipo_data.append(entry)

    
    print("Data fetched.")

    filtered_data = []

    for ipo in ipo_data:
        ipo_last_date_str = ipo['IPO_Last_Date'][-13:].replace('th', '').replace('st', '').replace('nd', '').replace('rd', '').strip()
        ipo_last_date = datetime.strptime(ipo_last_date_str, '%d %b %Y').date()
        ipo['IPO_Last_Date'] = ipo_last_date
        if ipo['IPO_Last_Date'] >= datetime.now().date():
            filtered_data.append(ipo)
        listing_date = datetime.strptime(ipo['Listing_Date'], '%d %b %Y').date()
        ipo['Listing_Date'] = listing_date

    print("Data filtered.")

    if len(filtered_data) > 0:
        csv_file_path = "ipo.csv"
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
        

# URL and XPath expression
url = "https://zerodha.com/ipo/"
xpath = "/html/body/main/div/section[1]/div[2]/div[1]/table/tbody"

# url = "https://www.chittorgarh.com/report/mainboard-ipo-list-in-india-bse-nse/83/"
# xpath = "/html/body/div[10]/div[3]/div[1]/div[5]/div/div[2]/div/table/tbody"


# Call the function to scrape data
scrape_data(url, xpath)
