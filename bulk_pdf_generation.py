import io
import os
import smtplib
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email import encoders
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph
from reportlab.lib.styles import getSampleStyleSheet
from PyPDF2 import PdfWriter, PdfReader

def generate_bank_statement(output_file, customer_name, account_number, transactions):
    try:
        # Create a PDF document
        pdf = SimpleDocTemplate(output_file, pagesize=letter)
        
        # Set up styles
        styles = getSampleStyleSheet()
        title_style = styles['Title']
        normal_style = styles['Normal']
        
        # Static Elements
        title = Paragraph("Bank Statement", title_style)
        subtitle = Paragraph(f"Customer Name: {customer_name}<br/>Account Number: {account_number}", normal_style)
        
        # Static Headers for Table
        table_headers = ["Date", "Description", "Withdrawals", "Deposits", "Balance"]
        
        # Combine Headers and Dynamic Transaction Data
        table_data = [table_headers] + transactions
        
        # Create the Table
        table = Table(table_data, colWidths=[70, 200, 80, 80, 80])  # Adjust column widths
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),  # Header row background
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),  # Header text color
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),  # Align all cells
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),  # Header font
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),  # Header padding
            ('GRID', (0, 0), (-1, -1), 1, colors.black),  # Cell borders
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),  # Rows background color
        ]))
        
        # Assemble the PDF
        elements = [title, subtitle, table]
        pdf.build(elements)
        print(f"Bank statement PDF generated: {output_file}")
    except Exception as e:
        print(f"Error generating bank statement: {e}")

def password_protect_pdf(input_pdf, output_pdf, password):
    try:
        # Open the generated PDF
        writer = PdfWriter()
        with open(input_pdf, 'rb') as infile:
            reader = PdfReader(infile)
            
            # Copy all pages from the input PDF
            for page in reader.pages:
                writer.add_page(page)
            
            # Add encryption
            writer.encrypt(password)
            
            # Write to a new file
            with open(output_pdf, 'wb') as outfile:
                writer.write(outfile)
        
        print(f"PDF password protected: {output_pdf}")
    except Exception as e:
        print(f"Error password protecting PDF: {e}")

def send_email_with_attachment(receiver_email, subject, body, attachment_path):
    try:
        # Email configuration
        sender_email = "your_email@example.com"
        sender_password = "your_email_password"

        # Create the email message
        message = MIMEMultipart()
        message['From'] = sender_email
        message['To'] = receiver_email
        message['Subject'] = subject

        # Add the email body
        message.attach(MIMEText(body, 'plain'))

        # Attach the PDF file
        with open(attachment_path, 'rb') as attachment:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(attachment.read())
            encoders.encode_base64(part)
            part.add_header(
                'Content-Disposition',
                f'attachment; filename={os.path.basename(attachment_path)}',
            )
            message.attach(part)

        # Send the email
        with smtplib.SMTP('smtp.gmail.com', 587) as server:
            server.starttls()
            server.login(sender_email, sender_password)
            server.send_message(message)

        print(f"Email sent to {receiver_email} with attachment {attachment_path}")
    except Exception as e:
        print(f"Error sending email: {e}")

def generate_bulk_statements(users):
    try:
        os.makedirs("statements", exist_ok=True)  # Ensure output directory exists
        
        for user in users:
            customer_name = user['name']
            account_number = user['account_number']
            transactions = user['transactions']
            email = user['email']
            
            # Generate the file names
            output_file = f"statements/{customer_name}_statement.pdf"
            protected_file = f"statements/{customer_name}_statement_protected.pdf"
            
            # Generate the PDF
            generate_bank_statement(output_file, customer_name, account_number, transactions)
            
            # Password-protect the PDF
            password_protect_pdf(input_pdf=output_file, output_pdf=protected_file, password=account_number)
            
            # Optionally, remove the unprotected file
            os.remove(output_file)
            
            # Send the protected PDF via email
            subject = "Your Bank Statement"
            body = f"Dear {customer_name},\n\nPlease find attached your bank statement. The file is password-protected with your account number.\n\nBest regards,\nYour Bank"
            send_email_with_attachment(email, subject, body, protected_file)
        
        print("All bank statements generated, password protected, and emailed.")
    except Exception as e:
        print(f"Error generating bulk bank statements: {e}")

def main():
    # Example data for multiple users
    users = [
        {
            "name": "John Doe",
            "account_number": "1234567890",
            "transactions": [
                ["2024-11-01", "ATM Withdrawal", "$200.00", "", "$4,800.00"],
                ["2024-11-02", "Salary Credit", "", "$3,000.00", "$7,800.00"],
                ["2024-11-03", "Utility Bill Payment", "$150.00", "", "$7,650.00"],
            ],
            "email": "johndoe@example.com",
        },
        {
            "name": "Jane Smith",
            "account_number": "9876543210",
            "transactions": [
                ["2024-11-01", "Grocery Shopping", "$150.00", "", "$2,350.00"],
                ["2024-11-02", "Online Purchase", "$80.00", "", "$2,270.00"],
                ["2024-11-03", "Salary Credit", "", "$3,200.00", "$5,470.00"],
            ],
            "email": "janesmith@example.com",
        },
    ]
    
    # Generate bulk statements
    generate_bulk_statements(users)

if __name__ == "__main__":
    main()
