import subprocess
import os
import requests
from urllib.parse import urljoin
from fpdf import FPDF
import streamlit as st

# Set up Streamlit page
st.set_page_config(page_title="PentPeek", page_icon="👀")
st.title("👀 PentPeek")
st.write("""
    PentPeek is an advanced tool based on Dynamic Application Security Testing (DAST), 
    a method that identifies security vulnerabilities in web applications by simulating 
    real-world attacks. Provide a URL to scan for potential vulnerabilities.
""")

# Input URL from user
url = st.text_input("Enter the URL:")

# Directory Traversal Payloads
payloads = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd",
    "%2E%2E%2F%2E%2E%2F%2E%2E%2F%2E%2E%2Fetc%2Fpasswd"
]

def check_directory_traversal(url):
    results = []
    detected_vulnerabilities = []

    for payload in payloads:
        test_url = urljoin(url, payload)
        try:
            response = requests.get(test_url)
            if "root:x" in response.text or "passwd" in response.text:
                detected_vulnerabilities.append(f"Directory Traversal vulnerability detected at: {test_url}")
            # Only add payloads that reveal vulnerabilities
        except requests.RequestException as e:
            results.append(f"Error accessing {test_url}: {e}")

    return detected_vulnerabilities

# Initialize the vulnerability_found dictionary
vulnerability_found = {
    'sql_injection': False,
    'xss': False,
    'directory_traversal': False,
    'directory_listing': False
}

# Vulnerability selection using checkboxes
sql_injection = st.checkbox("SQL Injection")
xss = st.checkbox("XSS")
directory_traversal = st.checkbox("Directory Traversal")
directory_listing = st.checkbox("Directory Listing")

if st.button("Start Scan"):
    if url:
        # Prepare report file names
        sqlmap_report_file = "sqlmap_report.txt"
        xsstrike_report_file = "xsstrike_report.txt"
        directory_traversal_report_file = "directory_traversal_report.txt"
        dirb_report_file = "dirb_report.txt"
        pdf_file = "vulnerability_report.pdf"
        
        try:
            # Run Directory Traversal Scan
            if directory_traversal:
                directory_traversal_results = check_directory_traversal(url)
                with open(directory_traversal_report_file, "w") as f:
                    for result in directory_traversal_results:
                        f.write(result + "\n")
                if directory_traversal_results:
                    vulnerability_found['directory_traversal'] = True

            # Run SQL Injection Scan
            if sql_injection:
                sqlmap_command = f"sqlmap -u {url} --batch --flush-session --output-dir=./ --risk=3 --level=5 --dbs | grep -v '\\[INFO\\]'"
                with open(sqlmap_report_file, "w") as f:
                    subprocess.run(sqlmap_command, stdout=f, stderr=subprocess.STDOUT, shell=True, text=True)
                vulnerability_found['sql_injection'] = True

            # Run XSS Scan
            if xss:
                xsstrike_command = ["python3", "XSStrike/xsstrike.py", "--url", url]
                with open(xsstrike_report_file, "w") as f:
                    subprocess.run(xsstrike_command, stdout=f, stderr=subprocess.STDOUT, text=True)
                vulnerability_found['xss'] = True  # Assume XSStrike reports vulnerabilities

            # Run Directory Listing Scan (dirb)
            if directory_listing:
                dirb_command = ["dirb", url, "-o", dirb_report_file, "-S", "-r", "-s", "200"]
                with open(dirb_report_file, "w") as f:
                    process = subprocess.Popen(dirb_command, stdout=subprocess.PIPE, text=True)
                    for line in process.stdout:
                        f.write(line)
                        f.flush()
                    process.stdout.close()
                    process.wait()
                vulnerability_found['directory_listing'] = True  # Assume dirb finds a vulnerability

            # Generate PDF Report
            pdf = FPDF()
            pdf.add_page()

            # Set font for the title and add a big heading on the first page
            pdf.set_font("Arial", "B", 24)

            # Calculate page dimensions
            page_width = pdf.w
            page_height = pdf.h

            # Calculate the position to center the title
            title = "PentPeek Vulnerability Scanning Report"
            title_width = pdf.get_string_width(title)

            # Set the position for the title to be centered on the page
            pdf.set_xy((page_width - title_width) / 2, page_height / 3)

            # Add the title
            pdf.cell(title_width, 10, title, ln=True, align="C")

            # Set font for the vulnerability list
            pdf.set_font("Arial", size=14)
            pdf.ln(20)  # Add space between the title and the vulnerabilities

            # Check for found vulnerabilities and print them
            vulnerability_text = "Vulnerabilities Found:\n"
            if vulnerability_found['sql_injection']:
                vulnerability_text += "* SQL Injection\n"
            if vulnerability_found['xss']:
                vulnerability_text += "* XSS\n"
            if vulnerability_found['directory_traversal']:
                vulnerability_text += "* Directory Traversal\n"
            if vulnerability_found['directory_listing']:
                vulnerability_text += "* Directory Listing\n"

            # Add the vulnerabilities list to the first page
            pdf.multi_cell(0, 10, vulnerability_text)

            # Move to the next page for the detailed reports
            pdf.add_page()
            pdf.set_font("Arial", size=12)

            # Conditionally include reports based on user selection

            # Include Directory Traversal Report
            if vulnerability_found['directory_traversal'] and os.path.exists(directory_traversal_report_file):
                pdf.multi_cell(0, 10, "Directory Traversal Report")
                with open(directory_traversal_report_file, "r") as f:
                    for line in f:
                        pdf.multi_cell(0, 10, line)

            # Include SQL Injection Report
            if vulnerability_found['sql_injection'] and os.path.exists(sqlmap_report_file):
                pdf.add_page()
                pdf.multi_cell(0, 10, "SQL Injection Report")
                with open(sqlmap_report_file, "r") as f:
                    for line in f:
                        pdf.multi_cell(0, 10, line)

            # Include XSS Report
            if vulnerability_found['xss'] and os.path.exists(xsstrike_report_file):
                pdf.add_page()
                pdf.multi_cell(0, 10, "XSS Report")
                with open(xsstrike_report_file, "r") as f:
                    for line in f:
                        pdf.multi_cell(0, 10, line)

            # Include Directory Listing Report from dirb
            if vulnerability_found['directory_listing'] and os.path.exists(dirb_report_file):
                pdf.add_page()
                pdf.multi_cell(0, 10, "Directory Listing Report")
                with open(dirb_report_file, "r") as f:
                    for line in f:
                        pdf.multi_cell(0, 10, line)

            # Add mitigations section at the end of the report
            if any(vulnerability_found.values()):
                pdf.add_page()
                pdf.set_font("Arial", "B", 16)
                pdf.cell(0, 10, "Mitigations", ln=True)
                pdf.set_font("Arial", size=12)

                if vulnerability_found['sql_injection']:
                    pdf.multi_cell(0, 10, "*SQL Injection:*")
                    pdf.multi_cell(0, 10, "1. Use prepared statements and parameterized queries.")
                    pdf.multi_cell(0, 10, "2. Employ stored procedures.")
                    pdf.multi_cell(0, 10, "3. Implement input validation and sanitization.")
                    pdf.multi_cell(0, 10, "4. Use ORM frameworks.")
                if vulnerability_found['xss']:
                    pdf.multi_cell(0, 10, "*Cross-Site Scripting (XSS):*")
                    pdf.multi_cell(0, 10, "1. Escape user inputs.")
                    pdf.multi_cell(0, 10, "2. Use Content Security Policy (CSP).")
                    pdf.multi_cell(0, 10, "3. Validate and sanitize inputs.")
                    pdf.multi_cell(0, 10, "4. Implement proper output encoding.")
                if vulnerability_found['directory_traversal']:
                    pdf.multi_cell(0, 10, "*Directory Traversal:*")
                    pdf.multi_cell(0, 10, "1. Validate and sanitize user inputs.")
                    pdf.multi_cell(0, 10, "2. Use secure APIs for file access.")
                    pdf.multi_cell(0, 10, "3. Implement file access controls.")
                    pdf.multi_cell(0, 10, "4. Restrict file uploads and access.")
                if vulnerability_found['directory_listing']:
                    pdf.multi_cell(0, 10, "*Directory Listing:*")
                    pdf.multi_cell(0, 10, "1. Disable directory listing on the web server.")
                    pdf.multi_cell(0, 10, "2. Use proper access controls.")
                    pdf.multi_cell(0, 10, "3. Restrict permissions on sensitive directories.")

            
                # Output the PDF file
                pdf.output(pdf_file)

                # Provide Download Link
                with open(pdf_file, "rb") as pdf_file_handle:
                    st.download_button(
                        label="Download PDF Report",
                        data=pdf_file_handle,
                        file_name="vulnerability_report.pdf",
                        mime="application/pdf"
                    )

                st.success("Vulnerability test completed. You can download the report using the button above.")
            else:
                st.write("No vulnerabilities found during the scan.")

        except Exception as e:
            st.error(f"An error occurred during the scan: {e}")
