import os
import re
import sys
import time
from datetime import datetime
import PySimpleGUI as sg
from plyer import notification
import requests
from urllib.parse import urlparse
import tldextract
from socket import gethostbyname, gaierror
from bs4 import BeautifulSoup
from ssl import get_server_certificate
import ssl
import OpenSSL.crypto

#This is a trial commit

# Function to update the timer information
def update_timer(start_time):
    current_time = datetime.now()
    elapsed_time = current_time - start_time
    elapsed_seconds = int(elapsed_time.total_seconds())
    formatted_time = f"Time Open: {elapsed_seconds} seconds"
    current_datetime = current_time.strftime("Date: %Y-%m-%d Time: %H:%M:%S")
    return f"{formatted_time}\n{current_datetime}"

sg.theme('SystemDefault')

# Login credentials
username = 'Admin'
password = 'Admin@123'

# Global variables for window title, logo, and copyright text
window_title = "Malicious App Analyzer"
SIH_logo = "CODEBREAKERS.png"
copyright_text = "Copyright © 2023 CodeBreakers023. All rights reserved."


# Define the login layout
login_layout = [
    [sg.Image(SIH_logo, size=(800, 200))],
    [sg.Text('Username:'), sg.Input(size=(25, 1), key='-USERNAME-', enable_events=True)],
    [sg.Text('Password:'), sg.Input(size=(25, 1), key='-PASSWORD-', password_char='*', enable_events=True)],
    [sg.Button('Login')],
    [sg.Text('', key='-LOGIN_MESSAGE-', text_color='red')],
    [sg.Text(copyright_text, justification='center', text_color='Black', font=('Helvetica', 10, 'bold','italic'))],
]

# Create the login window
login_window = sg.Window('Login', login_layout, finalize=True)

while True:
    event_login, values_login = login_window.read()

    if event_login == sg.WINDOW_CLOSED:
        sys.exit(0)

    if event_login == 'Login':
        if values_login['-USERNAME-'] == username and values_login['-PASSWORD-'] == password:
            notification.notify(
                title="Login Status: Successful",
                message="Login Successful, Welcome Administrator",
                app_name="MaliciousAppAnalyzer"
            )
            break

        else:
            login_window['-LOGIN_MESSAGE-'].update('Login Credentials Invalid')
            notification.notify(
                title="Login Status: Failed",
                message="Login attempt failed",
                app_name="MaliciousAppAnalyzer"
            )

login_window.close()

if event_login == sg.WINDOW_CLOSED:
    sys.exit(0)

# Function to analyze a URL
def analyze_url(url):
    try:
        domain_info = tldextract.extract(url)
        domain = domain_info.domain + "." + domain_info.suffix

        ip_address = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', domain)

        if ip_address:
            return f"The URL contains an IP address: {ip_address.group()}\nAnalysis Result: IP Address"
        else:
            return f"The URL contains a domain: {domain}\nAnalysis Result: Domain"

    except Exception as e:
        return f"An error occurred while analyzing the URL {url}: {str(e)}\nAnalysis Result: Error"

# Function to check if a URL is malicious
def is_malicious_url(url):
    try:
        response = requests.get(url)
        status_code = response.status_code

        if status_code in [404, 403, 500]:
            print(f"The URL {url} might be malicious. Status code: {status_code}")
            return "Malicious"
        else:
            print(f"The URL {url} seems to be safe. Status code: {status_code}")
            return "Safe"

    except Exception as e:
        print(f"An error occurred while checking the URL {url}: {str(e)}")
        return "Error"

#SSL Certificate
def fetch_ssl_certificate(url):
    try:
        domain_info = tldextract.extract(url)
        domain = domain_info.domain + "." + domain_info.suffix

        pem_cert = get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, pem_cert)

        ssl_certificate_info = {
            'Subject': x509.get_subject().get_components(),
            'Issuer': x509.get_issuer().get_components(),
            'Not Before': x509.get_notBefore(),
            'Not After': x509.get_notAfter(),
            'Serial Number': x509.get_serial_number(),
            'Version': x509.get_version(),
            'Signature Algorithm': x509.get_signature_algorithm(),
        }

        return format_ssl_certificate_info(ssl_certificate_info)

    except Exception as e:
        return f"Error fetching SSL certificate information: {str(e)}"


def format_ssl_certificate_info(ssl_certificate_info):
    formatted_result = "SSL Certificate Information:\n"

    for key, value in ssl_certificate_info.items():
        formatted_result += f"{key}: {value}\n"

    return formatted_result

    # Add date formatting logic as needed
    return date_str

#URL components
def extract_url_components(url):
    try:
        parsed_url = urlparse(url)

        url_components = {
            'Scheme': parsed_url.scheme,
            'Netloc': parsed_url.netloc,
            'Path': parsed_url.path,
            'Params': parsed_url.params,
            'Query': parsed_url.query,
            'Fragment': parsed_url.fragment
        }

        return format_url_components(url_components)

    except Exception as e:
        return f"Error extracting URL components: {str(e)}"


def format_url_components(url_components):
    formatted_result = "URL Components:\n"

    for key, value in url_components.items():
        formatted_result += f"{key}: {value}\n"

    return formatted_result


def get_webpage_content(url):
    try:
        response = requests.get(url)
        if response.status_code == 200:
            return response.text
        else:
            print(f"Failed to retrieve the webpage. Status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {str(e)}")
        return None

def extract_links(html_content):
    if html_content:
        soup = BeautifulSoup(html_content, 'html.parser')
        links = soup.find_all('a')
        return [link.get('href') for link in links if link.get('href')]
    else:
        return []

def get_ssl_certificate(url):
    try:
        domain_info = tldextract.extract(url)
        domain = domain_info.domain + "." + domain_info.suffix

        cert = ssl.get_server_certificate((domain, 443))
        x509 = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, cert)

        subject = x509.get_subject()
        issuer = x509.get_issuer()
        expiration_date = x509.get_notAfter()

        return f"SSL Certificate Details:\nSubject: {subject}\nIssuer: {issuer}\nExpiration Date: {expiration_date}"

    except Exception as e:
        print(f"An error occurred while fetching SSL certificate details for {url}: {str(e)}")
        return "Error"

# Function to check if a URL is a phishing attempt
def is_phishing_url(url):
    phishing_terms = ["login", "password", "bank", "secure", "account"]
    if any(term in url for term in phishing_terms):
        print(f"The URL {url} might be a phishing attempt.")
        return "Phishing"
    else:
        print(f"The URL {url} seems to be safe from phishing.")
        return "Safe"

# Function to detect malware in a URL
def detect_malware(url):
    try:
        response = requests.get(url)
        content = response.text.lower()

        malware_terms = ["malware", "virus", "trojan", "ransomware"]
        if any(term in content for term in malware_terms):
            print(f"The URL {url} might contain malware.")
            return "Malware"
        else:
            print(f"The URL {url} seems to be free from malware.")
            return "Safe"

    except Exception as e:
        print(f"An error occurred while checking for malware in {url}: {str(e)}")
        return "Error"

# Function to get IP address and country information for a URL
def get_ip_and_country(url):
    try:
        domain_info = tldextract.extract(url)
        domain = domain_info.domain + "." + domain_info.suffix

        ip_address = gethostbyname(domain)

        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()

        country = data.get('country', 'Unknown')

        print(f"IP Address: {ip_address} — Country: {country}")
        return ip_address, country

    except gaierror:
        print(f"Unable to resolve the IP address for {domain}")
        return "Unknown", "Unknown"
    except Exception as e:
        print(f"An error occurred while fetching IP and country for {url}: {str(e)}")
        return "Error", "Error"

# Function to get details about a web page
def get_page_details(url):
    try:
        response = requests.get(url)
        status_code = response.status_code
        content_type = response.headers.get('content-type')
        page_size = len(response.content) / 1024  # in kilobytes
        server_info = response.headers.get('server', 'Unknown')

        print(f"HTTP Status Code: {status_code}")
        print(f"Content Type: {content_type}")
        print(f"Page Size: {page_size:.2f} KB")
        print(f"Web Server: {server_info}")

        return status_code, content_type, page_size, server_info

    except Exception as e:
        print(f"An error occurred while fetching page details for {url}: {str(e)}")
        return "Error"

# Function to perform URL analysis
def perform_url_analysis(url):
    url_analysis_result = ""

    # Analyze URL for malicious content
    url_type = is_malicious_url(url)
    url_analysis_result += f"\n\nURL Analysis Result: {url_type}\n"

    if url_type == "Safe":
        # Analyze the URL details
        url_analysis_type = analyze_url(url)
        url_analysis_result += f"\n{url_analysis_type}"

        # Check for phishing attempts
        phishing_type = is_phishing_url(url)
        url_analysis_result += f"\nPhishing Check Result: {phishing_type}"

        # Detect malware in the URL
        malware_type = detect_malware(url)
        url_analysis_result += f"\nMalware Detection Result: {malware_type}"

        # Get IP address and country
        ip_address, country = get_ip_and_country(url)
        url_analysis_result += f"\nIP Address and Country: {ip_address} — {country}"

        # Get page details
        page_details = get_page_details(url)
        url_analysis_result += f"\nPage Details Result: {page_details}"

    elif url_type == "Malicious":
        url_analysis_result += "Malicious URL detected. Further analysis may be required."
    else:
        url_analysis_result += "Error occurred during URL analysis."

    return url_analysis_result

# Set the theme to change the background color
sg.theme('SystemDefault')

# Login credentials
username = 'Admin'
password = 'Admin@123'

# Global variables for window title, logo, and copyright text
window_title = "Malicious App Analyzer"
SIH_logo = "CODEBREAKERS.png"  # Replace with your actual logo path
copyright_text = "Copyright © 2023 CodeBreakers023. All rights reserved."
text_file_path = "malicious_apps.txt"

# Function to clear the log screen
def clear_log_screen():
    analysis_window['-OUTPUT-'].update('')  # Clear the log screen

# Define the malicious app analysis layout
analysis_layout = [
    [sg.Image(SIH_logo, size=(800, 200))],
    [sg.Text("File Path:"), sg.Input(key='-FILE_PATH-', enable_events=True), sg.FileBrowse(initial_folder=text_file_path)],
    [sg.Button("Analyze"), sg.Button("Stop"), sg.Button("Exit"), sg.Button("Reset"), sg.Text('', key='timer', justification='right')],
    [sg.Text('Status: Ready', key='status', text_color='green')],
    [sg.Multiline(default_text='Please upload an application...\n__________________________________________________', size=(50, 15), key='-OUTPUT-', enable_events=True, autoscroll=True, disabled=True)],
    [sg.Button("Link Analyzer"), sg.Button("Clear Log")], # New button for clearing the log
    [sg.Text(copyright_text, justification='center', text_color='Black', font=('Helvetica', 10, 'bold', 'italic'))]
]

# Create the analysis window
analysis_window = sg.Window('Malicious App Analyzer', analysis_layout, finalize=True,
                            return_keyboard_events=True, location=(None, None), size=(800, 625))
start_time = datetime.now()

exit_confirmed = False

while True:
    event, values = analysis_window.read(timeout=1000)

    # Call update_timer and update the timer field
    analysis_window['timer'].update(update_timer(start_time))

    if event == sg.WIN_CLOSED or event == 'Exit':
        if not exit_confirmed:
            # Ask for confirmation before exiting
            confirm_layout = [
                [sg.Text('Are you sure you want to exit?')],
                [sg.Button('Yes'), sg.Button('No')]
            ]

            confirm_window = sg.Window('Exit Confirmation', confirm_layout)
            confirm_event, _ = confirm_window.read()

            if confirm_event == sg.WINDOW_CLOSED or confirm_event == 'No':
                confirm_window.close()
                continue

            exit_confirmed = True
            confirm_window.close()

        try:
            analysis_window['status'].update('Analysis process ended', text_color='red')
        except Exception as e:
            sys.exit(0)

        time.sleep(5)
        analysis_window['status'].update('Analysis done', text_color='yellow')
        sys.exit(0)

    if event == 'Analyze':
        # Simulate detailed analysis for at least 5 seconds
        analysis_window['status'].update('Analyzing...', text_color='blue')
        start_analysis_time = time.time()
        while time.time() - start_analysis_time < 5:
            event, values = analysis_window.read(timeout=100)
            if event == sg.WIN_CLOSED or event == 'Exit':
                sys.exit(0)
            # Call update_timer and update the timer field during analysis
            analysis_window['timer'].update(update_timer(start_time))

        # Retrieve the file path from the input field
        file_path = values['-FILE_PATH-']

        if os.path.isfile(file_path):
            # Read the predefined list of malicious apps from a text file
            with open(text_file_path, 'r') as file:
                malicious_apps = [line.strip() for line in file]

            # Check if the selected app is in the list of malicious apps
            app_name = os.path.basename(file_path)
            if app_name in malicious_apps:
                notification.notify(
                    title="Analysis Result: Malicious App",
                    message=f"{app_name} is identified as a malicious application",
                    app_name="MaliciousAppAnalyzer"
                )
                analysis_window['-OUTPUT-'].update(f'Alert: The Application {app_name} is Malicious!\n')
            else:
                notification.notify(
                    title="Analysis Result: Not Malicious",
                    message=f"{app_name} is not identified as a malicious application",
                    app_name="MaliciousAppAnalyzer"
                )
                analysis_window['-OUTPUT-'].update(f'The Application {app_name} is not Malicious.\n')
            analysis_window['status'].update('Analysis done', text_color='green')
        else:
            sg.popup_error("Please select a valid file for analysis.")

        # Call update_timer and update the timer field
        analysis_window['timer'].update(update_timer(start_time))

    if event == 'Reset':
        # Reset log screen and display toast notification
        analysis_window['-FILE_PATH-'].update('')
        analysis_window['status'].update('Status: Ready', text_color='green')
        analysis_window['-OUTPUT-'].update('Please upload an application...')
        notification.notify(
            title="Application Refreshed",
            message="Application log screen has been refreshed.",
            app_name="MaliciousAppAnalyzer"
        )

    # New event for "Link Analyzer" button
    if event == 'Link Analyzer':
        link_analyzer_layout = [
            [sg.Text("Enter URL:"), sg.Input(key='-URL-', size=(30, 1)), sg.Button("Analyze URL")],
            [sg.Text('', key='-LINK_ANALYZER_OUTPUT-', size=(90, 30))]
        ]

        link_analyzer_window = sg.Window("Link Analyzer", link_analyzer_layout, finalize=True)

        while True:
            link_event, link_values = link_analyzer_window.read()

            if link_event == sg.WIN_CLOSED:
                link_analyzer_window.close()
                break

            if link_event == 'Analyze URL':
                url_to_analyze = link_values['-URL-']
                analysis_result = perform_url_analysis(url_to_analyze)

                # Fetch and display SSL certificate details
                ssl_certificate_result = fetch_ssl_certificate(url_to_analyze)
                analysis_result += f"\n{ssl_certificate_result}"

                # Fetch and display URL components
                url_components_result = extract_url_components(url_to_analyze)
                analysis_result += f"\n{url_components_result}"

                link_analyzer_window['-LINK_ANALYZER_OUTPUT-'].update(analysis_result)

        link_analyzer_window.close()

    # Event for "Clear Log" button
    if event == 'Clear Log':
        clear_log_screen()

analysis_window.close()
