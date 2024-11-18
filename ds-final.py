import os
import json
import requests
import streamlit as st
from collections import namedtuple
from datetime import datetime, datetime as dt

# Vulnerability information
Vulnerability = namedtuple('Vulnerability', ['cve_id', 'vendor_project', 'product', 'vulnerability_name', 'date_added', 'short_description', 'required_action', 'due_date', 'known_ransomware_campaign_use', 'notes', 'cwes', 'cvss_score', 'owasp_risk', 'asset_value', 'threat_level', 'exploitability'])

# Risk assessment
owasp_risk_scores = {
    'A1 - Injection': 10,
    'A2 - Broken Authentication': 8,
    'A3 - Sensitive Data Exposure': 6,
    'A4 - XML External Entities (XXE)': 8,
    'A5 - Broken Access Control': 7,
    'A6 - Security Misconfiguration': 6,
    'A7 - Cross-Site Scripting (XSS)': 7,
    'A8 - Insecure Deserialization': 7,
    'A9 - Using Components with Known Vulnerabilities': 9,
    'A10 - Insufficient Logging & Monitoring': 5,
    'Unknown': 5
}

def get_owasp_risk_score(owasp_risk):
    return owasp_risk_scores.get(owasp_risk, 5)

def assess_risk(vulnerability):
    """
    Assess the risk of a vulnerability based on CVSS score, OWASP risk, asset value, threat level, and exploitability.
    Returns the risk priority (0-100).
    """
    cvss_weight = 0.4
    owasp_weight = 0.3
    asset_weight = 0.15
    threat_weight = 0.1
    exploitability_weight = 0.05

    risk_score = (
        vulnerability.cvss_score * cvss_weight +
        get_owasp_risk_score(vulnerability.owasp_risk) * owasp_weight +
        vulnerability.asset_value * asset_weight +
        vulnerability.threat_level * threat_weight +
        vulnerability.exploitability * exploitability_weight
    )

    return int(risk_score * 100)

# Vulnerability management
def load_vulnerabilities():
    try:
        with open('vulnerabilities.json', 'r') as file:
            data = json.load(file)
            vulnerabilities = []
            for item in data:
                vulnerability = Vulnerability(
                    cve_id=item['cve_id'],
                    vendor_project=item['vendor_project'],
                    product=item['product'],
                    vulnerability_name=item['vulnerability_name'],
                    date_added=datetime.strptime(item['date_added'], '%Y-%m-%d'),
                    short_description=item['short_description'],
                    required_action=item['required_action'],
                    due_date=datetime.strptime(item['due_date'], '%Y-%m-%d'),
                    known_ransomware_campaign_use=item['known_ransomware_campaign_use'],
                    notes=item['notes'],
                    cwes=item['cwes'],
                    cvss_score=item['cvss_score'],
                    owasp_risk=item['owasp_risk'],
                    asset_value=item['asset_value'],
                    threat_level=item['threat_level'],
                    exploitability=item['exploitability']
                )
                vulnerabilities.append(vulnerability)
            return vulnerabilities
    except FileNotFoundError:
        return []
    except json.JSONDecodeError as e:
        print(f"Error decoding JSON: {e}")
        return []

def save_vulnerabilities(vulnerabilities):
    data = []
    for v in vulnerabilities:
        v_dict = v._asdict()
        v_dict['date_added'] = v.date_added.strftime('%Y-%m-%d')
        v_dict['due_date'] = v.due_date.strftime('%Y-%m-%d')
        data.append(v_dict)
    with open('vulnerabilities.json', 'w') as file:
        json.dump(data, file, indent=4)

def add_vulnerability(vulnerability):
    vulnerabilities = load_vulnerabilities()
    vulnerabilities.append(vulnerability)
    save_vulnerabilities(vulnerabilities)

def update_vulnerability(vulnerability):
    vulnerabilities = load_vulnerabilities()
    for i, v in enumerate(vulnerabilities):
        if v.cve_id == vulnerability.cve_id:
            vulnerabilities[i] = vulnerability
            save_vulnerabilities(vulnerabilities)
            break

def get_vulnerabilities(vulnerability_name=None, order_by='assess_risk'):
    vulnerabilities = load_vulnerabilities()
    if vulnerability_name:
        if isinstance(vulnerability_name, str):
            vulnerabilities = [v for v in vulnerabilities if v.vulnerability_name == vulnerability_name]
        else:
            vulnerabilities = [v for v in vulnerabilities if v.vulnerability_name == str(vulnerability_name)]
    if order_by == 'priority':
        vulnerabilities.sort(key=assess_risk, reverse=True)
    elif order_by == 'assess_risk':
        vulnerabilities.sort(key=assess_risk, reverse=True)
    else:
        vulnerabilities.sort(key=lambda x: getattr(x, order_by), reverse=True)
    return vulnerabilities

# Streamlit app
def vulnerability_management_app():
    st.set_page_config(page_title="Risk-Based Vulnerability Management")
    st.title("Risk-Based Vulnerability Management")

    user_choice = st.radio("What would you like to do?", ("Add New Vulnerability", "Search Existing Vulnerabilities"))

    if user_choice == "Add New Vulnerability":
        st.subheader("Add New Vulnerability")
        cve_id = st.text_input("CVE ID")
        vendor_project = st.text_input("Vendor Project")
        product = st.text_input("Product")
        vulnerability_name = st.text_input("Vulnerability Name")
        date_added = st.date_input("Date Added")
        short_description = st.text_area("Short Description")
        required_action = st.text_area("Required Action")
        due_date = st.date_input("Due Date")
        known_ransomware_campaign_use = st.text_input("Known Ransomware Campaign Use")
        notes = st.text_area("Notes")
        cwes = st.text_input("CWEs (comma-separated)")
        cvss_score = st.number_input("CVSS Score", min_value=0.0, max_value=10.0, step=0.1)
        owasp_risk = st.selectbox("OWASP Risk", options=list(owasp_risk_scores.keys()))
        asset_value = st.slider("Asset Value", min_value=1, max_value=10, value=5)
        threat_level = st.slider("Threat Level", min_value=1, max_value=10, value=5)
        exploitability = st.slider("Exploitability", min_value=1, max_value=10, value=5)

        if st.button("Add Vulnerability"):
            new_vulnerability = Vulnerability(
                cve_id=str(cve_id),
                vendor_project=vendor_project,
                product=product,
                vulnerability_name=vulnerability_name,
                date_added=date_added,
                short_description=short_description,
                required_action=required_action,
                due_date=due_date,
                known_ransomware_campaign_use=known_ransomware_campaign_use,
                notes=notes,
                cwes=cwes.split(','),
                cvss_score=cvss_score,
                owasp_risk=owasp_risk,
                asset_value=asset_value,
                threat_level=threat_level,
                exploitability=exploitability
            )
            add_vulnerability(new_vulnerability)
            st.success(f"Vulnerability {cve_id} added to the database.")

    else:
        st.subheader("Search Existing Vulnerabilities")
        search_query = st.text_input("Enter CVE ID (e.g., CVE-2019-16278)")

        vulnerabilities = load_vulnerabilities()

        if search_query:
            # Filter vulnerabilities by the search query
            filtered_vulnerabilities = [v for v in vulnerabilities if v.cve_id == search_query]

            if filtered_vulnerabilities:
                vulnerability = filtered_vulnerabilities[0]
                st.subheader(f"Details for {vulnerability.cve_id}")
                st.write(f"Vendor Project: {vulnerability.vendor_project}")
                st.write(f"Product: {vulnerability.product}")
                st.write(f"Vulnerability Name: {vulnerability.vulnerability_name}")
                st.write(f"Date Added: {vulnerability.date_added.strftime('%Y-%m-%d')}")
                st.write(f"Short Description: {vulnerability.short_description}")
                st.write(f"Required Action: {vulnerability.required_action}")
                st.write(f"Due Date: {vulnerability.due_date.strftime('%Y-%m-%d')}")
                st.write(f"Known Ransomware Campaign Use: {vulnerability.known_ransomware_campaign_use}")
                st.write(f"Notes: {vulnerability.notes}")
                st.write(f"CWEs: {', '.join(vulnerability.cwes)}")
                st.write(f"CVSS Score: {vulnerability.cvss_score}")
                st.write(f"OWASP Risk: {vulnerability.owasp_risk}")
                st.write(f"Asset Value: {vulnerability.asset_value}")
                st.write(f"Threat Level: {vulnerability.threat_level}")
                st.write(f"Exploitability: {vulnerability.exploitability}")
                st.write(f"Priority: {assess_risk(vulnerability)}")
            else:
                st.warning("No vulnerability found with that CVE ID.")

        st.subheader("All Vulnerabilities")
        order_by = st.selectbox("Order By", options=["assess_risk", "cvss_score", "cve_id"])
        displayed_vulnerabilities = get_vulnerabilities(order_by=order_by)

        for vulnerability in displayed_vulnerabilities:
            with st.expander(f"CVE ID: {vulnerability.cve_id}"):
                st.write(f"Vendor Project: {vulnerability.vendor_project}")
                st.write(f"Product: {vulnerability.product}")
                st.write(f"Vulnerability Name: {vulnerability.vulnerability_name}")
                st.write(f"Date Added: {vulnerability.date_added.strftime('%Y-%m-%d')}")
                st.write(f"Short Description: {vulnerability.short_description}")
                st.write(f"Required Action: {vulnerability.required_action}")
                st.write(f"Due Date: {vulnerability.due_date.strftime('%Y-%m-%d')}")
                st.write(f"Known Ransomware Campaign Use: {vulnerability.known_ransomware_campaign_use}")
                st.write(f"Notes: {vulnerability.notes}")
                st.write(f"CWEs: {', '.join(vulnerability.cwes)}")
                st.write(f"CVSS Score: {vulnerability.cvss_score}")
                st.write(f"OWASP Risk: {vulnerability.owasp_risk}")
                st.write(f"Asset Value: {vulnerability.asset_value}")
                st.write(f"Threat Level: {vulnerability.threat_level}")
                st.write(f"Exploitability: {vulnerability.exploitability}")
                st.write(f"Priority: {assess_risk(vulnerability)}")

if __name__ == "__main__":
    vulnerability_management_app()