import streamlit as st
import pandas as pd
import requests
from requests.auth import HTTPBasicAuth
import re
from urllib.parse import urlparse, urljoin
import json
from datetime import datetime
import time
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed

st.set_page_config(page_title="SERP & Contact Extraction Tool", layout="wide", page_icon="🔍")

# Initialize session state
if 'serp_results' not in st.session_state:
    st.session_state.serp_results = None
if 'contact_results' not in st.session_state:
    st.session_state.contact_results = None
if 'snov_token' not in st.session_state:
    st.session_state.snov_token = None

# Custom CSS
st.markdown("""
    <style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        margin-bottom: 0.5rem;
    }
    .sub-header {
        font-size: 1.2rem;
        color: #666;
        margin-bottom: 2rem;
    }
    .stButton>button {
        width: 100%;
        background-color: #1f77b4;
        color: white;
        font-weight: bold;
    }
    </style>
""", unsafe_allow_html=True)

# ==================== HELPER FUNCTIONS ====================

def extract_emails_from_text(text):
    """Extract email addresses from text using regex"""
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    emails = re.findall(email_pattern, text)
    filtered_emails = []
    for email in emails:
        email = email.lower().strip()
        if not any(ext in email for ext in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.css', '.js', '.woff', '.ttf']):
            if '@' in email and '.' in email.split('@')[1]:
                if not any(word in email for word in ['example', 'test', 'sample', 'domain', 'email', 'your']):
                    filtered_emails.append(email)
    return list(set(filtered_emails))

def find_contact_pages(soup, base_url, domain):
    """Intelligently find contact pages by analyzing all links"""
    contact_keywords = [
        'contact', 'about', 'team', 'staff', 'people', 'who-we-are',
        'get-in-touch', 'reach', 'write', 'support', 'help',
        'company', 'our-team', 'meet', 'leadership', 'management',
        'connect', 'touch', 'reach-us', 'contact-us', 'about-us',
        'careers', 'office', 'location', 'headquarters'
    ]

    candidate_urls = []
    found_keywords = set()

    for link in soup.find_all('a', href=True):
        href = link.get('href', '').lower()
        link_text = link.get_text().lower().strip()

        if href.startswith(('http://', 'https://')):
            link_domain = urlparse(href).netloc.replace('www.', '')
            if link_domain != domain:
                continue
        elif href.startswith(('#', 'javascript:', 'mailto:', 'tel:')):
            continue
        elif any(href.endswith(ext) for ext in ['.pdf', '.doc', '.zip', '.jpg', '.png', '.gif']):
            continue

        matches = []
        for keyword in contact_keywords:
            if keyword in href or keyword in link_text:
                matches.append(keyword)

        if matches:
            full_url = urljoin(base_url, href)
            if full_url not in [url for url, _ in candidate_urls]:
                candidate_urls.append((full_url, matches))
                found_keywords.update(matches)

    candidate_urls.sort(key=lambda x: len(x[1]), reverse=True)
    return candidate_urls, list(found_keywords)

def scrape_contact_page(domain, timeout=10, max_pages=5):
    """Intelligently scrape contact information from a domain"""
    results = {
        'domain': domain,
        'emails': [],
        'contact_pages_found': [],
        'contact_page': None,
        'linkedin': None,
        'twitter': None,
        'facebook': None,
        'status': 'Not Found',
        'method': 'Scraping',
        'pages_checked': []
    }

    try:
        url = f"https://{domain}"
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        }

        response = requests.get(url, headers=headers, timeout=timeout, allow_redirects=True)
        if response.status_code != 200:
            results['status'] = f'Error: HTTP {response.status_code}'
            return results

        soup = BeautifulSoup(response.text, 'html.parser')
        results['pages_checked'].append(url)

        for script in soup(["script", "style", "noscript"]):
            script.decompose()

        text = soup.get_text()
        html_text = response.text
        emails = extract_emails_from_text(text + " " + html_text)
        results['emails'].extend(emails)

        for link in soup.find_all('a', href=True):
            href = link['href'].lower()
            if 'linkedin.com' in href:
                results['linkedin'] = link['href']
            elif 'twitter.com' in href or 'x.com' in href:
                results['twitter'] = link['href']
            elif 'facebook.com' in href:
                results['facebook'] = link['href']

        candidate_urls, found_keywords = find_contact_pages(soup, url, domain)

        if candidate_urls:
            results['contact_pages_found'] = [url for url, _ in candidate_urls[:max_pages]]

        for contact_url, keywords in candidate_urls[:max_pages]:
            try:
                contact_response = requests.get(contact_url, headers=headers, timeout=timeout)
                if contact_response.status_code == 200:
                    results['pages_checked'].append(contact_url)
                    contact_soup = BeautifulSoup(contact_response.text, 'html.parser')

                    for script in contact_soup(["script", "style", "noscript"]):
                        script.decompose()

                    contact_text = contact_soup.get_text()
                    contact_emails = extract_emails_from_text(contact_text + " " + contact_response.text)

                    if contact_emails:
                        results['emails'].extend(contact_emails)
                        if not results['contact_page']:
                            results['contact_page'] = contact_url

                time.sleep(0.2)
            except Exception as e:
                continue

        results['emails'] = list(set(results['emails']))

        if results['emails']:
            results['status'] = 'Found'
        else:
            results['status'] = 'Not Found'

    except requests.Timeout:
        results['status'] = 'Error: Timeout'
    except requests.ConnectionError:
        results['status'] = 'Error: Connection Failed'
    except Exception as e:
        results['status'] = f'Error: {str(e)[:50]}'

    return results

def get_snov_access_token(client_id, client_secret):
    """Get Snov.io OAuth access token"""
    url = "https://api.snov.io/v1/oauth/access_token"
    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
    }
    try:
        res = requests.post(url, data=payload, timeout=15)
        if res.status_code == 200:
            data = res.json()
            return data.get("access_token")
        else:
            return None
    except Exception as e:
        return None

def snov_get_domain_emails(domain, access_token):
    """Get emails from domain using Snov.io API v2 (CORRECT endpoint)"""
    start_url = "https://api.snov.io/v2/domain-search/domain-emails/start"
    headers = {"Authorization": f"Bearer {access_token}"}
    params = {"domain": domain}

    try:
        start_res = requests.post(start_url, params=params, headers=headers, timeout=30)
        if start_res.status_code != 200:
            return {'success': False, 'error': f"Start failed: HTTP {start_res.status_code}"}

        start_data = start_res.json()
        if 'meta' not in start_data or 'task_hash' not in start_data['meta']:
            return {'success': False, 'error': 'No task_hash'}

        task_hash = start_data['meta']['task_hash']
        time.sleep(2)

        result_url = f"https://api.snov.io/v2/domain-search/domain-emails/result/{task_hash}"
        result_res = requests.get(result_url, headers=headers, timeout=30)

        if result_res.status_code != 200:
            return {'success': False, 'error': f"Result failed: HTTP {result_res.status_code}"}

        result_data = result_res.json()
        emails = []
        if 'data' in result_data and isinstance(result_data['data'], list):
            for item in result_data['data']:
                if isinstance(item, dict) and 'email' in item:
                    emails.append(item['email'])

        return {'success': True, 'emails': list(set(emails)), 'raw_data': result_data}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def extract_contacts_with_fallback(domain, timeout, max_pages, snov_token=None, use_snov=False):
    """Extract contacts using BOTH scraping AND Snov.io (parallel mode)"""
    result = scrape_contact_page(domain, timeout, max_pages)
    scraping_emails = list(result['emails']) if result['emails'] else []
    snov_emails = []

    if use_snov and snov_token:
        try:
            snov_result = snov_get_domain_emails(domain, snov_token)
            if snov_result['success'] and snov_result['emails']:
                snov_emails = snov_result['emails']
        except:
            pass

    all_emails = list(set(scraping_emails + snov_emails))
    result['emails'] = all_emails
    result['scraping_count'] = len(scraping_emails)
    result['snov_count'] = len(snov_emails)

    if scraping_emails and snov_emails:
        result['method'] = 'Scraping + Snov.io'
    elif scraping_emails:
        result['method'] = 'Scraping Only'
    elif snov_emails:
        result['method'] = 'Snov.io Only'
    else:
        result['method'] = 'None'

    result['status'] = 'Found' if all_emails else 'Not Found'
    return result

def call_dataforseo_serp_api(keywords, login, password, location="United States", language="English", device="desktop", batch_mode=False):
    """Call DataForSEO SERP API - Sequential mode by DEFAULT (avoids error 40000)"""
    url = "https://api.dataforseo.com/v3/serp/google/organic/live/advanced"

    if batch_mode and len(keywords) > 1:
        # BATCH MODE (May trigger error 40000)
        tasks = []
        for keyword in keywords:
            task = {
                "keyword": keyword,
                "location_name": location,
                "language_code": "en" if language == "English" else "es",
                "device": device.lower(),
                "os": "windows" if device.lower() == "desktop" else "ios",
                "depth": 100
            }
            tasks.append(task)

        try:
            response = requests.post(url, json=tasks, auth=HTTPBasicAuth(login, password),
                                   headers={'Content-Type': 'application/json'}, timeout=120)
            if response.status_code == 200:
                return response.json()
            else:
                return {"error": f"HTTP {response.status_code}", "response": response.text}
        except Exception as e:
            return {"error": str(e)}
    else:
        # SEQUENTIAL MODE (RECOMMENDED - Avoids error 40000)
        combined_response = {"tasks": [], "status_code": 20000}

        st.info(f"🔄 Sequential Mode: Processing {len(keywords)} keyword(s) one-by-one (avoids error 40000)...")

        for idx, keyword in enumerate(keywords):
            task = [{
                "keyword": keyword,
                "location_name": location,
                "language_code": "en" if language == "English" else "es",
                "device": device.lower(),
                "os": "windows" if device.lower() == "desktop" else "ios",
                "depth": 100
            }]

            try:
                st.info(f"📡 Processing keyword {idx + 1}/{len(keywords)}: '{keyword}'")

                response = requests.post(url, json=task, auth=HTTPBasicAuth(login, password),
                                       headers={'Content-Type': 'application/json'}, timeout=120)

                if response.status_code == 200:
                    data = response.json()
                    if 'tasks' in data and len(data['tasks']) > 0:
                        combined_response['tasks'].extend(data['tasks'])
                        result_count = len(data['tasks'][0].get('result', [{}])[0].get('items', []))
                        st.success(f"✅ '{keyword}' completed - {result_count} results")
                else:
                    st.warning(f"⚠️ '{keyword}' failed: HTTP {response.status_code}")

                if idx < len(keywords) - 1:
                    time.sleep(1)

            except Exception as e:
                st.error(f"❌ '{keyword}' error: {str(e)}")
                continue

        return combined_response if combined_response['tasks'] else {"error": "All keywords failed"}

def parse_dataforseo_results(api_response):
    """Parse DataForSEO API response with enhanced error handling"""
    all_results = []

    try:
        if 'tasks' not in api_response:
            st.error("No 'tasks' key in API response")
            return None

        for task_idx, task in enumerate(api_response['tasks']):
            task_results = []

            if task['status_code'] != 20000:
                status_code = task['status_code']
                keyword = task.get('data', {}).get('keyword', 'Unknown')
                error_msg = task.get('status_message', 'Unknown')

                if status_code == 40000:
                    st.error(f"❌ Task {task_idx + 1} ('{keyword}'): Error 40000")
                    st.info("💡 Leave 'Batch Mode' UNCHECKED to fix this")
                elif status_code == 40102:
                    st.warning(f"⚠️ Task {task_idx + 1} ('{keyword}'): No results")
                elif status_code == 40200:
                    st.error(f"❌ Task {task_idx + 1} ('{keyword}'): Payment required")
                elif status_code == 40202:
                    st.error(f"❌ Task {task_idx + 1} ('{keyword}'): Rate limit")
                elif status_code == 40210:
                    st.error(f"❌ Task {task_idx + 1} ('{keyword}'): Insufficient funds")
                else:
                    st.warning(f"⚠️ Task {task_idx + 1} ('{keyword}'): Status {status_code} - {error_msg}")
                continue

            if 'result' not in task or not task['result']:
                continue

            keyword = task.get('data', {}).get('keyword', 'Unknown')

            for result_item in task['result']:
                if 'items' not in result_item:
                    continue

                for item in result_item['items']:
                    if item.get('type') == 'organic':
                        parsed_url = urlparse(item.get('url', ''))
                        domain = parsed_url.netloc.replace('www.', '')

                        result = {
                            'keyword': keyword,
                            'serp_position': item.get('rank_absolute', 0),
                            'domain': domain,
                            'page_url': item.get('url', ''),
                            'page_title': item.get('title', ''),
                            'description': item.get('description', ''),
                            'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                        }
                        task_results.append(result)

            all_results.extend(task_results)
            if task_results:
                st.info(f"✅ Keyword '{keyword}': Found {len(task_results)} results")

        if all_results:
            df = pd.DataFrame(all_results)
            st.success(f"📊 Total: {len(all_results)} results from {len(api_response['tasks'])} keywords")
            return df
        else:
            st.warning("No organic results found")
            return None

    except Exception as e:
        st.error(f"❌ Error parsing: {str(e)}")
        return None

# ==================== HEADER ====================

st.markdown('<div class="main-header">🔍 SERP & Contact Extraction Tool</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Sequential Mode by Default - No Error 40000!</div>', unsafe_allow_html=True)

# ==================== SIDEBAR ====================

with st.sidebar:
    st.header("⚙️ Configuration")

    st.subheader("DataForSEO API")
    dataforseo_login = st.text_input("API Login", help="Your DataForSEO email")
    dataforseo_password = st.text_input("API Password", type="password")

    st.divider()

    st.subheader("Snov.io API (Optional)")
    st.info("💡 Runs in parallel with scraping")
    snov_client_id = st.text_input("Client ID (User ID)")
    snov_client_secret = st.text_input("Client Secret", type="password")

    if snov_client_id and snov_client_secret:
        if st.button("🔐 Authenticate Snov.io"):
            with st.spinner("Authenticating..."):
                token = get_snov_access_token(snov_client_id, snov_client_secret)
                if token:
                    st.session_state.snov_token = token
                    st.success("✅ Authenticated!")
                else:
                    st.error("❌ Failed")

        if st.session_state.snov_token:
            st.success("✅ Snov.io Active - Parallel mode enabled")

    st.divider()

    st.subheader("Scraping Settings")
    st.info("🤖 Intelligent page discovery enabled")

# ==================== TABS ====================

tab1, tab2, tab3 = st.tabs(["🔍 SERP Extraction", "📧 Contact Extraction", "📊 Results"])

# ==================== TAB 1: SERP ====================

with tab1:
    st.header("Extract Top 100 SERP Results")

    st.success("✅ Sequential Mode Active by Default - NO ERROR 40000!")

    col1, col2 = st.columns([3, 1])

    with col1:
        input_method = st.radio("Input Method", ["Single Keyword", "Bulk Keywords"], horizontal=True)

        if input_method == "Single Keyword":
            keyword = st.text_input("Enter Keyword", placeholder="crypto casino")
            keywords_list = [keyword.strip()] if keyword.strip() else []
        else:
            keywords_bulk = st.text_area("Enter Keywords (one per line)", 
                                        placeholder="crypto casino\nbitcoin slots\nonline gambling",
                                        height=150)
            keywords_list = [k.strip() for k in keywords_bulk.split("\n") if k.strip()]

    with col2:
        location = st.text_input("Location", value="United States")
        language = st.selectbox("Language", ["English", "Spanish"])
        device = st.selectbox("Device", ["Desktop", "Mobile"])

    st.divider()

    col1, col2 = st.columns([3, 1])
    with col1:
        exclude_domains = st.text_area("Exclude Domains (one per line)", 
                                       placeholder="youtube.com\nwikipedia.org",
                                       help="Domains to exclude from results")
    with col2:
        st.write("")
        st.write("")
        remove_duplicates = st.checkbox("Remove Duplicate Domains", value=True)

    st.divider()

    if keywords_list:
        st.success(f"📝 {len(keywords_list)} keyword(s) ready • Will extract up to {len(keywords_list) * 100} results")

        if len(keywords_list) > 1:
            batch_mode = st.checkbox(
                "⚡ Batch Mode (faster but may fail with error 40000)", 
                value=False,
                help="Leave UNCHECKED (recommended). Only check if your account supports batch."
            )

            if not batch_mode:
                st.success("✅ Sequential Mode - Keywords processed one-by-one (RECOMMENDED)")
            else:
                st.warning("⚠️ Batch Mode - May cause error 40000 on some accounts")
        else:
            batch_mode = False
    else:
        batch_mode = False

    if st.button("🚀 Extract Top 100 SERP Results", type="primary", disabled=not keywords_list):
        if not dataforseo_login or not dataforseo_password:
            st.error("⚠️ Please enter DataForSEO API credentials in the sidebar")
        else:
            with st.spinner("Extracting SERP results..."):
                start_time = time.time()

                api_response = call_dataforseo_serp_api(
                    keywords_list, 
                    dataforseo_login, 
                    dataforseo_password,
                    location=location,
                    language=language,
                    device=device,
                    batch_mode=batch_mode
                )

                if 'error' in api_response:
                    st.error(f"❌ API Error: {api_response['error']}")
                    if 'response' in api_response:
                        with st.expander("View API Response"):
                            st.code(api_response['response'])
                else:
                    df_results = parse_dataforseo_results(api_response)

                    if df_results is not None and len(df_results) > 0:
                        # Apply filters
                        if exclude_domains:
                            excluded = [d.strip() for d in exclude_domains.split("\n") if d.strip()]
                            df_results = df_results[~df_results['domain'].isin(excluded)]

                        if remove_duplicates:
                            df_results = df_results.sort_values('serp_position').drop_duplicates(
                                subset=['keyword', 'domain'], keep='first'
                            )

                        st.session_state.serp_results = df_results

                        elapsed = time.time() - start_time
                        st.success(f"✅ Extracted {len(df_results)} results from {df_results['keyword'].nunique()} keywords in {elapsed:.1f}s")
                        st.balloons()

                        col1, col2, col3, col4 = st.columns(4)
                        with col1:
                            st.metric("Total Results", len(df_results))
                        with col2:
                            st.metric("Unique Domains", df_results['domain'].nunique())
                        with col3:
                            st.metric("Keywords", df_results['keyword'].nunique())
                        with col4:
                            avg_pos = df_results['serp_position'].mean()
                            st.metric("Avg Position", f"{avg_pos:.1f}")

                        st.subheader("Preview Results")
                        st.dataframe(df_results.head(20), use_container_width=True)
                    else:
                        st.warning("No results found. Check your keywords and credentials.")

# ==================== TAB 2: CONTACTS ====================

with tab2:
    st.header("Intelligent Contact Extraction")

    st.success("🤖 **Smart Page Discovery Active** - Automatically finds contact pages")

    if st.session_state.snov_token:
        st.success("✅ Snov.io API Active - Will run in parallel with scraping")
    else:
        st.warning("⚠️ Snov.io not authenticated - Only web scraping will be used")

    extraction_source = st.radio("Contact Extraction Source", 
                                ["Use SERP Results", "Upload Domain List"], 
                                horizontal=True)

    domains_to_process = []

    if extraction_source == "Use SERP Results":
        if st.session_state.serp_results is not None:
            unique_domains = st.session_state.serp_results['domain'].unique()
            st.write(f"**{len(unique_domains)} unique domains** from SERP results")
            domains_to_process = unique_domains.tolist()

            with st.expander("Preview Domains"):
                st.write(", ".join(unique_domains[:30]))
                if len(unique_domains) > 30:
                    st.write(f"... and {len(unique_domains) - 30} more")
        else:
            st.warning("⚠️ No SERP results available. Extract SERP results first or upload a domain list.")

    else:
        st.subheader("Upload Domains")

        upload_method = st.radio("Upload Method", ["Paste Domains", "Upload CSV"], horizontal=True)

        if upload_method == "Paste Domains":
            domains_text = st.text_area("Paste Domains (one per line)", 
                                       placeholder="example.com\nanothersite.com\nwebsite.org",
                                       height=200)
            if domains_text:
                domains_to_process = [d.strip().replace('https://', '').replace('http://', '').replace('www.', '') 
                                     for d in domains_text.split("\n") if d.strip()]
                st.success(f"✅ {len(domains_to_process)} domains ready")

        else:
            uploaded_file = st.file_uploader("Upload CSV file with domains", type=['csv'])
            if uploaded_file is not None:
                try:
                    df_upload = pd.read_csv(uploaded_file)
                    domain_column = None
                    for col in df_upload.columns:
                        if 'domain' in col.lower() or 'url' in col.lower() or 'website' in col.lower():
                            domain_column = col
                            break

                    if domain_column:
                        domains_to_process = df_upload[domain_column].dropna().unique().tolist()
                        domains_to_process = [d.strip().replace('https://', '').replace('http://', '').replace('www.', '') 
                                            for d in domains_to_process if str(d).strip()]
                        st.success(f"✅ Loaded {len(domains_to_process)} domains from: {domain_column}")
                    else:
                        st.error("Could not find domain column. Ensure CSV has 'domain', 'url', or 'website' column.")
                except Exception as e:
                    st.error(f"Error reading CSV: {str(e)}")

    st.divider()

    col1, col2, col3 = st.columns(3)
    with col1:
        max_workers = st.slider("Concurrent Requests", min_value=1, max_value=10, value=5, 
                               help="Number of domains to process simultaneously")
    with col2:
        timeout = st.slider("Timeout (seconds)", min_value=5, max_value=30, value=10,
                           help="Timeout for each page request")
    with col3:
        max_pages = st.slider("Max Pages per Domain", min_value=1, max_value=10, value=5,
                             help="Maximum number of contact pages to check per domain")

    st.divider()

    use_snov_parallel = st.checkbox("Use Snov.io API (Parallel)", value=True, 
                                    disabled=not st.session_state.snov_token,
                                    help="Use Snov.io API in parallel with scraping")

    st.divider()

    if st.button("📧 Extract Contacts", type="primary", disabled=len(domains_to_process) == 0):
        with st.spinner(f"Intelligently extracting contacts from {len(domains_to_process)} domains..."):
            progress_bar = st.progress(0)
            status_text = st.empty()

            contact_results = []
            completed = 0

            use_snov = use_snov_parallel and st.session_state.snov_token

            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_domain = {
                    executor.submit(
                        extract_contacts_with_fallback, 
                        domain, 
                        timeout,
                        max_pages,
                        st.session_state.snov_token,
                        use_snov
                    ): domain for domain in domains_to_process
                }

                for future in as_completed(future_to_domain):
                    result = future.result()
                    contact_results.append(result)
                    completed += 1
                    progress_bar.progress(completed / len(domains_to_process))
                    status_text.text(f"Processed {completed}/{len(domains_to_process)} domains...")

            df_contacts = pd.DataFrame(contact_results)
            st.session_state.contact_results = df_contacts

            found_count = len(df_contacts[df_contacts['status'] == 'Found'])
            scraping_only = len(df_contacts[df_contacts['method'] == 'Scraping Only'])
            snov_only = len(df_contacts[df_contacts['method'] == 'Snov.io Only'])
            both = len(df_contacts[df_contacts['method'] == 'Scraping + Snov.io'])

            st.success(f"✅ Extraction complete! Found contacts for {found_count}/{len(domains_to_process)} domains")

            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Domains", len(domains_to_process))
            with col2:
                st.metric("Contacts Found", found_count)
            with col3:
                st.metric("Both Methods", both)
            with col4:
                st.metric("Success Rate", f"{(found_count/len(domains_to_process)*100):.1f}%")

            st.subheader("Preview Contact Results")
            preview_df = df_contacts.copy()
            preview_df['emails'] = preview_df['emails'].apply(lambda x: ', '.join(x) if isinstance(x, list) and x else 'None')
            preview_df['pages_checked_count'] = df_contacts['pages_checked'].apply(lambda x: len(x) if isinstance(x, list) else 0)
            preview_df['contact_pages_found_count'] = df_contacts['contact_pages_found'].apply(lambda x: len(x) if isinstance(x, list) else 0)

            display_cols = ['domain', 'status', 'method', 'emails', 'scraping_count', 'snov_count', 
                          'pages_checked_count', 'contact_pages_found_count', 'contact_page']
            st.dataframe(preview_df[display_cols].head(20), use_container_width=True)

# ==================== TAB 3: RESULTS ====================

with tab3:
    st.header("Results Dashboard")

    if st.session_state.serp_results is not None:
        st.subheader("📈 SERP Results (Top 100)")

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Results", len(st.session_state.serp_results))
        with col2:
            st.metric("Unique Domains", st.session_state.serp_results['domain'].nunique())
        with col3:
            st.metric("Keywords", st.session_state.serp_results['keyword'].nunique())
        with col4:
            avg_position = st.session_state.serp_results['serp_position'].mean()
            st.metric("Avg Position", f"{avg_position:.1f}")

        search_serp = st.text_input("🔍 Search SERP results", placeholder="Filter by keyword, domain...")

        filtered_serp = st.session_state.serp_results
        if search_serp:
            mask = filtered_serp.astype(str).apply(lambda x: x.str.contains(search_serp, case=False, na=False)).any(axis=1)
            filtered_serp = filtered_serp[mask]

        st.dataframe(filtered_serp, use_container_width=True, height=300)

        csv_serp = filtered_serp.to_csv(index=False).encode('utf-8')
        st.download_button(
            label="📥 Download SERP Results (CSV)",
            data=csv_serp,
            file_name=f"serp_top100_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )

        st.divider()

    if st.session_state.contact_results is not None:
        st.subheader("📧 Contact Extraction Results")

        df_contacts = st.session_state.contact_results

        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Domains Processed", len(df_contacts))
        with col2:
            found = len(df_contacts[df_contacts['status'] == 'Found'])
            st.metric("Contacts Found", found)
        with col3:
            total_emails = df_contacts['emails'].apply(lambda x: len(x) if isinstance(x, list) else 0).sum()
            st.metric("Total Emails", total_emails)
        with col4:
            success_rate = (found / len(df_contacts) * 100) if len(df_contacts) > 0 else 0
            st.metric("Success Rate", f"{success_rate:.1f}%")

        display_df = df_contacts.copy()
        display_df['emails'] = display_df['emails'].apply(lambda x: ', '.join(x) if isinstance(x, list) and x else '')
        display_df['email_count'] = df_contacts['emails'].apply(lambda x: len(x) if isinstance(x, list) else 0)
        display_df['pages_checked_count'] = df_contacts['pages_checked'].apply(lambda x: len(x) if isinstance(x, list) else 0)

        col1, col2, col3 = st.columns([2, 1, 1])
        with col1:
            search_filter = st.text_input("🔍 Search contacts", placeholder="Filter by domain, email...")
        with col2:
            st.write("")
            st.write("")
            show_found_only = st.checkbox("Found only", value=False)
        with col3:
            st.write("")
            st.write("")
            filter_method = st.selectbox("Method", ["All", "Scraping Only", "Snov.io Only", "Scraping + Snov.io"])

        filtered_df = display_df.copy()
        if search_filter:
            mask = filtered_df.astype(str).apply(lambda x: x.str.contains(search_filter, case=False, na=False)).any(axis=1)
            filtered_df = filtered_df[mask]
        if show_found_only:
            filtered_df = filtered_df[filtered_df['status'] == 'Found']
        if filter_method != "All":
            filtered_df = filtered_df[filtered_df['method'] == filter_method]

        display_columns = ['domain', 'status', 'method', 'emails', 'email_count', 'scraping_count', 
                          'snov_count', 'pages_checked_count', 'contact_page', 'linkedin', 'twitter']
        st.dataframe(filtered_df[display_columns], use_container_width=True, height=400)

        st.subheader("📥 Export Contact Results")
        col1, col2, col3 = st.columns(3)

        with col1:
            csv_contacts = filtered_df.to_csv(index=False).encode('utf-8')
            st.download_button(
                label="📄 Download CSV",
                data=csv_contacts,
                file_name=f"contacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
                mime="text/csv"
            )

        with col2:
            all_emails = []
            for emails in df_contacts[df_contacts['status'] == 'Found']['emails']:
                if isinstance(emails, list):
                    all_emails.extend(emails)
            unique_emails = list(set(all_emails))
            email_text = "\n".join(unique_emails)
            st.download_button(
                label="📧 Download Emails (TXT)",
                data=email_text,
                file_name=f"emails_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

        with col3:
            json_data = filtered_df.to_json(orient='records', indent=2)
            st.download_button(
                label="📋 Download JSON",
                data=json_data,
                file_name=f"contacts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )

    if st.session_state.serp_results is None and st.session_state.contact_results is None:
        st.info("👈 No results yet. Start by extracting SERP results or contact information!")

# Footer
st.divider()
st.markdown("""
    <div style='text-align: center; color: #666; padding: 1rem;'>
        <p><strong>SERP & Contact Extraction Tool v4.0 COMPLETE</strong></p>
        <p><small>✅ Sequential Mode Default • ✅ Parallel Snov.io • ✅ Smart Contact Discovery • ✅ No Error 40000</small></p>
    </div>
""", unsafe_allow_html=True)
