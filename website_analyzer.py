import requests
from bs4 import BeautifulSoup
import re
import json
from treelib import Tree
import webbrowser
import os
import hashlib
from urllib.parse import urlparse, urljoin

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def analyze_website(url):
    tech_stack = {
        "Frontend": {},
        "Backend": {},
        "Server": {},
        "CDN": {},
        "Analytics": {},
        "Security": {},
        "Frameworks": {},
        "Libraries": {},
        "Fonts": {},
        "Other": {}
    }

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        url = normalize_url(url)
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        
        # Analyze headers
        analyze_headers(response.headers, tech_stack)
        
        # Analyze HTML content
        soup = BeautifulSoup(response.text, 'html.parser')
        analyze_html(soup, tech_stack, url)
        
        # Analyze JavaScript
        analyze_javascript(response.text, tech_stack)
        
        # Analyze meta tags
        analyze_meta_tags(soup, tech_stack)
        
        # Analyze cookies
        analyze_cookies(response.cookies, tech_stack)
        
        return tech_stack
    
    except requests.RequestException as e:
        print(f"Error fetching the website: {e}")
        return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def analyze_headers(headers, tech_stack):
    server = headers.get('Server', 'Unknown')
    tech_stack["Server"]["Web Server"] = server
    
    if 'cloudflare' in headers.get('CF-RAY', '').lower():
        tech_stack["CDN"]["Cloudflare"] = True
    elif 'akamai' in headers.get('X-Cache', '').lower():
        tech_stack["CDN"]["Akamai"] = True
    elif 'fastly' in headers.get('X-Served-By', '').lower():
        tech_stack["CDN"]["Fastly"] = True
    elif 'cloudfront' in headers.get('Via', '').lower():
        tech_stack["CDN"]["CloudFront"] = True
    
    if 'ASP.NET' in headers.get('X-Powered-By', ''):
        tech_stack["Backend"]["Framework"] = "ASP.NET"
    elif 'PHP' in headers.get('X-Powered-By', ''):
        tech_stack["Backend"]["Language"] = "PHP"
    elif 'Express' in headers.get('X-Powered-By', ''):
        tech_stack["Backend"]["Framework"] = "Express.js"
    
    if 'strict-transport-security' in headers:
        tech_stack["Security"]["HSTS"] = True
    
    if 'content-security-policy' in headers:
        tech_stack["Security"]["CSP"] = True

def analyze_html(soup, tech_stack, base_url):
    # Check for JavaScript frameworks
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = urljoin(base_url, script['src'].lower())
        if 'react' in src:
            tech_stack["Frameworks"]["React"] = True
        elif 'vue' in src:
            tech_stack["Frameworks"]["Vue.js"] = True
        elif 'angular' in src:
            tech_stack["Frameworks"]["Angular"] = True
        elif 'jquery' in src:
            tech_stack["Libraries"]["jQuery"] = True
        elif 'bootstrap' in src:
            tech_stack["Frontend"]["CSS Framework"] = "Bootstrap"
        elif 'tailwind' in src:
            tech_stack["Frontend"]["CSS Framework"] = "Tailwind CSS"
    
    # Check for CSS frameworks
    links = soup.find_all('link', rel="stylesheet")
    for link in links:
        href = urljoin(base_url, link.get('href', '').lower())
        if 'bootstrap' in href:
            tech_stack["Frontend"]["CSS Framework"] = "Bootstrap"
        elif 'tailwind' in href:
            tech_stack["Frontend"]["CSS Framework"] = "Tailwind CSS"
        elif 'fontawesome' in href:
            tech_stack["Libraries"]["Font Awesome"] = True
    
    # Check for web fonts
    for link in soup.find_all('link', rel="stylesheet"):
        if 'fonts.googleapis.com' in link.get('href', ''):
            tech_stack["Fonts"]["Google Fonts"] = True
    
    # Check for CMS
    if soup.find(attrs={"name": "generator", "content": re.compile("WordPress", re.I)}):
        tech_stack["Backend"]["CMS"] = "WordPress"
    elif soup.find(attrs={"name": "generator", "content": re.compile("Drupal", re.I)}):
        tech_stack["Backend"]["CMS"] = "Drupal"
    elif soup.find(attrs={"name": "generator", "content": re.compile("Joomla", re.I)}):
        tech_stack["Backend"]["CMS"] = "Joomla"
    elif soup.find(attrs={"name": "generator", "content": re.compile("Shopify", re.I)}):
        tech_stack["Backend"]["E-commerce Platform"] = "Shopify"

def analyze_javascript(content, tech_stack):
    if re.search(r'react.*\.production\.min\.js', content, re.I):
        tech_stack["Frameworks"]["React"] = True
    if re.search(r'vue.*\.js', content, re.I):
        tech_stack["Frameworks"]["Vue.js"] = True
    if re.search(r'angular.*\.js', content, re.I):
        tech_stack["Frameworks"]["Angular"] = True
    if re.search(r'jquery.*\.js', content, re.I):
        tech_stack["Libraries"]["jQuery"] = True
    if re.search(r'lodash.*\.js', content, re.I):
        tech_stack["Libraries"]["Lodash"] = True
    
    # Check for analytics
    if re.search(r'google-analytics.com|googletagmanager.com', content, re.I):
        tech_stack["Analytics"]["Google Analytics"] = True
    if re.search(r'script\.hotjar\.com', content, re.I):
        tech_stack["Analytics"]["Hotjar"] = True
    if re.search(r'cdn\.segment\.com', content, re.I):
        tech_stack["Analytics"]["Segment"] = True

def analyze_meta_tags(soup, tech_stack):
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator:
        content = meta_generator.get('content', '').lower()
        if 'wordpress' in content:
            tech_stack["Backend"]["CMS"] = "WordPress"
        elif 'drupal' in content:
            tech_stack["Backend"]["CMS"] = "Drupal"
        elif 'joomla' in content:
            tech_stack["Backend"]["CMS"] = "Joomla"
        elif 'shopify' in content:
            tech_stack["Backend"]["E-commerce Platform"] = "Shopify"
        elif 'wix' in content:
            tech_stack["Backend"]["Website Builder"] = "Wix"

def analyze_cookies(cookies, tech_stack):
    for cookie in cookies:
        if cookie.name.startswith('_ga'):
            tech_stack["Analytics"]["Google Analytics"] = True
        elif cookie.name.startswith('_hj'):
            tech_stack["Analytics"]["Hotjar"] = True
        elif cookie.name == 'PHPSESSID':
            tech_stack["Backend"]["Language"] = "PHP"
        elif cookie.name.startswith('ASP.NET'):
            tech_stack["Backend"]["Framework"] = "ASP.NET"

def tree_to_html(tree, node, parent=None):
    html = ""
    if parent is None:
        html += f"<li>{node.tag}"
    else:
        html += f"<li>{node.tag}"
    children = tree.children(node.identifier)
    if children:
        html += "<ul>"
        for child in children:
            html += tree_to_html(tree, child, node)
        html += "</ul>"
    html += "</li>"
    return html

def create_tree_diagram(tech_stack, url):
    tree = Tree()
    tree.create_node("Website", "root")
    
    def add_nodes(parent, children, parent_id):
        for key, value in children.items():
            if isinstance(value, dict):
                new_id = hashlib.md5(f"{parent_id}_{key}".encode()).hexdigest()
                tree.create_node(key, new_id, parent=parent_id)
                add_nodes(key, value, new_id)
            else:
                new_id = hashlib.md5(f"{parent_id}_{key}_{value}".encode()).hexdigest()
                tree.create_node(f"{key}: {value}", new_id, parent=parent_id)
    
    add_nodes("Website", tech_stack, "root")
    
    # Generate HTML
    html_content = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Website Technology Stack: {url}</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                margin: 0;
                padding: 20px;
                background-color: #f0f0f0;
            }}
            .tree {{
                margin-left: 20px;
            }}
            .tree ul {{
                list-style-type: none;
                padding-left: 20px;
            }}
            .tree li {{
                margin: 10px 0;
                position: relative;
            }}
            .tree li::before {{
                content: '';
                position: absolute;
                top: -5px;
                left: -20px;
                border-left: 1px solid #ccc;
                border-bottom: 1px solid #ccc;
                width: 20px;
                height: 15px;
            }}
            .tree li:last-child::before {{
                border-left: none;
            }}
            .tree li::after {{
                content: '';
                position: absolute;
                border-top: 1px solid #ccc;
                top: 10px;
                left: -20px;
                width: 20px;
            }}
        </style>
    </head>
    <body>
        <h1>Website Technology Stack: {url}</h1>
        <div class="tree">
            <ul>
                {tree_to_html(tree, tree.get_node(tree.root))}
            </ul>
        </div>
    </body>
    </html>
    """
    
    with open("tech_stack_diagram.html", "w", encoding="utf-8") as f:
        f.write(html_content)

# Example usage
url = input("Enter the website URL to analyze (e.g., google.com): ")
tech_stack = analyze_website(url)

if tech_stack:
    print(json.dumps(tech_stack, indent=2))
    create_tree_diagram(tech_stack, url)
    print("Technology stack diagram saved as 'tech_stack_diagram.html'")
    
    # Open the HTML file in the default web browser
    webbrowser.open('file://' + os.path.realpath("tech_stack_diagram.html"))
else:
    print("Failed to analyze the website.")