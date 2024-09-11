import asyncio
import aiohttp
from bs4 import BeautifulSoup
import re
import json
from treelib import Tree
import webbrowser
import os
import hashlib
from urllib.parse import urlparse, urljoin
import ssl
import socket
import whois
import dns.resolver
import tldextract
import logging
from user_agents import parse
import time
import requests
import dns.resolver
import tldextract
import re
from bs4 import BeautifulSoup

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def normalize_url(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

async def analyze_website(url):
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
        "CMS": {},
        "E-commerce": {},
        "Advertising": {},
        "Hosting": {},
        "SSL": {},
        "DNS": {},
        "Domain": {},
        "Performance": {},
        "Marketing": {},
        "Social Media": {},
        "Other": {}
    }

    try:
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        }
        url = normalize_url(url)
        
        async with aiohttp.ClientSession() as session:
            start_time = time.time()
            async with session.get(url, headers=headers, timeout=10) as response:
                html_content = await response.text()
                response_headers = response.headers
            end_time = time.time()
        
        # Analyze headers
        analyze_headers(response_headers, tech_stack)
        
        # Analyze HTML content
        soup = BeautifulSoup(html_content, 'html.parser')
        analyze_html(soup, tech_stack, url)
        
        # Analyze JavaScript
        analyze_javascript(html_content, tech_stack)
        
        # Analyze meta tags
        analyze_meta_tags(soup, tech_stack)
        
        # Analyze SSL certificate
        await analyze_ssl_cert(url, tech_stack)
        
        # Analyze DNS records
        await analyze_dns(url, tech_stack)
        
        # Analyze WHOIS information
        await analyze_whois(url, tech_stack)
        
        # Analyze performance
        analyze_performance(response_headers, start_time, end_time, tech_stack)
        
        # Analyze third-party services
        analyze_third_party_services(html_content, tech_stack)
        
        # Detect marketing technologies
        detect_marketing_technologies(html_content, tech_stack)
        
        # Find social media handles
        find_social_media_handles(soup, tech_stack)
        
        return tech_stack
    
    except Exception as e:
        logger.error(f"An error occurred: {e}")
        return None

def analyze_headers(headers, tech_stack):
    server = headers.get('Server', 'Unknown')
    tech_stack["Server"]["Web Server"] = server
    
    # CDN detection
    cdn_headers = {
        'CF-RAY': 'Cloudflare',
        'X-Cache': 'Akamai',
        'X-Served-By': 'Fastly',
        'Via': 'CloudFront',
        'X-CDN': 'AWS',
        'X-Azure-Ref': 'Azure CDN',
        'X-Powered-By-ChinaCache': 'ChinaCache'
    }
    
    for header, cdn in cdn_headers.items():
        if header in headers:
            tech_stack["CDN"][cdn] = True
    
    # Backend frameworks
    backend_headers = {
        'X-Powered-By': {
            'ASP.NET': 'ASP.NET',
            'PHP': 'PHP',
            'Express': 'Express.js',
            'JSF': 'JavaServer Faces',
            'Servlet': 'Java Servlet',
            'Ruby': 'Ruby',
            'Phusion Passenger': 'Phusion Passenger'
        }
    }
    
    for header, frameworks in backend_headers.items():
        if header in headers:
            for framework, name in frameworks.items():
                if framework in headers[header]:
                    tech_stack["Backend"]["Framework"] = name
    
    # Security headers
    security_headers = [
        'Strict-Transport-Security',
        'Content-Security-Policy',
        'X-XSS-Protection',
        'X-Frame-Options',
        'X-Content-Type-Options',
        'Referrer-Policy'
    ]
    
    for header in security_headers:
        if header.lower() in [h.lower() for h in headers]:
            tech_stack["Security"][header] = True

def analyze_html(soup, tech_stack, base_url):
    # Check for JavaScript frameworks
    script_frameworks = {
        'react': 'React',
        'vue': 'Vue.js',
        'angular': 'Angular',
        'jquery': 'jQuery',
        'backbone': 'Backbone.js',
        'ember': 'Ember.js',
        'knockout': 'Knockout.js',
        'mootools': 'MooTools',
        'prototype': 'Prototype',
        'dojo': 'Dojo'
    }
    
    scripts = soup.find_all('script', src=True)
    for script in scripts:
        src = urljoin(base_url, script['src'].lower())
        for keyword, framework in script_frameworks.items():
            if keyword in src:
                tech_stack["Frameworks"][framework] = True
    
    # Check for CSS frameworks
    css_frameworks = {
        'bootstrap': 'Bootstrap',
        'tailwind': 'Tailwind CSS',
        'foundation': 'Foundation',
        'bulma': 'Bulma',
        'semantic-ui': 'Semantic UI',
        'materialize': 'Materialize'
    }
    
    links = soup.find_all('link', rel="stylesheet")
    for link in links:
        href = urljoin(base_url, link.get('href', '').lower())
        for keyword, framework in css_frameworks.items():
            if keyword in href:
                tech_stack["Frontend"]["CSS Framework"] = framework
    
    # Check for web fonts
    font_services = {
        'fonts.googleapis.com': 'Google Fonts',
        'use.typekit.net': 'Adobe Fonts',
        'fast.fonts.net': 'Fonts.com',
        'use.fontawesome.com': 'Font Awesome'
    }
    
    for link in soup.find_all('link', rel="stylesheet"):
        href = link.get('href', '').lower()
        for service, name in font_services.items():
            if service in href:
                tech_stack["Fonts"][name] = True
    
    # Check for CMS
    cms_patterns = {
        'WordPress': r'wp-content|wp-includes',
        'Drupal': r'sites/all|drupal.js',
        'Joomla': r'com_content|com_users',
        'Magento': r'skin/frontend|js/mage',
        'Shopify': r'cdn.shopify.com',
        'Wix': r'wix-bolt|wix-viewer'
    }
    
    for cms, pattern in cms_patterns.items():
        if re.search(pattern, str(soup), re.I):
            tech_stack["CMS"][cms] = True

def analyze_javascript(content, tech_stack):
    js_libraries = {
        'react': 'React',
        'vue': 'Vue.js',
        'angular': 'Angular',
        'jquery': 'jQuery',
        'lodash': 'Lodash',
        'moment': 'Moment.js',
        'underscore': 'Underscore.js',
        'backbone': 'Backbone.js',
        'ember': 'Ember.js',
        'knockout': 'Knockout.js',
        'mootools': 'MooTools',
        'prototype': 'Prototype',
        'dojo': 'Dojo'
    }
    
    for keyword, library in js_libraries.items():
        if re.search(rf'\b{keyword}\b', content, re.I):
            tech_stack["Libraries"][library] = True
    
    # Check for analytics
    analytics_services = {
        'google-analytics.com|googletagmanager.com': 'Google Analytics',
        'analytics.google.com': 'Google Analytics 4',
        'script.hotjar.com': 'Hotjar',
        'cdn.segment.com': 'Segment',
        'js.hs-scripts.com': 'HubSpot',
        'script.crazyegg.com': 'Crazy Egg',
        'static.mixpanel.com': 'Mixpanel',
        'cdn.heapanalytics.com': 'Heap',
        'cdn.optimizely.com': 'Optimizely'
    }
    
    for pattern, service in analytics_services.items():
        if re.search(pattern, content, re.I):
            tech_stack["Analytics"][service] = True
    
    # Check for advertising networks
    ad_networks = {
        'googlesyndication.com': 'Google AdSense',
        'pagead2.googlesyndication.com': 'Google AdSense',
        'amazon-adsystem.com': 'Amazon Advertising',
        'ads.pubmatic.com': 'PubMatic',
        'cdn.taboola.com': 'Taboola',
        'cdn.outbrain.com': 'Outbrain'
    }
    
    for domain, network in ad_networks.items():
        if domain in content:
            tech_stack["Advertising"][network] = True

def analyze_meta_tags(soup, tech_stack):
    meta_generator = soup.find('meta', attrs={'name': 'generator'})
    if meta_generator:
        content = meta_generator.get('content', '').lower()
        cms_patterns = {
            'wordpress': 'WordPress',
            'drupal': 'Drupal',
            'joomla': 'Joomla',
            'shopify': 'Shopify',
            'wix': 'Wix',
            'squarespace': 'Squarespace',
            'ghost': 'Ghost'
        }
        for pattern, cms in cms_patterns.items():
            if pattern in content:
                tech_stack["CMS"][cms] = True
    
    # Check for e-commerce platforms
    ecommerce_patterns = {
        'shopify': 'Shopify',
        'magento': 'Magento',
        'woocommerce': 'WooCommerce',
        'bigcommerce': 'BigCommerce',
        'prestashop': 'PrestaShop',
        'opencart': 'OpenCart'
    }
    
    for meta in soup.find_all('meta'):
        content = meta.get('content', '').lower()
        for pattern, platform in ecommerce_patterns.items():
            if pattern in content:
                tech_stack["E-commerce"][platform] = True

async def analyze_ssl_cert(url, tech_stack):
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        conn = await asyncio.open_connection(hostname, 443, ssl=context)
        transport = conn[0].get_extra_info('ssl_object')
        cert = transport.getpeercert()
        
        if cert:
            tech_stack["SSL"]["Issuer"] = dict(x[0] for x in cert['issuer'])
            tech_stack["SSL"]["Version"] = cert['version']
            tech_stack["SSL"]["Serial Number"] = cert['serialNumber']
            tech_stack["SSL"]["Not Before"] = cert['notBefore']
            tech_stack["SSL"]["Not After"] = cert['notAfter']
            tech_stack["SSL"]["Subject Alternative Names"] = cert.get('subjectAltName', [])
    except Exception as e:
        logger.error(f"Error analyzing SSL certificate: {e}")

async def analyze_dns(url, tech_stack):
    try:
        domain = tldextract.extract(url).registered_domain
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5  # Set a timeout of 5 seconds

        dns_providers = {
            'cloudflare': ('Cloudflare', 'https://www.cloudflare.com/favicon.ico'),
            'awsdns': ('Amazon Web Services', 'https://aws.amazon.com/favicon.ico'),
            'azure': ('Microsoft Azure', 'https://azure.microsoft.com/favicon.ico'),
            'googledomains': ('Google Domains', 'https://domains.google/favicon.ico'),
            'godaddy': ('GoDaddy', 'https://www.godaddy.com/favicon.ico'),
            'hostgator': ('HostGator', 'https://www.hostgator.com/favicon.ico'),
            'bluehost': ('Bluehost', 'https://www.bluehost.com/favicon.ico'),
            'namecheap': ('Namecheap', 'https://www.namecheap.com/favicon.ico'),
            'dreamhost': ('DreamHost', 'https://www.dreamhost.com/favicon.ico'),
            'digitalocean': ('DigitalOcean', 'https://www.digitalocean.com/favicon.ico')
        }

        mail_providers = {
            'google': ('Google Workspace', 'https://workspace.google.com/favicon.ico'),
            'outlook': ('Microsoft 365', 'https://www.microsoft.com/favicon.ico'),
            'zoho': ('Zoho Mail', 'https://www.zoho.com/favicon.ico'),
            'protonmail': ('ProtonMail', 'https://protonmail.com/favicon.ico'),
            'mailgun': ('Mailgun', 'https://www.mailgun.com/favicon.ico'),
            'sendgrid': ('SendGrid', 'https://sendgrid.com/favicon.ico'),
            'amazonses': ('Amazon SES', 'https://aws.amazon.com/favicon.ico')
        }

        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, domain, record_type)
                if record_type == 'NS':
                    nameservers = [str(r) for r in answers]
                    provider = 'Unknown'
                    logo_url = ''
                    for ns in nameservers:
                        for key, (value, logo) in dns_providers.items():
                            if key in ns.lower():
                                provider = value
                                logo_url = logo
                                break
                        if provider != 'Unknown':
                            break
                    tech_stack["DNS"]["Provider"] = f"{provider} (logo: {logo_url})"
                    tech_stack["DNS"]["Nameservers"] = nameservers
                elif record_type == 'MX':
                    mx_records = [f"{r.exchange} (priority: {r.preference})" for r in answers]
                    provider = 'Unknown'
                    logo_url = ''
                    for mx in mx_records:
                        for key, (value, logo) in mail_providers.items():
                            if key in mx.lower():
                                provider = value
                                logo_url = logo
                                break
                        if provider != 'Unknown':
                            break
                    tech_stack["Email"]["Provider"] = f"{provider} (logo: {logo_url})"
                    tech_stack["Email"]["MX Records"] = mx_records
                else:
                    tech_stack["DNS"][record_type] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                logger.info(f"No {record_type} record found for {domain}")
            except dns.exception.Timeout:
                logger.error(f"Timeout resolving {record_type} record for {domain}")
            except Exception as e:
                logger.error(f"Error resolving {record_type} record for {domain}: {e}")
    except Exception as e:
        logger.error(f"Error analyzing DNS records: {e}")
    try:
        domain = tldextract.extract(url).registered_domain
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5  # Set a timeout of 5 seconds

        dns_providers = {
            'cloudflare': 'Cloudflare',
            'awsdns': 'Amazon Web Services',
            'azure': 'Microsoft Azure',
            'googledomains': 'Google Domains',
            'godaddy': 'GoDaddy',
            'hostgator': 'HostGator',
            'bluehost': 'Bluehost',
            'namecheap': 'Namecheap',
            'dreamhost': 'DreamHost',
            'digitalocean': 'DigitalOcean'
        }

        for record_type in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
            try:
                answers = await asyncio.get_event_loop().run_in_executor(None, resolver.resolve, domain, record_type)
                if record_type == 'NS':
                    nameservers = [str(r) for r in answers]
                    provider = 'Unknown'
                    for ns in nameservers:
                        for key, value in dns_providers.items():
                            if key in ns.lower():
                                provider = value
                                break
                        if provider != 'Unknown':
                            break
                    tech_stack["DNS"]["Provider"] = provider
                    tech_stack["DNS"]["Nameservers"] = nameservers
                elif record_type == 'MX':
                    tech_stack["DNS"][record_type] = [f"{r.exchange} (priority: {r.preference})" for r in answers]
                else:
                    tech_stack["DNS"][record_type] = [str(r) for r in answers]
            except dns.resolver.NoAnswer:
                logger.info(f"No {record_type} record found for {domain}")
            except dns.exception.Timeout:
                logger.error(f"Timeout resolving {record_type} record for {domain}")
            except Exception as e:
                logger.error(f"Error resolving {record_type} record for {domain}: {e}")
    except Exception as e:
        logger.error(f"Error analyzing DNS records: {e}")

async def analyze_whois(url, tech_stack):
    try:
        domain = tldextract.extract(url).registered_domain
        whois_info = await asyncio.get_event_loop().run_in_executor(None, whois.whois, domain)
        tech_stack["Domain"]["Registrar"] = whois_info.registrar
        tech_stack["Domain"]["Creation Date"] = str(whois_info.creation_date)
        tech_stack["Domain"]["Expiration Date"] = str(whois_info.expiration_date)
        tech_stack["Domain"]["Name Servers"] = whois_info.name_servers
    except Exception as e:
        logger.error(f"Error analyzing WHOIS information: {e}")

def analyze_performance(headers, start_time, end_time, tech_stack):
    tech_stack["Performance"]["Status Code"] = headers.get('Status', 'Unknown')
    tech_stack["Performance"]["Content Type"] = headers.get('Content-Type', 'Unknown')
    tech_stack["Performance"]["Content Length"] = headers.get('Content-Length', 'Unknown')
    tech_stack["Performance"]["Response Time"] = f"{end_time - start_time:.2f} seconds"

def analyze_third_party_services(content, tech_stack):
    services = {
        'api.stripe.com': 'Stripe',
        'js.braintreegateway.com': 'Braintree',
        'www.paypalobjects.com': 'PayPal',
        'cdn.auth0.com': 'Auth0',
        'apis.google.com': 'Google APIs',
        'platform.twitter.com': 'Twitter',
        'connect.facebook.net': 'Facebook',
        'assets.zendesk.com': 'Zendesk',
        'cdn.jsdelivr.net': 'jsDelivr CDN',
        'cdnjs.cloudflare.com': 'Cloudflare CDN',
        'unpkg.com': 'UNPKG CDN',
        'use.fontawesome.com': 'Font Awesome',
        'maps.googleapis.com': 'Google Maps',
        'recaptcha.net': 'Google reCAPTCHA',
        'www.googletagmanager.com': 'Google Tag Manager',
        'connect.facebook.net': 'Facebook SDK',
        'platform.twitter.com': 'Twitter Platform',
        'www.linkedin.com/embed': 'LinkedIn Embed',
        'www.youtube.com/iframe_api': 'YouTube iFrame API',
        'player.vimeo.com': 'Vimeo Player',
        'cdn.ampproject.org': 'AMP',
        'js.intercomcdn.com': 'Intercom',
        'widget.trustpilot.com': 'Trustpilot',
        'seal.digicert.com': 'DigiCert Seal',
        'verify.authorize.net': 'Authorize.net Seal',
        'seal.godaddy.com': 'GoDaddy Seal',
        'www.sitelock.com': 'SiteLock',
        'cdn.onesignal.com': 'OneSignal',
        'cdn.ravenjs.com': 'Sentry',
        'browser.sentry-cdn.com': 'Sentry',
        'securepubads.g.doubleclick.net': 'Google Ad Manager',
        'static.ads-twitter.com': 'Twitter Ads',
        'connect.facebook.net/signals': 'Facebook Pixel',
        'sc-static.net': 'Snapchat Pixel',
        'static.criteo.net': 'Criteo',
        'cdn.mouseflow.com': 'Mouseflow',
        'static.cloudflareinsights.com': 'Cloudflare Web Analytics',
        'cdn.lr-ingest.io': 'LogRocket',
        'js.driftt.com': 'Drift',
        'js.hs-scripts.com': 'HubSpot',
        'static.zdassets.com': 'Zendesk',
        'cdn.livechatinc.com': 'LiveChat',
        'code.tidio.co': 'Tidio',
        'assets.calendly.com': 'Calendly',
        'js.usemessages.com': 'Userlike',
        'static.olark.com': 'Olark'
    }
    
    for url, service in services.items():
        if url in content:
            category = 'Other'
            if 'cdn' in service.lower():
                category = 'CDN'
            elif 'analytics' in service.lower():
                category = 'Analytics'
            elif 'ads' in service.lower() or 'pixel' in service.lower():
                category = 'Advertising'
            elif any(word in service.lower() for word in ['payment', 'stripe', 'paypal', 'braintree']):
                category = 'Payment'
            elif any(word in service.lower() for word in ['chat', 'support', 'zendesk', 'intercom']):
                category = 'Customer Support'
            
            tech_stack[category][service] = True

def detect_marketing_technologies(html_content, tech_stack):
    marketing_tech = {
        'Analytics': {
            'Google Analytics': ('google-analytics.com', 'https://www.google.com/analytics/favicon.ico'),
            'Google Analytics 4': ('gtag', 'https://www.google.com/analytics/favicon.ico'),
            'Mixpanel': ('cdn.mxpnl.com', 'https://mixpanel.com/favicon.ico'),
            'Segment': ('cdn.segment.com', 'https://segment.com/favicon.ico'),
            'Hotjar': ('static.hotjar.com', 'https://www.hotjar.com/favicon.ico'),
            'Heap': ('cdn.heapanalytics.com', 'https://heapanalytics.com/favicon.ico'),
            'Amplitude': ('cdn.amplitude.com', 'https://amplitude.com/favicon.ico'),
            'Matomo': ('matomo.js', 'https://matomo.org/favicon.ico'),
            'Plausible': ('plausible.js', 'https://plausible.io/favicon.ico'),
        },
        'Tag Management': {
            'Google Tag Manager': ('googletagmanager.com', 'https://www.google.com/tagmanager/favicon.ico'),
            'Tealium': ('tags.tiqcdn.com', 'https://tealium.com/favicon.ico'),
            'Adobe Tag Manager': ('assets.adobedtm.com', 'https://www.adobe.com/favicon.ico'),
            'Ensighten': ('nexus.ensighten.com', 'https://www.ensighten.com/favicon.ico'),
        },
        'Advertising': {
            'Google Ads': ('googleads.g.doubleclick.net', 'https://www.google.com/ads/favicon.ico'),
            'Facebook Ads': ('connect.facebook.net/signals', 'https://www.facebook.com/favicon.ico'),
            'Twitter Ads': ('static.ads-twitter.com', 'https://ads.twitter.com/favicon.ico'),
            'LinkedIn Ads': ('snap.licdn.com', 'https://www.linkedin.com/favicon.ico'),
            'AdRoll': ('d.adroll.com', 'https://www.adroll.com/favicon.ico'),
            'Criteo': ('static.criteo.net', 'https://www.criteo.com/favicon.ico'),
        },
        'CRM & Marketing Automation': {
            'HubSpot': ('js.hs-scripts.com', 'https://www.hubspot.com/favicon.ico'),
            'Marketo': ('munchkin.marketo.net', 'https://www.marketo.com/favicon.ico'),
            'Salesforce Pardot': ('pi.pardot.com', 'https://www.pardot.com/favicon.ico'),
            'ActiveCampaign': ('trackcmp.net', 'https://www.activecampaign.com/favicon.ico'),
            'Mailchimp': ('chimpstatic.com', 'https://mailchimp.com/favicon.ico'),
            'Constant Contact': ('r20.rs6.net', 'https://www.constantcontact.com/favicon.ico'),
            'Intercom': ('widget.intercom.io', 'https://www.intercom.com/favicon.ico'),
            'Drift': ('js.driftt.com', 'https://www.drift.com/favicon.ico'),
        },
        'A/B Testing & Personalization': {
            'Optimizely': ('cdn.optimizely.com', 'https://www.optimizely.com/favicon.ico'),
            'VWO': ('dev.visualwebsiteoptimizer.com', 'https://vwo.com/favicon.ico'),
            'Adobe Target': ('tt.omtrdc.net', 'https://www.adobe.com/favicon.ico'),
            'Google Optimize': ('optimize.google.com', 'https://www.google.com/favicon.ico'),
            'Dynamic Yield': ('cdn.dynamicyield.com', 'https://www.dynamicyield.com/favicon.ico'),
        },
        'Chat & Support': {
            'Zendesk': ('static.zdassets.com', 'https://www.zendesk.com/favicon.ico'),
            'LiveChat': ('cdn.livechatinc.com', 'https://www.livechat.com/favicon.ico'),
            'Olark': ('static.olark.com', 'https://www.olark.com/favicon.ico'),
            'Tawk.to': ('embed.tawk.to', 'https://www.tawk.to/favicon.ico'),
            'Crisp': ('client.crisp.chat', 'https://crisp.chat/favicon.ico'),
        },
        'Retargeting': {
            'AdRoll': ('d.adroll.com', 'https://www.adroll.com/favicon.ico'),
            'Perfect Audience': ('tag.perfectaudience.com', 'https://www.perfectaudience.com/favicon.ico'),
            'Criteo': ('static.criteo.net', 'https://www.criteo.com/favicon.ico'),
        },
        'Email Marketing': {
            'Mailchimp': ('chimpstatic.com', 'https://mailchimp.com/favicon.ico'),
            'Constant Contact': ('r20.rs6.net', 'https://www.constantcontact.com/favicon.ico'),
            'Campaign Monitor': ('createsend.com', 'https://www.campaignmonitor.com/favicon.ico'),
            'Klaviyo': ('static.klaviyo.com', 'https://www.klaviyo.com/favicon.ico'),
            'Drip': ('tag.getdrip.com', 'https://www.drip.com/favicon.ico'),
            'ConvertKit': ('app.convertkit.com', 'https://convertkit.com/favicon.ico'),
        },
        'Social Media': {
            'Facebook Pixel': ('connect.facebook.net/en_US/fbevents.js', 'https://www.facebook.com/favicon.ico'),
            'Twitter Pixel': ('static.ads-twitter.com', 'https://ads.twitter.com/favicon.ico'),
            'LinkedIn Insight Tag': ('snap.licdn.com', 'https://www.linkedin.com/favicon.ico'),
            'Pinterest Tag': ('s.pinimg.com/ct/', 'https://www.pinterest.com/favicon.ico'),
        },
        'Other': {
            'ClickFunnels': ('app.clickfunnels.com', 'https://www.clickfunnels.com/favicon.ico'),
            'Leadpages': ('static.leadpages.net', 'https://www.leadpages.net/favicon.ico'),
            'Sumo': ('load.sumo.com', 'https://sumo.com/favicon.ico'),
            'Lucky Orange': ('cdn.luckyorange.com', 'https://www.luckyorange.com/favicon.ico'),
            'Crazy Egg': ('script.crazyegg.com', 'https://www.crazyegg.com/favicon.ico'),
        }
    }

    for category, technologies in marketing_tech.items():
        for tech, (pattern, logo_url) in technologies.items():
            if pattern in html_content:
                if category not in tech_stack["Marketing"]:
                    tech_stack["Marketing"][category] = {}
                tech_stack["Marketing"][category][tech] = f"Detected (logo: {logo_url})"

    # Additional checks for specific technologies
    if 'ua-' in html_content and 'google-analytics.com' in html_content:
        tech_stack["Marketing"]["Analytics"]["Google Analytics (Universal Analytics)"] = f"Detected (logo: https://www.google.com/analytics/favicon.ico)"
    
    if 'gtag' in html_content and 'google-analytics.com' in html_content:
        tech_stack["Marketing"]["Analytics"]["Google Analytics 4"] = f"Detected (logo: https://www.google.com/analytics/favicon.ico)"
    
    if 'function(h,o,t,j,a,r)' in html_content:
        tech_stack["Marketing"]["Analytics"]["Hotjar"] = f"Detected (logo: https://www.hotjar.com/favicon.ico)"

    # Check for Google Ads Remarketing
    if 'google_conversion_id' in html_content or 'google_remarketing_only' in html_content:
        tech_stack["Marketing"]["Advertising"]["Google Ads Remarketing"] = f"Detected (logo: https://www.google.com/ads/favicon.ico)"

    # Check for Facebook Pixel
    if 'fbq(' in html_content:
        tech_stack["Marketing"]["Social Media"]["Facebook Pixel"] = f"Detected (logo: https://www.facebook.com/favicon.ico)"

    # Check for LinkedIn Insight Tag
    if '_linkedin_partner_id' in html_content:
        tech_stack["Marketing"]["Social Media"]["LinkedIn Insight Tag"] = f"Detected (logo: https://www.linkedin.com/favicon.ico)"

    return tech_stack
    marketing_tech = {
        'Google Tag Manager': 'googletagmanager.com',
        'Google Analytics': 'google-analytics.com',
        'Facebook Pixel': 'connect.facebook.net/en_US/fbevents.js',
        'HubSpot': 'js.hs-scripts.com',
        'Marketo': 'munchkin.marketo.net',
        'Mailchimp': 'chimpstatic.com',
        'Intercom': 'widget.intercom.io',
        'Hotjar': 'static.hotjar.com',
        'Optimizely': 'cdn.optimizely.com',
        'Salesforce Pardot': 'pi.pardot.com',
        'Adobe Analytics': 'sc.omtrdc.net',
        'Segment': 'cdn.segment.com',
        'Mixpanel': 'cdn.mxpnl.com',
        'Crazy Egg': 'script.crazyegg.com',
        'Drift': 'js.driftt.com',
        'Zendesk': 'static.zdassets.com',
        'Tawk.to': 'embed.tawk.to',
        'LiveChat': 'cdn.livechatinc.com',
        'Olark': 'static.olark.com',
        'ClickFunnels': 'app.clickfunnels.com',
        'VWO': 'dev.visualwebsiteoptimizer.com',
        'Leadfeeder': 'lftracker.leadfeeder.com',
        'Lucky Orange': 'cdn.luckyorange.com',
        'Sumo': 'load.sumo.com',
        'Klaviyo': 'static.klaviyo.com',
        'Mailerlite': 'static.mailerlite.com',
        'ActiveCampaign': 'trackcmp.net',
        'Drip': 'tag.getdrip.com',
        'Convertkit': 'app.convertkit.com',
        'Autopilot': 'api.autopilothq.com',
        'RightMessage': 'app.rightmessage.com'
    }

    for tech, pattern in marketing_tech.items():
        if pattern in html_content:
            tech_stack["Marketing"][tech] = True

def find_social_media_handles(soup, tech_stack):
    social_patterns = {
        'Facebook': (r'facebook\.com/([A-Za-z0-9.]+)', 'https://www.facebook.com/favicon.ico'),
        'Twitter': (r'twitter\.com/([A-Za-z0-9_]+)', 'https://twitter.com/favicon.ico'),
        'Instagram': (r'instagram\.com/([A-Za-z0-9_.]+)', 'https://www.instagram.com/favicon.ico'),
        'LinkedIn': (r'linkedin\.com/(?:company|in)/([A-Za-z0-9-]+)', 'https://www.linkedin.com/favicon.ico'),
        'YouTube': (r'youtube\.com/(?:user|channel)/([A-Za-z0-9_-]+)', 'https://www.youtube.com/favicon.ico'),
        'Pinterest': (r'pinterest\.com/([A-Za-z0-9_]+)', 'https://www.pinterest.com/favicon.ico'),
        'TikTok': (r'tiktok\.com/@([A-Za-z0-9_.]+)', 'https://www.tiktok.com/favicon.ico'),
        'Medium': (r'medium\.com/@([A-Za-z0-9_.]+)', 'https://medium.com/favicon.ico'),
        'GitHub': (r'github\.com/([A-Za-z0-9-]+)', 'https://github.com/favicon.ico'),
        'Snapchat': (r'snapchat\.com/add/([A-Za-z0-9_.]+)', 'https://www.snapchat.com/favicon.ico'),
        'Tumblr': (r'([A-Za-z0-9-]+)\.tumblr\.com', 'https://www.tumblr.com/favicon.ico'),
        'Reddit': (r'reddit\.com/user/([A-Za-z0-9_-]+)', 'https://www.reddit.com/favicon.ico'),
        'Vimeo': (r'vimeo\.com/([A-Za-z0-9]+)', 'https://vimeo.com/favicon.ico'),
        'Dribbble': (r'dribbble\.com/([A-Za-z0-9_-]+)', 'https://dribbble.com/favicon.ico'),
        'Behance': (r'behance\.net/([A-Za-z0-9_-]+)', 'https://www.behance.net/favicon.ico')
    }

    for platform, (pattern, logo_url) in social_patterns.items():
        links = soup.find_all('a', href=re.compile(pattern, re.I))
        for link in links:
            handle = re.search(pattern, link['href'], re.I)
            if handle:
                tech_stack["Social Media"][platform] = f"@{handle.group(1)} (logo: {logo_url})"
                break  # Stop after finding the first handle for each platform
    social_patterns = {
        'Facebook': r'facebook\.com/([A-Za-z0-9.]+)',
        'Twitter': r'twitter\.com/([A-Za-z0-9_]+)',
        'Instagram': r'instagram\.com/([A-Za-z0-9_.]+)',
        'LinkedIn': r'linkedin\.com/(?:company|in)/([A-Za-z0-9-]+)',
        'YouTube': r'youtube\.com/(?:user|channel)/([A-Za-z0-9_-]+)',
        'Pinterest': r'pinterest\.com/([A-Za-z0-9_]+)',
        'TikTok': r'tiktok\.com/@([A-Za-z0-9_.]+)',
        'Medium': r'medium\.com/@([A-Za-z0-9_.]+)',
        'GitHub': r'github\.com/([A-Za-z0-9-]+)',
        'Snapchat': r'snapchat\.com/add/([A-Za-z0-9_.]+)',
        'Tumblr': r'([A-Za-z0-9-]+)\.tumblr\.com',
        'Reddit': r'reddit\.com/user/([A-Za-z0-9_-]+)',
        'Vimeo': r'vimeo\.com/([A-Za-z0-9]+)',
        'Dribbble': r'dribbble\.com/([A-Za-z0-9_-]+)',
        'Behance': r'behance\.net/([A-Za-z0-9_-]+)'
    }

    for platform, pattern in social_patterns.items():
        links = soup.find_all('a', href=re.compile(pattern, re.I))
        for link in links:
            handle = re.search(pattern, link['href'], re.I)
            if handle:
                tech_stack["Social Media"][platform] = handle.group(1)
                break  # Stop after finding the first handle for each platform

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
            elif isinstance(value, list):
                new_id = hashlib.md5(f"{parent_id}_{key}".encode()).hexdigest()
                tree.create_node(f"{key}: {', '.join(value)}", new_id, parent=parent_id)
            else:
                new_id = hashlib.md5(f"{parent_id}_{key}_{value}".encode()).hexdigest()
                if isinstance(value, str) and value.startswith("http"):
                    tree.create_node(f"{key}: <img src='{value}' alt='{key}' style='width:16px;height:16px;'> {value.split('(logo: ')[0]}", new_id, parent=parent_id)
                else:
                    tree.create_node(f"{key}: {value}", new_id, parent=parent_id)
    
    add_nodes("Website", tech_stack, "root")
    
    return tree

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

def generate_html_report(tech_stack, url):
    tree = create_tree_diagram(tech_stack, url)
    
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
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: #ffffff;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0 0 10px rgba(0,0,0,0.1);
            }}
            h1 {{
                color: #333;
                border-bottom: 2px solid #333;
                padding-bottom: 10px;
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
            .tree img {{
                vertical-align: middle;
                margin-right: 5px;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Website Technology Stack: {url}</h1>
            <div class="tree">
                <ul>
                    {tree_to_html(tree, tree.get_node(tree.root))}
                </ul>
            </div>
        </div>
    </body>
    </html>
    """
    
    with open("tech_stack_report.html", "w", encoding="utf-8") as f:
        f.write(html_content)

async def main():
    url = input("Enter the website URL to analyze (e.g., google.com): ")
    tech_stack = await analyze_website(url)

    if tech_stack:
        print(json.dumps(tech_stack, indent=2))
        generate_html_report(tech_stack, url)
        print("Technology stack report saved as 'tech_stack_report.html'")
        
        # Open the HTML file in the default web browser
        webbrowser.open('file://' + os.path.realpath("tech_stack_report.html"))
    else:
        print("Failed to analyze the website.")

if __name__ == "__main__":
    asyncio.run(main())