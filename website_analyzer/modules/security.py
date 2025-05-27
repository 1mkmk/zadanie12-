#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
import ssl
from datetime import datetime
from urllib.parse import urlparse

class SecurityAnalyzer:
    """
    Analizator bezpieczeństwa stron internetowych.
    Sprawdza nagłówki bezpieczeństwa, konfigurację SSL/TLS, podatności XSS i inne aspekty bezpieczeństwa.
    """
    def __init__(self, soup, response, url, results):
        self.soup = soup
        self.response = response
        self.url = url
        self.results = results
        self.security = {}
        self.results["security"] = self.security
        
    def analyze(self):
        """Uruchamia wszystkie analizy bezpieczeństwa"""
        self.check_security_headers()
        self.check_ssl_tls()
        self.check_content_security()
        self.check_mixed_content()
        self.check_form_security()
        self.calculate_security_score()
    
    def check_security_headers(self):
        """Analizuje nagłówki bezpieczeństwa HTTP"""
        headers = self.response.headers
        security_headers = {
            'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Missing'),
            'Content-Security-Policy': headers.get('Content-Security-Policy', 'Missing'),
            'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Missing'),
            'X-Frame-Options': headers.get('X-Frame-Options', 'Missing'),
            'X-XSS-Protection': headers.get('X-XSS-Protection', 'Missing'),
            'Referrer-Policy': headers.get('Referrer-Policy', 'Missing'),
            'Permissions-Policy': headers.get('Permissions-Policy', headers.get('Feature-Policy', 'Missing'))
        }
        
        # Liczenie brakujących i obecnych nagłówków
        missing_headers = sum(1 for value in security_headers.values() if value == 'Missing')
        present_headers = len(security_headers) - missing_headers
        
        self.security["headers"] = security_headers
        self.security["missing_security_headers"] = missing_headers
        self.security["present_security_headers"] = present_headers
        self.security["security_headers_percentage"] = round((present_headers / len(security_headers)) * 100, 1)
    
    def check_ssl_tls(self):
        """Analizuje konfigurację SSL/TLS i certyfikat"""
        parsed_url = urlparse(self.url)
        self.security["https_enabled"] = parsed_url.scheme == 'https'
        
        if not self.security["https_enabled"]:
            self.security["ssl_issues"] = ["HTTPS not enabled"]
            return
        
        try:
            hostname = parsed_url.netloc
            context = ssl.create_default_context()
            
            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Dane certyfikatu
                    cert_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter']
                    }
                    
                    # Czas ważności
                    cert_expiry = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_to_expiry = (cert_expiry - datetime.now()).days
                    
                    self.security["ssl_certificate"] = cert_info
                    self.security["ssl_days_to_expiry"] = days_to_expiry
                    self.security["ssl_expires_soon"] = days_to_expiry < 30
                    
                    # Wersja protokołu
                    self.security["ssl_protocol_version"] = ssock.version()
                    
                    # Lista problemów
                    ssl_issues = []
                    if days_to_expiry < 30:
                        ssl_issues.append(f"Certificate expires soon ({days_to_expiry} days)")
                    
                    self.security["ssl_issues"] = ssl_issues
                    
        except Exception as e:
            self.security["ssl_error"] = str(e)
            self.security["ssl_issues"] = ["Error analyzing SSL: " + str(e)]
    
    def check_content_security(self):
        """Analizuje zabezpieczenia treści"""
        # Wykrywanie inline JavaScript
        inline_scripts = self.soup.find_all('script', src=False)
        has_unsafe_inline = any(
            'javascript:' in str(script) 
            for script in inline_scripts 
            if script.string
        )
        
        # Wykrywanie potencjalnych luk XSS
        potential_xss_vectors = []
        
        # Sprawdzanie atrybutów, które mogą zawierać JavaScript
        risky_attrs = ['onclick', 'onload', 'onmouseover', 'onerror', 'onkeyup', 'onsubmit']
        for attr in risky_attrs:
            elements = self.soup.find_all(attrs={attr: True})
            for element in elements[:5]:  # Ograniczenie do 5 dla każdego atrybutu
                potential_xss_vectors.append({
                    'element': element.name,
                    'attribute': attr,
                    'value': element[attr][:100]  # Ograniczenie długości
                })
        
        # Sprawdzanie href z javascript:
        js_links = self.soup.find_all('a', href=re.compile(r'^javascript:', re.I))
        for link in js_links[:5]:
            potential_xss_vectors.append({
                'element': 'a',
                'attribute': 'href',
                'value': link['href'][:100]
            })
        
        self.security["inline_scripts"] = len(inline_scripts)
        self.security["has_unsafe_inline"] = has_unsafe_inline
        self.security["potential_xss_vectors"] = potential_xss_vectors
        self.security["xss_risk"] = len(potential_xss_vectors) > 0
    
    def check_mixed_content(self):
        """Sprawdza występowanie mieszanej zawartości (HTTP w HTTPS)"""
        if not self.security.get("https_enabled", False):
            self.security["mixed_content"] = {"status": "N/A - not using HTTPS"}
            return
        
        mixed_content = []
        
        # Sprawdzanie odwołań do zawartości HTTP
        for tag_name, attr_name in [
            ('img', 'src'), 
            ('script', 'src'), 
            ('link', 'href'),
            ('iframe', 'src'),
            ('object', 'data'),
            ('source', 'src'),
            ('audio', 'src'),
            ('video', 'src')
        ]:
            elements = self.soup.find_all(tag_name, attrs={attr_name: re.compile(r'^http://', re.I)})
            for element in elements[:3]:  # Limit do 3 przykładów dla każdego typu
                mixed_content.append({
                    'tag': tag_name,
                    'attribute': attr_name,
                    'url': element[attr_name][:100]
                })
        
        # Sprawdzanie stylów z url() odwołującymi się do HTTP
        style_tags = self.soup.find_all('style')
        for style in style_tags:
            if style.string:
                urls = re.findall(r'url\(\s*[\'"]?(http://[^\'")]+)[\'"]?\s*\)', style.string, re.I)
                for url in urls[:3]:
                    mixed_content.append({
                        'tag': 'style',
                        'attribute': 'url()',
                        'url': url[:100]
                    })
        
        self.security["mixed_content"] = {
            "status": "Issues found" if mixed_content else "No issues",
            "items": mixed_content,
            "count": len(mixed_content)
        }
    
    def check_form_security(self):
        """Analizuje bezpieczeństwo formularzy"""
        forms = self.soup.find_all('form')
        form_security = {
            "total": len(forms),
            "with_csrf_protection": 0,
            "with_https": 0,
            "with_autocomplete_off": 0,
            "insecure_forms": []
        }
        
        for form in forms:
            is_secure = True
            issues = []
            
            # Sprawdzanie, czy akcja formularza używa HTTPS
            action = form.get('action', '')
            if action and action.startswith('http:'):
                is_secure = False
                issues.append("Form submits to HTTP URL")
            elif not action and not self.security.get("https_enabled", False):
                is_secure = False
                issues.append("Form on non-HTTPS page without specific action")
            else:
                form_security["with_https"] += 1
            
            # Sprawdzanie ochrony CSRF (CSRF token)
            has_csrf = False
            # 1. Sprawdzanie ukrytego pola z typowymi nazwami tokenów CSRF
            csrf_fields = form.find_all('input', attrs={
                'type': 'hidden', 
                'name': re.compile(r'csrf|token|_token|xsrf', re.I)
            })
            if csrf_fields:
                has_csrf = True
                form_security["with_csrf_protection"] += 1
            else:
                is_secure = False
                issues.append("No CSRF protection detected")
            
            # Sprawdzanie autocomplete="off" dla całego formularza lub pól wrażliwych
            autocomplete_off = form.get('autocomplete') == 'off'
            password_fields = form.find_all('input', attrs={'type': 'password'})
            password_with_autocomplete_off = [
                field for field in password_fields 
                if field.get('autocomplete') == 'off'
            ]
            
            if autocomplete_off or (password_fields and len(password_with_autocomplete_off) == len(password_fields)):
                form_security["with_autocomplete_off"] += 1
            elif password_fields:
                is_secure = False
                issues.append("Password fields without autocomplete=off")
            
            if not is_secure:
                # Dodajemy opis formularza z problemami
                form_desc = {
                    'action': action,
                    'method': form.get('method', 'GET'),
                    'issues': issues
                }
                form_security["insecure_forms"].append(form_desc)
        
        self.security["forms"] = form_security
    
    def calculate_security_score(self):
        """Oblicza wynik bezpieczeństwa"""
        score = 100
        deductions = []
        
        # Redukcja za brakujące nagłówki bezpieczeństwa
        missing_headers = self.security.get("missing_security_headers", 0)
        if missing_headers > 0:
            header_deduction = min(missing_headers * 10, 40)  # Maksymalnie 40 punktów odjęcia za nagłówki
            score -= header_deduction
            deductions.append(f"Missing security headers: -{header_deduction}")
        
        # Redukcja za problemy z SSL
        if not self.security.get("https_enabled", False):
            score -= 50
            deductions.append("No HTTPS: -50")
        
        ssl_issues = self.security.get("ssl_issues", [])
        if ssl_issues:
            ssl_deduction = min(len(ssl_issues) * 10, 30)
            score -= ssl_deduction
            deductions.append(f"SSL issues: -{ssl_deduction}")
        
        # Redukcja za potencjalne wektory XSS
        xss_vectors = len(self.security.get("potential_xss_vectors", []))
        if xss_vectors > 0:
            xss_deduction = min(xss_vectors * 5, 25)
            score -= xss_deduction
            deductions.append(f"Potential XSS vectors: -{xss_deduction}")
        
        # Redukcja za mieszaną zawartość
        mixed_content_count = self.security.get("mixed_content", {}).get("count", 0)
        if mixed_content_count > 0:
            mixed_deduction = min(mixed_content_count * 3, 15)
            score -= mixed_deduction
            deductions.append(f"Mixed content: -{mixed_deduction}")
        
        # Redukcja za niezabezpieczone formularze
        insecure_forms = len(self.security.get("forms", {}).get("insecure_forms", []))
        if insecure_forms > 0:
            form_deduction = min(insecure_forms * 10, 30)
            score -= form_deduction
            deductions.append(f"Insecure forms: -{form_deduction}")
        
        # Zapisanie wyniku
        self.security["score"] = max(0, score)
        self.security["max_score"] = 100
        self.security["deductions"] = deductions
        
        # Ocena słowna
        if score >= 90:
            rating = "Excellent"
        elif score >= 75:
            rating = "Good"
        elif score >= 50:
            rating = "Fair"
        elif score >= 25:
            rating = "Poor"
        else:
            rating = "Very Poor"
        
        self.security["rating"] = rating