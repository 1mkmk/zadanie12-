#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from collections import Counter
import socket
from urllib.parse import urlparse
from ..utils.helpers import check_dns_lookup_time, has_responsive_meta_tag

class PerformanceAnalyzer:
    """
    Analizator wydajności stron internetowych.
    Analizuje czasy ładowania, zasoby, optymalizację i inne aspekty wpływające na wydajność.
    """
    def __init__(self, soup, response, url, results):
        self.soup = soup
        self.response = response
        self.url = url
        self.results = results
        self.performance = self.results["performance"]
        
    def analyze(self):
        """Uruchamia wszystkie analizy wydajności"""
        self.check_loading_performance()
        self.analyze_resources()
        self.analyze_seo()
        self.analyze_mobile_optimization()
        self.analyze_technical_aspects()
    
    def check_loading_performance(self):
        """Analizuje metryki ładowania strony"""
        loading = self.performance["loading"]
        
        # Kod odpowiedzi HTTP
        loading["status_code"] = self.response.status_code
        
        # Rozmiar odpowiedzi
        response_size = len(self.response.content)
        loading["response_size_bytes"] = response_size
        loading["response_size_kb"] = round(response_size / 1024, 2)
        loading["response_size_mb"] = round(response_size / (1024 * 1024), 3)
        
        # Czas wyszukiwania DNS
        try:
            hostname = urlparse(self.url).netloc
            dns_time = check_dns_lookup_time(hostname)
            if dns_time:
                loading["dns_lookup_time"] = dns_time
                
                # Czas odpowiedzi (całkowity czas - czas DNS)
                if "total_load_time" in loading:
                    loading["response_time"] = round(loading["total_load_time"] - (dns_time / 1000), 2)
        except Exception:
            pass
    
    def analyze_resources(self):
        """Analizuje zasoby strony"""
        resources = self.performance["resources"]
        
        # Zliczanie zasobów
        images = self.soup.find_all('img')
        css_links = self.soup.find_all('link', rel='stylesheet')
        js_scripts = self.soup.find_all('script', src=True)
        external_links = self.soup.find_all('a', href=re.compile(r'^https?://'))
        
        resources["total_images"] = len(images)
        resources["total_css_files"] = len(css_links)
        resources["total_js_files"] = len(js_scripts)
        resources["external_links"] = len(external_links)
        
        # Analiza optymalizacji obrazów
        images_without_dimensions = []
        images_formats = Counter()
        images_responsive = 0
        webp_images = 0
        
        for img in images:
            src = img.get('src', '')
            if src:
                # Sprawdzanie formatu obrazu
                if '.' in src:
                    ext = src.split('.')[-1].lower().split('?')[0]
                    images_formats[ext] += 1
                    if ext == 'webp':
                        webp_images += 1
                
                # Sprawdzanie, czy wymiary są określone
                if not (img.get('width') or img.get('height')):
                    images_without_dimensions.append(src)
                
                # Sprawdzanie, czy obraz jest responsywny
                if img.get('srcset') or img.has_attr('sizes'):
                    images_responsive += 1
        
        resources["images_without_dimensions"] = len(images_without_dimensions)
        resources["images_without_dimensions_percentage"] = round((len(images_without_dimensions) / max(len(images), 1)) * 100, 1)
        resources["image_formats"] = dict(images_formats)
        resources["responsive_images"] = images_responsive
        resources["responsive_images_percentage"] = round((images_responsive / max(len(images), 1)) * 100, 1)
        resources["webp_images"] = webp_images
        resources["webp_percentage"] = round((webp_images / max(len(images), 1)) * 100, 1)
        
        # Analiza wewnętrznych vs zewnętrznych zasobów
        css_external = 0
        js_external = 0
        
        for css in css_links:
            href = css.get('href', '')
            if href and not href.startswith('/') and ('://' in href):
                css_external += 1
        
        for js in js_scripts:
            src = js.get('src', '')
            if src and not src.startswith('/') and ('://' in src):
                js_external += 1
        
        resources["external_css"] = css_external
        resources["external_js"] = js_external
        resources["internal_css"] = len(css_links) - css_external
        resources["internal_js"] = len(js_scripts) - js_external
        resources["inline_styles"] = len(self.soup.find_all(style=True))
        resources["inline_scripts"] = len(self.soup.find_all('script', src=False))
    
    def analyze_seo(self):
        """Analizuje elementy SEO"""
        seo = self.performance["seo"]
        
        # Podstawowe meta tagi
        title = self.soup.find('title')
        meta_description = self.soup.find('meta', attrs={'name': 'description'})
        meta_keywords = self.soup.find('meta', attrs={'name': 'keywords'})
        meta_viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        canonical = self.soup.find('link', attrs={'rel': 'canonical'})
        robots = self.soup.find('meta', attrs={'name': 'robots'})
        
        seo["title"] = title.get_text().strip() if title else "Missing"
        seo["title_length"] = len(title.get_text().strip()) if title else 0
        seo["meta_description"] = meta_description.get('content', '') if meta_description else "Missing"
        seo["meta_description_length"] = len(meta_description.get('content', '')) if meta_description else 0
        seo["meta_keywords"] = meta_keywords.get('content', '') if meta_keywords else "Missing"
        seo["viewport_meta"] = meta_viewport.get('content', '') if meta_viewport else "Missing"
        seo["canonical_url"] = canonical.get('href', '') if canonical else "Missing"
        seo["robots"] = robots.get('content', '') if robots else "Missing"
        
        # Meta tagi Open Graph
        og_title = self.soup.find('meta', attrs={'property': 'og:title'})
        og_description = self.soup.find('meta', attrs={'property': 'og:description'})
        og_image = self.soup.find('meta', attrs={'property': 'og:image'})
        og_url = self.soup.find('meta', attrs={'property': 'og:url'})
        og_type = self.soup.find('meta', attrs={'property': 'og:type'})
        
        seo["opengraph"] = {
            "title": og_title.get('content', '') if og_title else "Missing",
            "description": og_description.get('content', '') if og_description else "Missing",
            "image": og_image.get('content', '') if og_image else "Missing",
            "url": og_url.get('content', '') if og_url else "Missing",
            "type": og_type.get('content', '') if og_type else "Missing"
        }
        
        # Meta tagi Twitter Card
        twitter_card = self.soup.find('meta', attrs={'name': 'twitter:card'})
        twitter_site = self.soup.find('meta', attrs={'name': 'twitter:site'})
        twitter_title = self.soup.find('meta', attrs={'name': 'twitter:title'})
        twitter_description = self.soup.find('meta', attrs={'name': 'twitter:description'})
        twitter_image = self.soup.find('meta', attrs={'name': 'twitter:image'})
        
        seo["twitter_card"] = {
            "card": twitter_card.get('content', '') if twitter_card else "Missing",
            "site": twitter_site.get('content', '') if twitter_site else "Missing",
            "title": twitter_title.get('content', '') if twitter_title else "Missing",
            "description": twitter_description.get('content', '') if twitter_description else "Missing",
            "image": twitter_image.get('content', '') if twitter_image else "Missing"
        }
        
        # Analiza skomplikowania i czytelności URL
        parsed_url = urlparse(self.url)
        path = parsed_url.path
        
        seo["url_analysis"] = {
            "length": len(self.url),
            "path_segments": len([s for s in path.split('/') if s]),
            "query_params": len(parsed_url.query.split('&')) if parsed_url.query else 0,
            "has_hash": bool(parsed_url.fragment),
            "uses_https": parsed_url.scheme == "https"
        }
        
        # Analiza nagłówków strony w kontekście SEO
        headings = []
        for i in range(1, 7):
            h_tags = self.soup.find_all(f'h{i}')
            for tag in h_tags:
                headings.append({
                    "level": i,
                    "text": tag.get_text().strip()[:100],
                    "length": len(tag.get_text().strip())
                })
        
        seo["headings_analysis"] = {
            "total": len(headings),
            "h1_count": len([h for h in headings if h["level"] == 1]),
            "samples": headings[:5]  # Pierwsze 5 nagłówków
        }
    
    def analyze_mobile_optimization(self):
        """Analizuje optymalizacje dla urządzeń mobilnych"""
        mobile = self.performance["mobile"]
        
        mobile["viewport_configured"] = has_responsive_meta_tag(self.soup)
        mobile["responsive_images"] = self.performance["resources"].get("responsive_images", 0)
        mobile["css_media_queries"] = self._count_media_queries()
        
        # Badanie używania flexboxa lub grida
        styles_content = ""
        for style in self.soup.find_all('style'):
            styles_content += style.get_text()
        
        mobile["uses_flexbox"] = "display: flex" in styles_content or "display:flex" in styles_content
        mobile["uses_grid"] = "display: grid" in styles_content or "display:grid" in styles_content
        
        # Analiza elementów input z typem dla mobile
        mobile_inputs = len(self.soup.find_all('input', attrs={
            'type': re.compile(r'tel|email|number|date|datetime-local|month|search|time|url|week')
        }))
        mobile["mobile_input_types"] = mobile_inputs
    
    def analyze_technical_aspects(self):
        """Analizuje techniczne aspekty strony"""
        tech = self.performance["technical"]
        
        # Typ dokumentu
        doctype = str(self.soup.contents[0]) if self.soup.contents and hasattr(self.soup.contents[0], 'strip') else "Unknown"
        tech["doctype"] = doctype.strip()
        
        # Liczba błędów HTML (uproszczona analiza)
        tech["html_validation_errors"] = self._check_html_validation()
        tech["total_dom_elements"] = len(self.soup.find_all())
        tech["inline_styles"] = len(self.soup.find_all(style=True))
        tech["inline_scripts"] = len(self.soup.find_all('script', src=False))
        
        # Analiza znaczników strukturalnych
        tech["html5_semantic_elements"] = len(self.soup.find_all(['header', 'nav', 'main', 'article', 'section', 'aside', 'footer']))
        
        # Analiza atrybutów lang i dir
        html_tag = self.soup.find('html')
        tech["lang_attribute"] = html_tag.get('lang', 'Missing') if html_tag else "Missing"
        tech["dir_attribute"] = html_tag.get('dir', 'Not specified') if html_tag else "Not specified"
        
        # Sprawdzanie, czy strona używa JQuery
        jquery_scripts = len(self.soup.find_all('script', src=re.compile(r'jquery', re.I)))
        tech["uses_jquery"] = jquery_scripts > 0 or "jQuery" in self.response.text or "$(" in self.response.text
    
    # Metody pomocnicze
    def _count_media_queries(self):
        """Zlicza zapytania o media w stylach strony"""
        count = 0
        for style in self.soup.find_all('style'):
            count += len(re.findall(r'@media', style.get_text()))
        
        for link in self.soup.find_all('link', rel='stylesheet'):
            media = link.get('media')
            if media and media != 'all':
                count += 1
        
        return count
    
    def _check_html_validation(self):
        """Prosta walidacja HTML"""
        errors = 0
        
        # Sprawdzenie podstawowych problemów
        if not self.soup.find('html'):
            errors += 1
        if not self.soup.find('head'):
            errors += 1
        if not self.soup.find('body'):
            errors += 1
        if not self.soup.find('title'):
            errors += 1
        
        # Sprawdzenie niezamkniętych tagów (uproszczone)
        html_content = str(self.soup)
        open_tags = re.findall(r'<(\w+)', html_content)
        close_tags = re.findall(r'</(\w+)>', html_content)
        
        for tag in set(open_tags):
            if tag.lower() not in ['img', 'br', 'hr', 'input', 'meta', 'link']:
                if open_tags.count(tag) != close_tags.count(tag):
                    errors += 1
        
        return errors