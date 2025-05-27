#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from urllib.parse import urlparse

class UsabilityAnalyzer:
    """
    Analizator użyteczności stron internetowych.
    Sprawdza elementy związane z nawigacją, czytelnością i ogólną użytecznością strony.
    """
    def __init__(self, soup, results):
        self.soup = soup
        self.results = results
        self.usability = {}
        self.results["usability"] = self.usability
        
    def analyze(self):
        """Uruchamia wszystkie analizy użyteczności"""
        self.check_navigation()
        self.check_content_usability()
        self.check_readability()
        self.check_mobile_usability()
    
    def check_navigation(self):
        """Analizuje elementy nawigacyjne strony"""
        nav = {}
        
        # Sprawdzanie elementów nawigacyjnych
        nav_elements = self.soup.find_all('nav')
        menu_elements = self.soup.find_all(class_=re.compile(r'menu|navigation', re.I))
        breadcrumbs = self.soup.find_all(class_=re.compile(r'breadcrumb', re.I))
        
        # Sprawdzanie funkcjonalności wyszukiwania
        search_inputs = self.soup.find_all('input', attrs={'type': 'search'})
        search_forms = self.soup.find_all('form', attrs={
            'action': re.compile(r'search', re.I)
        })
        search_elements = self.soup.find_all(class_=re.compile(r'search', re.I))
        
        nav["nav_elements"] = len(nav_elements)
        nav["menu_elements"] = len(menu_elements)
        nav["breadcrumbs"] = len(breadcrumbs)
        nav["search_functionality"] = (
            len(search_inputs) > 0 or
            len(search_forms) > 0 or
            len(search_elements) > 0
        )
        
        # Analiza linków
        links = self.soup.find_all('a', href=True)
        internal_links = []
        external_links = []
        social_links = []
        broken_links = []
        
        for link in links:
            href = link.get('href', '')
            
            # Pomijanie pustych linków i kotwic
            if not href or href.startswith('#'):
                continue
                
            # Klasyfikacja linków
            if href.startswith('http') or href.startswith('//'):
                parsed = urlparse(href)
                domain = parsed.netloc.lower()
                
                # Sprawdzenie linków społecznościowych
                if any(social in domain for social in ['facebook', 'twitter', 'instagram', 'linkedin', 'youtube']):
                    social_links.append(href)
                else:
                    external_links.append(href)
            else:
                internal_links.append(href)
            
            # Wykrywanie potencjalnie uszkodzonych linków
            if href == "#" or href == "javascript:void(0)" or href == "javascript:;":
                broken_links.append(href)
        
        nav["total_links"] = len(links)
        nav["internal_links"] = len(internal_links)
        nav["external_links"] = len(external_links)
        nav["social_media_links"] = len(social_links)
        nav["potentially_broken_links"] = len(broken_links)
        
        # Ocena przejrzystości nawigacji (prosta heurystyka)
        navigation_score = 0
        if nav["nav_elements"] > 0:
            navigation_score += 30
        if nav["breadcrumbs"] > 0:
            navigation_score += 20
        if nav["search_functionality"]:
            navigation_score += 30
        if nav["potentially_broken_links"] == 0:
            navigation_score += 20
        
        nav["navigation_clarity_score"] = navigation_score
        
        self.usability["navigation"] = nav
    
    def check_content_usability(self):
        """Analizuje użyteczność zawartości strony"""
        content = {}
        
        # Analiza długości tekstów
        paragraphs = self.soup.find_all('p')
        paragraph_lengths = [len(p.get_text().strip()) for p in paragraphs]
        avg_paragraph_length = sum(paragraph_lengths) / max(len(paragraph_lengths), 1)
        
        content["total_paragraphs"] = len(paragraphs)
        content["average_paragraph_length"] = round(avg_paragraph_length, 1)
        content["very_long_paragraphs"] = sum(1 for l in paragraph_lengths if l > 500)
        
        # Analiza elementów listy
        lists = self.soup.find_all(['ul', 'ol'])
        content["number_of_lists"] = len(lists)
        
        # Analiza obrazów dla ilustracji treści
        images = self.soup.find_all('img')
        content["total_images"] = len(images)
        content["images_with_alt"] = len([img for img in images if img.get('alt')])
        
        # Wykrywanie elementów wyróżniających treść
        content["blockquotes"] = len(self.soup.find_all('blockquote'))
        content["highlighted_content"] = len(self.soup.find_all(['strong', 'em', 'b', 'i', 'mark']))
        
        # Analiza tabel
        tables = self.soup.find_all('table')
        content["tables"] = len(tables)
        content["tables_with_caption"] = len([t for t in tables if t.find('caption')])
        
        # Analiza linków kontekstowych ("dowiedz się więcej", "czytaj dalej")
        contextual_links = []
        for link in self.soup.find_all('a', href=True):
            text = link.get_text().lower().strip()
            if any(pattern in text for pattern in ['read more', 'more info', 'dowiedz', 'więcej', 'czytaj']):
                contextual_links.append(link)
        
        content["contextual_links"] = len(contextual_links)
        
        # Wykrywanie elementów Call-to-Action
        cta_elements = []
        cta_links = self.soup.find_all('a', class_=re.compile(r'cta|button|btn', re.I))
        cta_buttons = self.soup.find_all('button')
        cta_elements.extend(cta_links)
        cta_elements.extend(cta_buttons)
        
        content["call_to_action_elements"] = len(cta_elements)
        
        # Ocena przejrzystości treści (prosta heurystyka)
        content_score = 0
        if content["total_paragraphs"] > 0:
            content_score += 10
        if content["average_paragraph_length"] < 300:
            content_score += 20
        if content["number_of_lists"] > 0:
            content_score += 20
        if content["images_with_alt"] / max(content["total_images"], 1) > 0.7:
            content_score += 20
        if content["highlighted_content"] > 0:
            content_score += 10
        if content["call_to_action_elements"] > 0:
            content_score += 20
        
        content["content_clarity_score"] = min(100, content_score)
        
        self.usability["content"] = content
    
    def check_readability(self):
        """Analizuje czytelność tekstu (prosta analiza)"""
        readability = {}
        
        # Pobieranie całego tekstu ze strony
        all_text = self.soup.get_text(" ", strip=True)
        words = all_text.split()
        sentences = self._count_sentences(all_text)
        
        # Podstawowe metryki
        readability["total_words"] = len(words)
        readability["total_sentences"] = sentences
        
        if sentences > 0:
            readability["words_per_sentence"] = round(len(words) / sentences, 1)
        else:
            readability["words_per_sentence"] = 0
        
        # Długość słów
        word_lengths = [len(word) for word in words if word]
        if word_lengths:
            readability["average_word_length"] = round(sum(word_lengths) / len(word_lengths), 1)
            readability["long_words"] = sum(1 for l in word_lengths if l > 10)
            readability["long_words_percentage"] = round((readability["long_words"] / max(len(words), 1)) * 100, 1)
        else:
            readability["average_word_length"] = 0
            readability["long_words"] = 0
            readability["long_words_percentage"] = 0
        
        # Prosta ocena czytelności
        readability_score = 0
        if 10 <= readability["words_per_sentence"] <= 25:
            readability_score += 50
        elif readability["words_per_sentence"] < 35:
            readability_score += 25
        
        if readability["average_word_length"] <= 6:
            readability_score += 50
        elif readability["average_word_length"] <= 8:
            readability_score += 25
        
        readability["readability_score"] = readability_score
        
        self.usability["readability"] = readability
    
    def check_mobile_usability(self):
        """Analizuje użyteczność strony na urządzeniach mobilnych"""
        mobile = {}
        
        # Sprawdzanie viewport meta tagu
        viewport = self.soup.find('meta', attrs={'name': 'viewport'})
        mobile["has_viewport"] = viewport is not None
        if viewport:
            mobile["viewport_content"] = viewport.get('content', '')
        
        # Sprawdzanie media queries w stylach inline
        media_queries = 0
        for style in self.soup.find_all('style'):
            if style.string:
                media_queries += len(re.findall(r'@media', style.string))
        
        mobile["media_queries"] = media_queries
        
        # Sprawdzanie elementów typu touch
        touch_elements = self.soup.find_all(['button', 'a'], class_=re.compile(r'btn|button', re.I))
        mobile["touch_elements"] = len(touch_elements)
        
        # Sprawdzanie elementów formularza przyjaznych dla urządzeń mobilnych
        mobile_friendly_inputs = self.soup.find_all('input', attrs={
            'type': re.compile(r'tel|email|number|date|datetime-local|month|search|time|url|week')
        })
        mobile["mobile_friendly_inputs"] = len(mobile_friendly_inputs)
        
        # Ocena użyteczności mobilnej
        mobile_score = 0
        if mobile["has_viewport"]:
            mobile_score += 40
        if mobile["media_queries"] > 0:
            mobile_score += 30
        if mobile["mobile_friendly_inputs"] > 0:
            mobile_score += 30
        
        mobile["mobile_usability_score"] = mobile_score
        
        self.usability["mobile"] = mobile
    
    # Metody pomocnicze
    def _count_sentences(self, text):
        """Liczy w przybliżeniu liczbę zdań w tekście"""
        # Prosta heurystyka: zlicz kropki, wykrzykniki i pytajniki kończące zdania
        sentence_end_pattern = r'[.!?](?:\s|$)'
        sentences = re.findall(sentence_end_pattern, text)
        return max(len(sentences), 1)  # Co najmniej jedno zdanie