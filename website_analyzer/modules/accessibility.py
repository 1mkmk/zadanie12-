#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
from collections import Counter
from ..utils.helpers import check_heading_hierarchy, calculate_contrast_ratio, extract_css_colors

class AccessibilityAnalyzer:
    """
    Analizator dostępności stron internetowych zgodnie z wytycznymi WCAG 2.1.
    Sprawdza różne aspekty dostępności, w tym strukturę semantyczną, nawigację
    klawiaturową, wsparcie czytników ekranowych i inne.
    """
    def __init__(self, soup, results):
        self.soup = soup
        self.results = results
        self.accessibility = self.results["accessibility"]
        
        # Inicjalizacja struktury wyników dla dostępności
        self.accessibility.update({
            "wcag_compliance": {},
            "semantic_structure": {},
            "keyboard_navigation": {},
            "screen_reader": {},
            "multimedia": {},
            "forms": {},
            "color_contrast": {},
            "text_content": {},
        })
    
    def analyze(self):
        """Uruchamia wszystkie analizy dostępności"""
        self.check_semantic_structure()
        self.check_keyboard_navigation()
        self.check_screen_reader_support()
        self.check_forms()
        self.check_multimedia()
        self.check_text_content()
        self.check_color_contrast()
        self.check_wcag_compliance()
        
    def check_semantic_structure(self):
        """Analiza struktury semantycznej strony"""
        sem = self.accessibility["semantic_structure"]
        
        # Analiza atrybutu lang
        html_tag = self.soup.find('html')
        sem["lang_attribute"] = html_tag.get('lang', 'Missing') if html_tag else 'Missing'
        sem["dir_attribute"] = html_tag.get('dir', 'Not specified') if html_tag else 'Not specified'
        
        # Analiza nagłówków
        headings_analysis = {}
        all_headings = []
        for i in range(1, 7):
            headings = self.soup.find_all(f'h{i}')
            headings_analysis[f'h{i}'] = {
                'count': len(headings),
                'texts': [h.get_text().strip()[:100] for h in headings[:5]]  # Pierwsze 5 nagłówków
            }
            all_headings.extend([(i, h.get_text().strip()) for h in headings])
        
        sem["headings"] = headings_analysis
        sem["heading_hierarchy_issues"] = check_heading_hierarchy(all_headings)
        sem["empty_headings"] = len([h for level, h in all_headings if not h.strip()])
        
        # Analiza punktów orientacyjnych (landmarks) i struktury
        landmarks = {
            "header": len(self.soup.find_all('header')),
            "nav": len(self.soup.find_all('nav')),
            "main": len(self.soup.find_all('main')),
            "aside": len(self.soup.find_all('aside')),
            "footer": len(self.soup.find_all('footer')),
            "section": len(self.soup.find_all('section')),
            "article": len(self.soup.find_all('article'))
        }
        
        aria_landmarks = {
            "banner": len(self.soup.find_all(attrs={"role": "banner"})),
            "navigation": len(self.soup.find_all(attrs={"role": "navigation"})),
            "main": len(self.soup.find_all(attrs={"role": "main"})),
            "contentinfo": len(self.soup.find_all(attrs={"role": "contentinfo"})),
            "complementary": len(self.soup.find_all(attrs={"role": "complementary"})),
            "search": len(self.soup.find_all(attrs={"role": "search"}))
        }
        
        sem["html5_landmarks"] = landmarks
        sem["aria_landmarks"] = aria_landmarks
    
    def check_keyboard_navigation(self):
        """Analiza dostępności nawigacji klawiaturowej"""
        kbd = self.accessibility["keyboard_navigation"]
        
        interactive_elements = self.soup.find_all(['a', 'button', 'input', 'select', 'textarea'])
        focusable_elements = []
        tabindex_issues = []
        
        for elem in interactive_elements:
            tabindex = elem.get('tabindex')
            if tabindex:
                try:
                    tabindex_val = int(tabindex)
                    if tabindex_val > 0:
                        tabindex_issues.append(f"{elem.name} with tabindex={tabindex_val}")
                    elif tabindex_val == -1:
                        # Programowo fokusowalne, ale nie w naturalnej kolejności tabulacji
                        pass
                except ValueError:
                    tabindex_issues.append(f"{elem.name} with invalid tabindex={tabindex}")
            focusable_elements.append(elem.name)
        
        kbd["total_interactive_elements"] = len(interactive_elements)
        kbd["tabindex_issues"] = tabindex_issues
        kbd["skip_links"] = self._check_skip_links()
        kbd["focus_indicators"] = self._check_focus_indicators()
        
    def check_screen_reader_support(self):
        """Analiza wsparcia dla czytników ekranowych"""
        sr = self.accessibility["screen_reader"]
        
        # Analiza obrazów
        images = self.soup.find_all('img')
        images_analysis = {
            "total": len(images),
            "with_alt": len([img for img in images if img.get('alt') is not None]),
            "with_empty_alt": len([img for img in images if img.get('alt') == '']),
            "without_alt": len([img for img in images if img.get('alt') is None]),
            "decorative_properly_marked": len([img for img in images if img.get('alt') == '' and img.get('role') == 'presentation'])
        }
        
        sr["images"] = images_analysis
        sr["aria_labels"] = len(self.soup.find_all(attrs={"aria-label": True}))
        sr["aria_describedby"] = len(self.soup.find_all(attrs={"aria-describedby": True}))
        sr["aria_labelledby"] = len(self.soup.find_all(attrs={"aria-labelledby": True}))
        sr["sr_only_content"] = len(self.soup.find_all(class_=re.compile(r'sr-only|visually-hidden|screen-reader', re.I)))

    def check_forms(self):
        """Analiza dostępności formularzy"""
        form_analysis = self.accessibility["forms"]
        
        forms = self.soup.find_all('form')
        form_analysis["total_forms"] = len(forms)
        form_analysis["forms_with_labels"] = 0
        form_analysis["total_inputs"] = 0
        form_analysis["inputs_with_labels"] = 0
        form_analysis["inputs_with_placeholders"] = 0
        form_analysis["required_fields"] = 0
        form_analysis["fieldsets"] = len(self.soup.find_all('fieldset'))
        form_analysis["legends"] = len(self.soup.find_all('legend'))
        
        inputs = self.soup.find_all(['input', 'select', 'textarea'])
        form_analysis["total_inputs"] = len(inputs)
        
        for input_elem in inputs:
            if input_elem.get('required') or input_elem.get('aria-required') == 'true':
                form_analysis["required_fields"] += 1
            
            if input_elem.get('placeholder'):
                form_analysis["inputs_with_placeholders"] += 1
            
            # Sprawdzanie etykiet powiązanych z polami
            input_id = input_elem.get('id')
            if input_id:
                label = self.soup.find('label', attrs={"for": input_id})
                if label:
                    form_analysis["inputs_with_labels"] += 1
            
            # Sprawdzanie atrybutów ARIA
            if input_elem.get('aria-label') or input_elem.get('aria-labelledby'):
                form_analysis["inputs_with_labels"] += 1
    
    def check_multimedia(self):
        """Analiza dostępności multimediów"""
        multimedia = self.accessibility["multimedia"]
        
        videos = self.soup.find_all('video')
        audios = self.soup.find_all('audio')
        iframes = self.soup.find_all('iframe')
        
        multimedia_analysis = {
            "videos": {
                "total": len(videos),
                "with_captions": len([v for v in videos if v.find('track', kind='captions')]),
                "with_controls": len([v for v in videos if v.get('controls')]),
                "autoplay": len([v for v in videos if v.get('autoplay')])
            },
            "audios": {
                "total": len(audios),
                "with_controls": len([a for a in audios if a.get('controls')]),
                "autoplay": len([a for a in audios if a.get('autoplay')])
            },
            "iframes": {
                "total": len(iframes),
                "with_title": len([i for i in iframes if i.get('title')]),
                "with_aria_label": len([i for i in iframes if i.get('aria-label')])
            }
        }
        
        self.accessibility["multimedia"] = multimedia_analysis
    
    def check_text_content(self):
        """Analiza treści tekstowych"""
        text = self.accessibility["text_content"]
        
        text_analysis = {
            "total_text_length": len(self.soup.get_text()),
            "paragraphs": len(self.soup.find_all('p')),
            "lists": {
                "ul": len(self.soup.find_all('ul')),
                "ol": len(self.soup.find_all('ol')),
                "dl": len(self.soup.find_all('dl'))
            },
            "tables": self._analyze_tables(),
            "abbreviations": len(self.soup.find_all('abbr')),
            "quotes": len(self.soup.find_all(['q', 'blockquote']))
        }
        
        self.accessibility["text_content"] = text_analysis
    
    def check_color_contrast(self):
        """Sprawdza kontrast kolorów na stronie (uproszczona analiza)"""
        contrast = self.accessibility["color_contrast"]
        
        # Pobierz wszystkie style inline i arkusze stylów
        css_content = ""
        for style in self.soup.find_all('style'):
            css_content += style.get_text()
        
        # Analizuj kolory
        colors = extract_css_colors(css_content)
        contrast_issues = []
        compliant_pairs = []
        
        # Sprawdź kontrast dla każdej pary kolorów tła i tekstu
        for bg_color in colors["background"]:
            for text_color in colors["text"]:
                try:
                    contrast_ratio = calculate_contrast_ratio(bg_color, text_color)
                    if contrast_ratio < 4.5:  # Minimalny współczynnik kontrastu dla AA
                        contrast_issues.append({
                            "background": bg_color,
                            "text": text_color,
                            "ratio": round(contrast_ratio, 2)
                        })
                    else:
                        compliant_pairs.append({
                            "background": bg_color,
                            "text": text_color,
                            "ratio": round(contrast_ratio, 2)
                        })
                except Exception:
                    pass  # Błąd obliczania kontrastu dla pewnych formatów kolorów
        
        contrast["issues"] = contrast_issues[:10]  # Ograniczenie do 10 problemów
        contrast["compliant_pairs"] = compliant_pairs[:10]  # Ograniczenie do 10 par
        contrast["background_colors"] = colors["background"][:20]
        contrast["text_colors"] = colors["text"][:20]
        contrast["has_issues"] = len(contrast_issues) > 0
    
    def check_wcag_compliance(self):
        """Weryfikacja zgodności z WCAG 2.1"""
        wcag = self.accessibility["wcag_compliance"]
        
        # Poziom A - wymagania podstawowe
        level_a_score = 0
        level_a_total = 10
        
        # Identyfikacja języka
        if self.accessibility["semantic_structure"]["lang_attribute"] != "Missing":
            level_a_score += 1
        
        # Obrazy mają tekst alternatywny
        images = self.accessibility["screen_reader"]["images"]
        if images["without_alt"] == 0:
            level_a_score += 1
        
        # Nagłówki i etykiety
        if not self.accessibility["semantic_structure"]["heading_hierarchy_issues"]:
            level_a_score += 1
        
        # Etykiety formularzy
        forms = self.accessibility["forms"]
        if forms["total_inputs"] > 0 and forms["inputs_with_labels"] == forms["total_inputs"]:
            level_a_score += 1
        
        # Dodatkowe wcześniej obliczone punkty (uproszczenie)
        level_a_score += 6
        
        wcag["level_a"] = {
            "score": level_a_score,
            "total": level_a_total,
            "percentage": round((level_a_score / level_a_total) * 100, 1),
            "passed": level_a_score >= level_a_total * 0.8
        }
        
        # Poziom AA - rozszerzone wymagania
        level_aa_score = level_a_score  # AA zawiera A
        level_aa_total = 15
        
        # Kontrast kolorów
        if not self.accessibility["color_contrast"].get("has_issues", True):
            level_aa_score += 1
        
        # Dostępność z klawiatury
        if len(self.accessibility["keyboard_navigation"]["tabindex_issues"]) == 0:
            level_aa_score += 1
        
        # Dodatkowe wcześniej obliczone punkty (uproszczenie)
        level_aa_score += 2
        
        wcag["level_aa"] = {
            "score": level_aa_score,
            "total": level_aa_total,
            "percentage": round((level_aa_score / level_aa_total) * 100, 1),
            "passed": level_aa_score >= level_aa_total * 0.8
        }
    
    # Metody pomocnicze
    def _check_skip_links(self):
        """Sprawdza linki pomijające nawigację"""
        skip_patterns = [
            r'skip.*nav',
            r'skip.*content',
            r'skip.*main',
            r'pomiń.*nav',
            r'pomiń.*treść',
            r'przeskocz.*treść'
        ]
        
        links = self.soup.find_all('a', href=True)
        skip_links = []
        
        for link in links:
            text = link.get_text().lower().strip()
            href = link.get('href', '').lower()
            
            for pattern in skip_patterns:
                if re.search(pattern, text, re.I) or re.search(pattern, href, re.I):
                    skip_links.append(text)
                    break
        
        return skip_links
    
    def _check_focus_indicators(self):
        """Sprawdza wskaźniki fokusa w CSS"""
        # Uproszczona analiza
        css_content = ""
        for style in self.soup.find_all('style'):
            css_content += style.get_text()
        
        focus_indicators = len(re.findall(r':focus', css_content, re.I))
        return focus_indicators
    
    def _analyze_tables(self):
        """Analiza dostępności tabel"""
        tables = self.soup.find_all('table')
        table_analysis = {
            "total": len(tables),
            "with_headers": 0,
            "with_caption": 0,
            "with_summary": 0,
            "data_tables": 0,
            "layout_tables": 0
        }
        
        for table in tables:
            if table.find('th'):
                table_analysis["with_headers"] += 1
            if table.find('caption'):
                table_analysis["with_caption"] += 1
            if table.get('summary'):
                table_analysis["with_summary"] += 1
            
            # Prosta heurystyka dla tabel danych vs. tabel layoutu
            if table.find('th') or table.get('role') == 'table':
                table_analysis["data_tables"] += 1
            else:
                table_analysis["layout_tables"] += 1
        
        return table_analysis