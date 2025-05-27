#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests
from bs4 import BeautifulSoup
import time
import json
from datetime import datetime

from ..modules.accessibility import AccessibilityAnalyzer
from ..modules.performance import PerformanceAnalyzer
from ..modules.usability import UsabilityAnalyzer
from ..modules.security import SecurityAnalyzer
from ..reports.report_generator import ReportGenerator
from ..utils.helpers import safe_get

class WebsiteAnalyzer:
    """
    Główna klasa analizatora stron internetowych, koordynująca wszystkie typy analiz
    i generowanie raportów.
    """
    def __init__(self, url):
        self.url = url
        self.soup = None
        self.response = None
        self.results = {
            "url": url,
            "accessibility": {},
            "performance": {
                "loading": {},
                "resources": {},
                "seo": {},
                "mobile": {},
                "technical": {}
            },
            "security": {},
            "usability": {},
            "date_analyzed": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        
        # Inicjalizacja modułów analizy
        self.accessibility_analyzer = None
        self.performance_analyzer = None
        self.security_analyzer = None
        self.usability_analyzer = None
        self.report_generator = None
        
    def analyze(self):
        """Uruchamia pełną analizę strony"""
        print(f"Analizuję stronę {self.url}...")
        
        try:
            self.get_website()
            self._initialize_analyzers()
            self._run_analysis()
            self._calculate_scores()
            self.print_summary_report()
            self.save_report()
            
            return self.results
        except Exception as e:
            print(f"Błąd podczas analizy strony: {str(e)}")
            raise
    
    def get_website(self):
        """Pobiera stronę internetową i mierzy parametry czasowe"""
        try:
            start_time = time.time()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
            }
            
            # Pobieranie strony
            self.response = requests.get(self.url, headers=headers, timeout=30)
            total_time = time.time() - start_time
            
            self.results["performance"]["loading"]["total_load_time"] = round(total_time, 2)
            
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            print(f"Pomyślnie pobrano stronę: {self.url}")
        except Exception as e:
            print(f"Błąd podczas pobierania strony: {str(e)}")
            raise
    
    def _initialize_analyzers(self):
        """Inicjalizuje wszystkie moduły analizy"""
        self.accessibility_analyzer = AccessibilityAnalyzer(self.soup, self.results)
        self.performance_analyzer = PerformanceAnalyzer(self.soup, self.response, self.url, self.results)
        self.security_analyzer = SecurityAnalyzer(self.soup, self.response, self.url, self.results)
        self.usability_analyzer = UsabilityAnalyzer(self.soup, self.results)
        self.report_generator = ReportGenerator(self.results)
    
    def _run_analysis(self):
        """Uruchamia wszystkie moduły analizy"""
        self.accessibility_analyzer.analyze()
        self.performance_analyzer.analyze()
        self.security_analyzer.analyze()
        self.usability_analyzer.analyze()
    
    def _calculate_scores(self):
        """Oblicza wyniki dla poszczególnych kategorii i wynik ogólny"""
        scores = {}
        
        # Wynik wydajności (0-100)
        perf_score = 100
        load_time = safe_get(self.results, "performance.loading.total_load_time", 0)
        if load_time > 3:
            perf_score -= 30
        elif load_time > 2:
            perf_score -= 15
        elif load_time > 1:
            perf_score -= 5
        
        # Odejmowanie za duży rozmiar pliku
        size_mb = safe_get(self.results, "performance.loading.response_size_mb", 0)
        if size_mb > 2:
            perf_score -= 20
        elif size_mb > 1:
            perf_score -= 10
        
        scores["performance"] = max(0, perf_score)
        
        # Wynik dostępności
        acc_score = 0
        if "wcag_compliance" in self.results["accessibility"]:
            acc_score = safe_get(self.results, "accessibility.wcag_compliance.level_aa.percentage", 0)
        
        scores["accessibility"] = acc_score
        
        # Wynik bezpieczeństwa
        security_score = safe_get(self.results, "security.score", 0)
        scores["security"] = security_score
        
        # Wynik ogólny (średnia ważona)
        scores["overall"] = round((scores["performance"] * 0.4 + scores["accessibility"] * 0.4 + 
                                   scores["security"] * 0.2), 1)
        
        self.results["scores"] = scores
    
    def print_summary_report(self):
        """Wyświetla podsumowanie analizy"""
        self.report_generator.print_summary_report()
    
    def save_report(self):
        """Zapisuje raport w formatach JSON i jako tekst"""
        return self.report_generator.save_reports()