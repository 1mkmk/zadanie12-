#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import re
import socket
from urllib.parse import urlparse

def safe_get(dictionary, path, default=None):
    """
    Bezpieczne pobieranie zagnieżdżonych wartości ze słownika za pomocą ścieżki z kropkami
    np. safe_get(dict, "a.b.c", "default") zwróci dict["a"]["b"]["c"] jeśli istnieje, w przeciwnym razie "default"
    """
    keys = path.split(".")
    current = dictionary
    
    for key in keys:
        if isinstance(current, dict) and key in current:
            current = current[key]
        else:
            return default
    
    return current

def extract_domain(url):
    """Wyodrębnia domenę z URL"""
    parsed = urlparse(url)
    return parsed.netloc

def calculate_contrast_ratio(color1, color2):
    """
    Oblicza współczynnik kontrastu między dwoma kolorami zgodnie z WCAG
    
    Args:
        color1, color2: Kolory w formacie RGB hex (#rrggbb) lub rgb(r,g,b)
        
    Returns:
        float: Współczynnik kontrastu (1:1 do 21:1)
    """
    # Konwersja z hex lub rgb() do wartości RGB
    def parse_color(color):
        if color.startswith("#"):
            color = color[1:]
            r = int(color[0:2], 16) / 255.0
            g = int(color[2:4], 16) / 255.0
            b = int(color[4:6], 16) / 255.0
            return r, g, b
        elif color.startswith("rgb"):
            match = re.search(r'rgb\(\s*(\d+)\s*,\s*(\d+)\s*,\s*(\d+)\s*\)', color)
            if match:
                r = int(match.group(1)) / 255.0
                g = int(match.group(2)) / 255.0
                b = int(match.group(3)) / 255.0
                return r, g, b
        return 0, 0, 0
    
    # Obliczanie luminancji zgodnie z WCAG
    def get_luminance(r, g, b):
        r = adjust_color_value(r)
        g = adjust_color_value(g)
        b = adjust_color_value(b)
        return 0.2126 * r + 0.7152 * g + 0.0722 * b
    
    def adjust_color_value(value):
        if value <= 0.03928:
            return value / 12.92
        else:
            return ((value + 0.055) / 1.055) ** 2.4
    
    # Obliczenie luminancji dla obu kolorów
    r1, g1, b1 = parse_color(color1)
    r2, g2, b2 = parse_color(color2)
    
    l1 = get_luminance(r1, g1, b1)
    l2 = get_luminance(r2, g2, b2)
    
    # Obliczenie współczynnika kontrastu
    if l1 > l2:
        return (l1 + 0.05) / (l2 + 0.05)
    else:
        return (l2 + 0.05) / (l1 + 0.05)

def check_dns_lookup_time(hostname):
    """Sprawdza czas wyszukiwania DNS dla podanej nazwy hosta"""
    import time
    
    start_time = time.time()
    try:
        socket.gethostbyname(hostname)
        end_time = time.time()
        return round((end_time - start_time) * 1000, 2)  # Czas w milisekundach
    except Exception:
        return None

def has_responsive_meta_tag(soup):
    """Sprawdza, czy strona zawiera tag meta viewport"""
    viewport_meta = soup.find("meta", attrs={"name": "viewport"})
    return viewport_meta is not None

def extract_css_colors(css_content):
    """
    Wyodrębnia kolory z zawartości CSS
    
    Returns:
        dict: Słownik kolorów tła i tekstu
    """
    colors = {
        "background": [],
        "text": [],
        "link": []
    }
    
    background_patterns = [
        r'background(-color)?:\s*([#0-9a-zA-Z(,)\s\.]+)',
        r'background(-color)?:\s*([a-zA-Z]+)'
    ]
    
    text_patterns = [
        r'color:\s*([#0-9a-zA-Z(,)\s\.]+)',
    ]
    
    link_patterns = [
        r'a\s*{[^}]*color:\s*([#0-9a-zA-Z(,)\s\.]+)',
        r'a:link\s*{[^}]*color:\s*([#0-9a-zA-Z(,)\s\.]+)'
    ]
    
    for pattern in background_patterns:
        for match in re.finditer(pattern, css_content):
            if match and match.group(2):
                color = match.group(2).strip()
                if color and color != 'transparent' and color != 'inherit' and color != 'initial':
                    colors["background"].append(color)
    
    for pattern in text_patterns:
        for match in re.finditer(pattern, css_content):
            if match and match.group(1):
                color = match.group(1).strip()
                if color and color != 'inherit' and color != 'initial':
                    colors["text"].append(color)
    
    for pattern in link_patterns:
        for match in re.finditer(pattern, css_content):
            if match and match.group(1):
                color = match.group(1).strip()
                if color and color != 'inherit' and color != 'initial':
                    colors["link"].append(color)
    
    # Usuwanie duplikatów
    for key in colors:
        colors[key] = list(set(colors[key]))
    
    return colors

def check_heading_hierarchy(headings):
    """
    Sprawdza, czy hierarchia nagłówków jest logiczna
    
    Args:
        headings: Lista krotek (poziom, treść)
        
    Returns:
        bool: True jeśli są problemy, False jeśli wszystko ok
    """
    if not headings:
        return False
    
    levels = [level for level, text in headings]
    
    # Sprawdź, czy istnieje H1
    if 1 not in levels:
        return True
    
    # Sprawdź, czy nie ma przeskoczonych poziomów
    for i in range(len(levels) - 1):
        if levels[i+1] - levels[i] > 1:
            return True
    
    return False