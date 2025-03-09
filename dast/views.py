from django.shortcuts import render

# Create your views here.
from django.shortcuts import render
from rest_framework import viewsets, generics

# Create your views here.
from .models import Scan
from .serializers import ScanSerializer
from rest_framework import viewsets, permissions

import os
import os
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime

# Função para calcular a pontuação do TLS
def calculate_tls_score(tls_versions, ciphers, compression, preference):
    score = 0
    
    # Verifica as versões do TLS
    if 'TLSv1.3' in tls_versions:
        score += 4  # TLSv1.3 é a versão mais segura
    elif 'TLSv1.2' in tls_versions:
        score += 3  # TLSv1.2 ainda é seguro, mas abaixo de TLSv1.3

    # Avalia as cifras
    strong_ciphers = ['ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'ECDHE_ECDSA_WITH_AES_256_GCM_SHA384', 'ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256']
    for cipher in ciphers:
        if cipher in strong_ciphers:
            score += 3  # Cifras fortes adicionam 3 pontos

    # Avalia a compressão
    if compression == 'NULL':
        score += 1  # Compressão segura (NULL) adiciona 1 ponto
    else:
        score -= 2  # Compressão habilitada (não segura) subtrai 2 pontos

    # Avalia a preferência de cifra
    if preference == 'server':
        score += 2  # Server preference é melhor em muitos casos

    return score

# Função para processar a saída XML do Nmap
def process_nmap_output(site, data):
    xml_file = f"scans/{site}_{data}"
    
    if not os.path.exists(xml_file):
        print(f"Arquivo XML não encontrado: {xml_file}")
        return None
    
    tree = ET.parse(xml_file)
    root = tree.getroot()

    # Extrair as versões do TLS
    tls_versions = []
    ciphers = []
    compression = None
    preference = None

    for script in root.findall(".//script[@id='ssl-enum-ciphers']"):
        # Extrair as versões de TLS
        for tls_version in script.findall(".//table[@key='TLSv1.2']") + script.findall(".//table[@key='TLSv1.3']"):
            tls_versions.append(tls_version.attrib['key'])
        
        # Extrair as cifras
        for cipher in script.findall(".//table[@key='ciphers']//elem"):
            ciphers.append(cipher.text.strip())
        
        # Extrair a compressão
        for compressor in script.findall(".//table[@key='compressors']//elem"):
            compression = compressor.text.strip()
        
        # Extrair a preferência
        preference = script.find(".//elem[@key='cipher preference']").text.strip()

    # Avaliar a pontuação
    score = calculate_tls_score(tls_versions, ciphers, compression, preference)
    
    return score

# Função para executar o Nmap e verificar a configuração do TLS de um site
def check_tls_for_site(site, data):
    # Cria um diretório para armazenar os resultados do Nmap
    os.makedirs("scans", exist_ok=True)
    site_update = site.replace('.','-')
    site_update = site.replace('/', '-')
    print(site)
    # Define o comando nmap com o script ssl-enum-ciphers
    command = ["nmap", "--script", "ssl-enum-ciphers", "-p", "443", site.replace("https://","").replace("http://",""), "-oX", f"scans/{site_update}_{data}"]
    
    # Executa o comando e captura a saída
    try:
        result = subprocess.run(command, capture_output=True, text=True, check=True)
        print(f"Resultado do Nmap para {site}: {result.stdout}")
        
        # Processar a saída XML e calcular a pontuação
        score = process_nmap_output(site_update, data)
        if score is not None:
            print(f"Pontuação TLS para {site}: {score}")
        else:
            print(f"Falha ao processar o resultado para {site}")
        return score
    
    except subprocess.CalledProcessError as e:
        print(f"Erro ao executar o Nmap: {e}")
        return None
    

# Integração com a sua view
class ScanViewSet(viewsets.ModelViewSet):
    queryset = Scan.objects.all()
    permission_classes = [permissions.AllowAny]
    http_method_names = ['get', 'post', 'put', 'patch', 'delete']
    serializer_class = ScanSerializer  # Definindo o serializer class
    def perform_create(self, serializer):
        scan = serializer.save(status='pending')
        scan.status = 'in_progress'
        scan.save()

        site_Scan = scan.site
        scan_data = scan.scan_date.strftime('%Y-%m-%d_%H-%M-%S')  # Formato de data adequado para usar no nome do arquivo

        # Chama a função para verificar o TLS e avaliar a pontuação
        score = check_tls_for_site(site_Scan, scan_data)
        if score == None:
            score = 0
        scan.pontuacao = score
        scan.status = "completed"
        scan.save()
