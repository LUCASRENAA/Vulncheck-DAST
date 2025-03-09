import ipaddress
import re
from django.core.exceptions import ValidationError
from django.db import models

# Função para validar o campo 'site'
def validate_https_and_no_private_ips(value):
    # Tenta identificar se o valor é um domínio ou IP
    try:
        # Se for um IP, vamos validar se é um IP válido
        ip = ipaddress.ip_address(value)
        
        # Verifica se o IP é privado
        if ip.is_private:
            raise ValidationError("IPs privados não são permitidos.")
        
        # Se o IP não for privado, podemos continuar (esse caso cobre IPs válidos)
        # Aqui, a URL que está sendo passada é um IP, então já validamos se é válido e se não é privado

    except ValueError:
        # Se não for um IP válido, trata como domínio e valida o esquema da URL (http ou https)
        # Verifica se o valor é uma URL com http ou https
        if not re.match(r'^(https?)://', value):
            raise ValidationError("O site deve começar com 'http://' ou 'https://'.")
        
        # Agora vamos extrair o domínio/IP da URL
        try:
            # Remove o esquema (http:// ou https://) e pega o domínio ou IP
            domain = value.split("://")[1].split("/")[0]
            
            # Verifica se o domínio é um IP
            ip = ipaddress.ip_address(domain)
            
            # Se for um IP, verifica se ele é privado
            if ip.is_private:
                raise ValidationError("IPs privados não são permitidos.")
        
        except ValueError:
            # Caso o domínio não seja um IP, nada mais é feito e ele é tratado como um domínio válido
            pass
    
    # Se o código chegou aqui, significa que o valor é válido
    return value

# Modelo de Scan com validação customizada
class Scan(models.Model):
    STATUS_CHOICES = [
        ('pending', 'Pending'),
        ('in_progress', 'In Progress'),
        ('completed', 'Completed'),
        ('failed', 'Failed'),
    ]
    
    site = models.CharField(max_length=50, validators=[validate_https_and_no_private_ips])
    scan_date = models.DateTimeField(auto_now_add=True)  # Campo para armazenar a data do scan
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='pending')
    pontuacao = models.IntegerField(default=0)
    def __str__(self):
        return self.site
