import requests
import json
import urllib.parse
import urllib3
from datetime import datetime
from typing import Optional, Dict, Any, List

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =====================================================
# Microsoft Defender Configuration
# =====================================================
tenant_id = 'YOUR_TENANT_ID_HERE'
app_id = 'YOUR_APP_ID_HERE'
app_secret = 'YOUR_APP_SECRET_HERE'

resource_app_id_uri = 'https://api.securitycenter.microsoft.com'
oauth_uri = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

# =====================================================
# IRIS Configuration
# =====================================================
# NOTA: Configure a URL base do seu IRIS e a chave de API
# A estrutura da API pode variar conforme a versão do IRIS
# Consulte a documentação oficial: https://docs.dfir-iris.org/
IRIS_BASE_URL = "https://YOUR_IRIS_HOST_HERE"  # Configure com a URL do seu IRIS
IRIS_API_KEY = "YOUR_IRIS_API_KEY_HERE"  # Configure com sua chave de API do IRIS
IRIS_API_PREFIX = "/alerts/"  # Ajuste conforme a versão do IRIS (pode ser /api/v2, etc.)

# Configurações padrão (ajuste conforme necessário)
IRIS_DEFAULT_CUSTOMER_ID = 2  # ID do customer padrão - ajuste conforme seu ambiente
IRIS_DEFAULT_ALERT_STATUS_ID = 1  # ID do status padrão (geralmente 1 = New) - ajuste conforme necessário
IRIS_DEFAULT_CASE_ID = None  # ID do caso padrão (None = criar alerta sem caso, ou defina um ID de caso existente)

# =====================================================
# ANSI color codes for terminal output
# =====================================================
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    GRAY = '\033[90m'
    DARK_GRAY = '\033[2m'
    RESET = '\033[0m'

def print_colored(text: str, color: str = Colors.WHITE):
    """Print colored text to console"""
    print(f"{color}{text}{Colors.RESET}")

# =====================================================
# Microsoft Defender Functions
# =====================================================

def get_defender_access_token() -> Optional[str]:
    """Authenticate with Microsoft Defender and get access token"""
    auth_body = {
        'client_id': app_id,
        'client_secret': app_secret,
        'scope': f"{resource_app_id_uri}/.default",
        'grant_type': 'client_credentials'
    }
    
    try:
        response = requests.post(oauth_uri, data=auth_body)
        response.raise_for_status()
        auth_response = response.json()
        return auth_response.get('access_token')
    except Exception as e:
        print_colored(f"[ERRO] Erro na autenticação: {e}", Colors.RED)
        return None

def get_defender_headers(token: str) -> Dict[str, str]:
    """Get headers with authorization token for Microsoft Defender"""
    return {
        'Authorization': f'Bearer {token}',
        'Content-Type': 'application/json'
    }

def get_alert_story(alert_id: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Get detailed alert information including story"""
    alert_detail_endpoint = f"{resource_app_id_uri}/api/alerts/{alert_id}"
    
    try:
        response = requests.get(alert_detail_endpoint, headers=headers)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        return None

def get_alert_story_timeline(alert_id: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
    """Get alert story timeline"""
    # Try different endpoints for alert story/timeline
    endpoints = [
        f"{resource_app_id_uri}/api/alerts/{alert_id}/story",
        f"{resource_app_id_uri}/api/alerts/{alert_id}/timeline",
        f"{resource_app_id_uri}/api/alerts/{alert_id}/events"
    ]
    
    for endpoint in endpoints:
        try:
            response = requests.get(endpoint, headers=headers)
            response.raise_for_status()
            timeline_data = response.json()
            if timeline_data:
                return timeline_data
        except:
            # Try next endpoint
            continue
    
    # If specific endpoints don't work, try getting full alert details which may contain story
    try:
        alert_detail = get_alert_story(alert_id, headers)
        if alert_detail:
            # Check for story/timeline in various possible properties
            if 'story' in alert_detail:
                return alert_detail['story']
            if 'timeline' in alert_detail:
                return alert_detail['timeline']
            if 'events' in alert_detail:
                return alert_detail['events']
            if 'alertStory' in alert_detail:
                return alert_detail['alertStory']
            # Return full detail if it contains story-like structure
            if 'value' in alert_detail or 'items' in alert_detail:
                return alert_detail
    except:
        pass
    
    return None


def get_new_alerts_from_defender(headers: Dict[str, str]) -> List[Dict[str, Any]]:
    """Fetch all alerts with status 'New' from Microsoft Defender"""
    alerts_endpoint = f"{resource_app_id_uri}/api/alerts"
    filter_query = "status eq 'New'"
    encoded_filter = urllib.parse.quote(filter_query)
    alerts_endpoint_with_filter = f"{alerts_endpoint}?$filter={encoded_filter}"
    
    print_colored("Buscando alertas com status 'New' no Microsoft Defender...", Colors.CYAN)
    
    try:
        response = requests.get(alerts_endpoint_with_filter, headers=headers)
        response.raise_for_status()
        alerts_response = response.json()
        
        if 'value' in alerts_response:
            alerts = alerts_response['value']
            # Client-side filter to ensure only "New" status
            alerts = [alert for alert in alerts if alert.get('status') in ['New', 'newAlert']]
            return alerts
        else:
            print_colored("Nenhum alerta encontrado ou formato de resposta inesperado.", Colors.YELLOW)
            return []
    
    except requests.exceptions.HTTPError as e:
        print_colored(f"[ERRO] Erro ao buscar alertas: {e}", Colors.RED)
        if e.response is not None:
            status_code = e.response.status_code
            print_colored(f"HTTP Status Code: {status_code}", Colors.RED)
            try:
                error_details = e.response.text
                if error_details:
                    print_colored(f"Detalhes do erro: {error_details}", Colors.RED)
            except:
                pass
        return []
    except Exception as e:
        print_colored(f"[ERRO] Erro ao buscar alertas: {e}", Colors.RED)
        return []

# =====================================================
# IRIS Functions
# =====================================================

def get_iris_headers() -> Dict[str, str]:
    """Get headers for IRIS API"""
    return {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "Authorization": f"Bearer {IRIS_API_KEY}",
    }

def get_iris_ioc_types() -> Optional[Dict[str, int]]:
    """Busca os tipos de IOC disponíveis no IRIS e retorna um dicionário mapeando nome -> ID"""
    try:
        endpoint = f"{IRIS_BASE_URL}/manage/ioc-types/list"
        response = requests.get(endpoint, headers=get_iris_headers(), timeout=10, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success" and "data" in data:
                ioc_types = {}
                for ioc_type in data["data"]:
                    type_name = ioc_type.get("type_name", "").lower()
                    type_id = ioc_type.get("type_id")
                    if type_name and type_id:
                        ioc_types[type_name] = type_id
                return ioc_types
    except Exception as e:
        print_colored(f"  [AVISO] Não foi possível buscar tipos de IOC: {e}", Colors.YELLOW)
    return None

def get_iris_customers() -> Optional[List[Dict[str, Any]]]:
    """Busca a lista de customers disponíveis no IRIS"""
    try:
        endpoint = f"{IRIS_BASE_URL}/manage/customers/list"
        response = requests.get(endpoint, headers=get_iris_headers(), timeout=10, verify=False)
        if response.status_code == 200:
            data = response.json()
            if data.get("status") == "success" and "data" in data:
                return data["data"]
    except Exception as e:
        print_colored(f"  [AVISO] Não foi possível buscar customers: {e}", Colors.YELLOW)
    return None

def find_available_customer_id() -> Optional[int]:
    """Tenta encontrar um customer ID disponível para o usuário atual"""
    customers = get_iris_customers()
    if customers:
        # Retornar o primeiro customer disponível
        if len(customers) > 0:
            customer_id = customers[0].get("customer_id") or customers[0].get("id")
            if customer_id:
                return int(customer_id)
    return None

def map_severity_to_iris(severity_str: str) -> int:
    """Mapeia a severidade do Defender para IRIS (geralmente 1=Low, 2=Medium, 3=High, 4=Critical)"""
    severity_map = {
        "Informational": 1,
        "Low": 1,
        "Medium": 2,
        "High": 3,
        "Critical": 4
    }
    return severity_map.get(severity_str, 2)  # Default: Medium

def create_iris_case_payload(alert_data: Dict[str, Any], ioc_types_map: Optional[Dict[str, int]] = None, customer_id: Optional[int] = None) -> Dict[str, Any]:
    """Cria o payload para criar um caso no IRIS a partir dos dados do Defender"""
    # Mapear campos do JSON do Defender para o formato do IRIS
    title = alert_data.get("title", "Alerta sem título")
    
    # Obter a descrição do alerta do Defender
    alert_description = alert_data.get("description", "")
    if not alert_description:
        # Tentar outras fontes de descrição
        alert_description = alert_data.get("alertDescription", "") or alert_data.get("message", "") or "Sem descrição disponível"
    
    # Construir a descrição usando o template fornecido
    description_parts = []
    
    # Seção 1: Descrição do evento
    description_parts.append("Descrição do evento (gerado pelo Defender):")
    description_parts.append("")
    description_parts.append(alert_description)
    description_parts.append("")
    description_parts.append("")
    description_parts.append("---")
    description_parts.append("")
    description_parts.append("")
    
    # Seção 2: Ação recomendada
    recommended_action = alert_data.get("recommendedAction", "")
    if recommended_action:
        description_parts.append("Ação recomendada:")
        description_parts.append("")
        description_parts.append(recommended_action)
        description_parts.append("")
        description_parts.append("")
        description_parts.append("---")
        description_parts.append("")
        description_parts.append("")
    
    # Seção 3: Notas adicionais
    description_parts.append("Notas adicionais:")
    description_parts.append("")
    
    # Adicionar informações técnicas adicionais como notas
    additional_notes = []
    
    # Informações básicas do alerta
    if alert_data.get("id"):
        additional_notes.append(f"Alert ID: {alert_data['id']}")
    if alert_data.get("severity"):
        additional_notes.append(f"Severidade: {alert_data['severity']}")
    if alert_data.get("category"):
        additional_notes.append(f"Categoria: {alert_data['category']}")
    if alert_data.get("status"):
        additional_notes.append(f"Status: {alert_data['status']}")
    
    # Informações do vendor/provider
    vendor_info = alert_data.get("vendorInformation", {})
    if isinstance(vendor_info, dict):
        if vendor_info.get("provider"):
            additional_notes.append(f"Provider: {vendor_info['provider']}")
        if vendor_info.get("subProvider"):
            additional_notes.append(f"Sub-Provider: {vendor_info['subProvider']}")
    
    # Informações de detecção
    if alert_data.get("detectionSource"):
        additional_notes.append(f"Fonte de detecção: {alert_data['detectionSource']}")
    if alert_data.get("threatName"):
        additional_notes.append(f"Ameaça: {alert_data['threatName']}")
    if alert_data.get("threatFamilyName"):
        additional_notes.append(f"Família de ameaça: {alert_data['threatFamilyName']}")
    
    # Informações de tempo
    if alert_data.get("createdDateTime"):
        additional_notes.append(f"Data de criação: {alert_data['createdDateTime']}")
    if alert_data.get("alertCreationTime"):
        additional_notes.append(f"Tempo de criação do alerta: {alert_data['alertCreationTime']}")
    
    # Informações do computador
    if alert_data.get("computerDnsName"):
        additional_notes.append(f"Computador: {alert_data['computerDnsName']}")
    if alert_data.get("machineId"):
        additional_notes.append(f"Machine ID: {alert_data['machineId']}")
    
    # Adicionar story timeline se disponível
    if alert_data.get("storyTimeline"):
        additional_notes.append("")
        additional_notes.append("--- Story Timeline ---")
        story_timeline = alert_data.get("storyTimeline")
        if isinstance(story_timeline, dict):
            # Tentar extrair informações relevantes do timeline
            events = story_timeline.get("value") or story_timeline.get("items") or story_timeline.get("events")
            if events and isinstance(events, list):
                for i, event in enumerate(events[:5]):  # Limitar a 5 eventos
                    if isinstance(event, dict):
                        event_info = []
                        if event.get("eventDateTime"):
                            event_info.append(f"  [{event['eventDateTime']}]")
                        if event.get("title"):
                            event_info.append(f"  {event['title']}")
                        if event.get("description"):
                            event_info.append(f"  {event['description']}")
                        if event_info:
                            additional_notes.append("\n".join(event_info))
    
    if additional_notes:
        description_parts.extend(additional_notes)
    else:
        description_parts.append("[Complementar conforme contexto ou triagem do SOC]")
    
    # Juntar todas as partes da descrição
    description = "\n".join(description_parts)
    
    # Severidade
    severity = map_severity_to_iris(alert_data.get("severity", "Medium"))
    
    # Tags
    tags = []
    if alert_data.get("category"):
        tags.append(alert_data["category"])
    if alert_data.get("detectionSource"):
        tags.append(alert_data["detectionSource"])
    if alert_data.get("threatFamilyName"):
        tags.append(alert_data["threatFamilyName"])
    if alert_data.get("severity"):
        tags.append(f"Severity-{alert_data['severity']}")
    tags.append("MicrosoftDefender")
    tags.append("Defender")
    
    # Source e SourceRef
    source = "Microsoft Defender"
    source_ref = alert_data.get("id", f"defender_{datetime.now().timestamp()}")
    
    # Criar payload base para IRIS ALERT
    # Baseado no formato correto da API do IRIS
    payload = {
        "alert_title": title,
        "alert_description": description,
        "alert_source": source,
        "alert_source_ref": source_ref,
        "alert_severity_id": severity,
        "alert_status_id": IRIS_DEFAULT_ALERT_STATUS_ID,
        "alert_customer_id": customer_id if customer_id is not None else IRIS_DEFAULT_CUSTOMER_ID,
    }
    
    # Adicionar alert_source_link se disponível (URL do alerta no Defender)
    if alert_data.get("id"):
        # Construir link para o alerta no Defender (ajuste conforme sua URL)
        defender_alert_url = f"https://security.microsoft.com/alerts/{alert_data['id']}"
        payload["alert_source_link"] = defender_alert_url
    
    # Adicionar alert_source_event_time (formato ISO)
    if alert_data.get("createdDateTime"):
        try:
            # Manter formato ISO se possível, ou converter
            alert_date_str = alert_data["createdDateTime"]
            # Remover 'Z' e ajustar formato se necessário
            if alert_date_str.endswith('Z'):
                alert_date_str = alert_date_str[:-1] + "+00:00"
            payload["alert_source_event_time"] = alert_date_str
        except:
            payload["alert_source_event_time"] = datetime.now().isoformat()
    else:
        payload["alert_source_event_time"] = datetime.now().isoformat()
    
    # Adicionar alert_source_content (conteúdo completo do alerta do Defender como JSON)
    # Isso pode ser útil para referência futura
    payload["alert_source_content"] = alert_data
    
    # Adicionar alert_tags como string separada por vírgulas
    if tags:
        tags_string = ",".join(tags) if isinstance(tags, list) else str(tags)
        payload["alert_tags"] = tags_string
    
    # Adicionar alert_note (nota adicional)
    if recommended_action:
        payload["alert_note"] = f"Ação recomendada: {recommended_action}"
    
    # Adicionar alert_context (contexto adicional)
    payload["alert_context"] = {
        "defender_alert_id": alert_data.get("id", ""),
        "defender_category": alert_data.get("category", ""),
        "defender_detection_source": alert_data.get("detectionSource", "")
    }
    
    # Adicionar IOCs (Indicators of Compromise) no formato correto
    # Formato: alert_iocs com ioc_value, ioc_description, ioc_tlp_id, ioc_type_id, ioc_tags, ioc_enrichment
    alert_iocs = []
    
    # Mapear tipos de IOC comuns para IDs
    default_ioc_types = {
        "hostname": 1,
        "domain": 2,
        "ip": 3,
        "url": 4,
        "hash": 5,
        "other": 99
    }
    
    ioc_type_map = ioc_types_map if ioc_types_map else default_ioc_types
    
    if alert_data.get("computerDnsName"):
        ioc_type_id = ioc_type_map.get("hostname") or ioc_type_map.get("domain") or ioc_type_map.get("other") or 1
        alert_iocs.append({
            "ioc_value": alert_data["computerDnsName"],
            "ioc_description": f"Hostname do alerta Defender: {alert_data.get('id', 'N/A')}",
            "ioc_tlp_id": 2,  # TLP Amber por padrão (1=White, 2=Green, 3=Amber, 4=Red)
            "ioc_type_id": ioc_type_id,
            "ioc_tags": "MicrosoftDefender,Hostname"
        })
    
    if alert_data.get("machineId"):
        ioc_type_id = ioc_type_map.get("other") or 99
        alert_iocs.append({
            "ioc_value": f"MachineID: {alert_data['machineId']}",
            "ioc_description": f"Machine ID do Defender: {alert_data.get('id', 'N/A')}",
            "ioc_tlp_id": 2,
            "ioc_type_id": ioc_type_id,
            "ioc_tags": "MicrosoftDefender,MachineID"
        })
    
    if alert_data.get("id"):
        ioc_type_id = ioc_type_map.get("other") or 99
        alert_iocs.append({
            "ioc_value": f"DefenderAlertID: {alert_data['id']}",
            "ioc_description": f"ID do alerta no Microsoft Defender",
            "ioc_tlp_id": 2,
            "ioc_type_id": ioc_type_id,
            "ioc_tags": "MicrosoftDefender,AlertID"
        })
    
    if alert_iocs:
        payload["alert_iocs"] = alert_iocs
    
    # Adicionar alert_assets se disponível
    alert_assets = []
    if alert_data.get("computerDnsName"):
        alert_assets.append({
            "asset_name": alert_data["computerDnsName"],
            "asset_description": f"Computador afetado pelo alerta Defender: {alert_data.get('id', 'N/A')}",
            "asset_type_id": 1,  # Ajuste conforme os tipos de asset disponíveis no IRIS
            "asset_ip": alert_data.get("networkIPv4", ""),
            "asset_domain": alert_data.get("computerDnsName", ""),
            "asset_tags": "MicrosoftDefender,Computer"
        })
    
    if alert_assets:
        payload["alert_assets"] = alert_assets
    
    # Adicionar alert_classification_id (opcional, ajuste conforme necessário)
    # payload["alert_classification_id"] = 1
    
    # Adicionar TTPs (MITRE ATT&CK Techniques) se disponíveis
    ttps = []
    
    # Extrair técnicas MITRE de diferentes campos possíveis
    mitre_techniques = (
        alert_data.get('mitreTechniques') or 
        alert_data.get('mitreAttackTechniques') or 
        alert_data.get('mitreTechniqueIds')
    )
    
    # Processar técnicas MITRE se encontradas
    if mitre_techniques:
        # Se for uma lista, processar cada técnica
        if isinstance(mitre_techniques, list):
            for technique in mitre_techniques:
                if isinstance(technique, dict):
                    # Se for um objeto com informações estruturadas
                    technique_id = technique.get('techniqueId') or technique.get('id') or technique.get('technique')
                    
                    if technique_id:
                        ttps.append({
                            "ttp_name": str(technique_id).strip(),
                            "ttp_type": "technique"
                        })
                elif isinstance(technique, str):
                    # Se for apenas uma string (ID da técnica)
                    technique_id = technique.strip()
                    if technique_id:
                        ttps.append({
                            "ttp_name": technique_id,
                            "ttp_type": "technique"
                        })
                elif technique is not None:
                    # Tentar converter para string se for outro tipo
                    technique_id = str(technique).strip()
                    if technique_id:
                        ttps.append({
                            "ttp_name": technique_id,
                            "ttp_type": "technique"
                        })
        elif isinstance(mitre_techniques, str):
            # Se for uma string única, tentar dividir por vírgula ou processar como uma única técnica
            techniques_list = [t.strip() for t in mitre_techniques.split(',') if t.strip()]
            for technique_id in techniques_list:
                if technique_id:
                    ttps.append({
                        "ttp_name": technique_id,
                        "ttp_type": "technique"
                    })
        else:
            # Tentar converter para string se for outro tipo
            technique_id = str(mitre_techniques).strip()
            if technique_id:
                ttps.append({
                    "ttp_name": technique_id,
                    "ttp_type": "technique"
                })
    
    # TTPs não são incluídos no payload de criação de alerta
    # Eles podem ser adicionados após a criação do alerta usando a API de atualização
    # Mantendo a lógica aqui para uso futuro se necessário
    if ttps:
        # Debug: log dos TTPs encontrados (mas não adicionados ao payload)
        ttp_names = [ttp.get("ttp_name", "N/A") for ttp in ttps]
        print_colored(f"    [DEBUG] TTPs encontrados (não incluídos no payload): {', '.join(ttp_names)}", Colors.DARK_GRAY)
        # Se precisar adicionar TTPs, descomente a linha abaixo:
        # payload["alert_ttps"] = ttps  # Verificar formato correto na documentação
    else:
        print_colored(f"    [DEBUG] Nenhum TTP encontrado", Colors.DARK_GRAY)
    
    return payload

def create_iris_case(alert_data: Dict[str, Any], customer_id_override: Optional[int] = None) -> Optional[Dict[str, Any]]:
    """Cria um alerta no IRIS a partir dos dados do Defender
    
    Args:
        alert_data: Dados do alerta do Defender
        customer_id_override: ID do customer a usar (sobrescreve IRIS_DEFAULT_CUSTOMER_ID)
    """
    # Buscar tipos de IOC do IRIS (cache para melhor performance)
    if not hasattr(create_iris_case, '_ioc_types_cache'):
        print_colored("  Buscando tipos de IOC do IRIS...", Colors.GRAY)
        create_iris_case._ioc_types_cache = get_iris_ioc_types()
        if create_iris_case._ioc_types_cache:
            print_colored(f"  [OK] {len(create_iris_case._ioc_types_cache)} tipo(s) de IOC encontrado(s)", Colors.GREEN)
        else:
            print_colored("  [AVISO] Usando tipos de IOC padrão", Colors.YELLOW)
    
    # Usar customer_id_override se fornecido, senão usar o padrão
    customer_id_to_use = customer_id_override if customer_id_override is not None else IRIS_DEFAULT_CUSTOMER_ID
    
    payload = create_iris_case_payload(alert_data, create_iris_case._ioc_types_cache, customer_id=customer_id_to_use)
    
    # Debug: mostrar payload completo
    print_colored(f"  [DEBUG] Payload completo: {json.dumps(payload, indent=2, ensure_ascii=False)}", Colors.DARK_GRAY)
    
    print_colored(f"  Criando alerta no IRIS...", Colors.CYAN)
    
    # Endpoint para criar alerta no IRIS
    # Documentação: https://docs.dfir-iris.org/latest/_static/iris_api_reference_v2.0.4.html#tag/Alerts/operation/post-case-add-alert
    # O endpoint precisa do parâmetro cid (case ID) na query string
    # Se IRIS_DEFAULT_CASE_ID estiver definido, usar esse caso
    # Caso contrário, tentar criar alerta sem caso (pode não funcionar dependendo da configuração do IRIS)
    if IRIS_DEFAULT_CASE_ID:
        case_endpoint = f"{IRIS_BASE_URL}{IRIS_API_PREFIX}add?cid={IRIS_DEFAULT_CASE_ID}"
    else:
        # Tentar sem cid - pode falhar se o IRIS exigir um caso
        case_endpoint = f"{IRIS_BASE_URL}{IRIS_API_PREFIX}add"
    
    try:
        response = requests.post(
            case_endpoint,
            json=payload,
            headers=get_iris_headers(),
            timeout=15,
            verify=False,
        )
        
        if response.status_code not in (200, 201):
            error_data = {}
            try:
                error_data = response.json()
            except:
                pass
            
            error_message = error_data.get("message", response.text) if error_data else response.text
            
            # Tratamento específico para erro de permissão de customer
            if "not entitled to create alerts for the client" in error_message.lower() or "customer" in error_message.lower():
                print_colored(f"  [ERRO] Falha ao criar alerta: {response.status_code}", Colors.RED)
                print_colored(f"  [ERRO] Mensagem: {error_message}", Colors.RED)
                print_colored(f"  [INFO] O usuário não tem permissão para criar alertas para o customer ID: {IRIS_DEFAULT_CUSTOMER_ID}", Colors.YELLOW)
                print_colored(f"  [INFO] Tentando encontrar um customer disponível...", Colors.CYAN)
                
                # Tentar encontrar um customer disponível
                available_customer = find_available_customer_id()
                if available_customer and available_customer != IRIS_DEFAULT_CUSTOMER_ID:
                    print_colored(f"  [INFO] Customer disponível encontrado: ID {available_customer}", Colors.GREEN)
                    print_colored(f"  [INFO] Tentando novamente com customer ID {available_customer}...", Colors.CYAN)
                    # Tentar novamente com o customer disponível
                    return create_iris_case(alert_data, customer_id_override=available_customer)
                else:
                    print_colored(f"  [INFO] Ajuste IRIS_DEFAULT_CUSTOMER_ID no script", Colors.YELLOW)
                    customers = get_iris_customers()
                    if customers:
                        print_colored(f"  [INFO] Customers disponíveis:", Colors.CYAN)
                        for customer in customers[:5]:  # Mostrar até 5
                            cust_id = customer.get("customer_id") or customer.get("id")
                            cust_name = customer.get("customer_name") or customer.get("name", "N/A")
                            print_colored(f"    - ID: {cust_id}, Nome: {cust_name}", Colors.WHITE)
            else:
                print_colored(f"  [ERRO] Falha ao criar alerta: {response.status_code} -> {error_message}", Colors.RED)
                if error_data and "data" in error_data:
                    print_colored(f"  [DEBUG] Detalhes: {json.dumps(error_data, indent=2)}", Colors.DARK_GRAY)
            
            return None
        
        try:
            alert_response = response.json()
            # A resposta pode conter o alerta criado em data
            if alert_response.get("status") == "success" and "data" in alert_response:
                alert_data_response = alert_response["data"]
                alert_id = alert_data_response.get("alert_id") or alert_data_response.get("id") or alert_data_response.get("_id")
                
                if alert_id:
                    print_colored(f"  [OK] Alerta criado no IRIS! ID: {alert_id}", Colors.GREEN)
                    return alert_data_response
                else:
                    print_colored(f"  [ERRO] Resposta não contém 'alert_id' ou 'id'", Colors.RED)
                    print_colored(f"  [DEBUG] Resposta completa: {json.dumps(alert_response, indent=2)}", Colors.DARK_GRAY)
                    return None
            else:
                # Tentar extrair ID diretamente da resposta
                alert_id = alert_response.get("alert_id") or alert_response.get("id") or alert_response.get("_id")
                if alert_id:
                    print_colored(f"  [OK] Alerta criado no IRIS! ID: {alert_id}", Colors.GREEN)
                    return alert_response
                else:
                    print_colored(f"  [ERRO] Formato de resposta inesperado", Colors.RED)
                    print_colored(f"  [DEBUG] Resposta completa: {json.dumps(alert_response, indent=2)}", Colors.DARK_GRAY)
                    return None
        except ValueError as e:
            print_colored(f"  [ERRO] Falha ao fazer parse da resposta JSON: {e}", Colors.RED)
            return None
            
    except requests.exceptions.Timeout:
        print_colored("  [ERRO] Timeout ao criar caso (15s)", Colors.RED)
        return None
    except requests.exceptions.ConnectionError as e:
        print_colored(f"  [ERRO] Erro de conexão: {e}", Colors.RED)
        return None
    except requests.exceptions.RequestException as e:
        print_colored(f"  [ERRO] Exceção ao criar caso: {e}", Colors.RED)
        return None

def add_iocs_to_case(case_id: str, iocs: List[Dict[str, Any]]) -> bool:
    """Adiciona IOCs a um caso existente no IRIS"""
    if not iocs:
        return False
    
    print_colored(f"  Adicionando {len(iocs)} IOC(s) ao caso...", Colors.CYAN)
    
    # Endpoint para adicionar IOCs
    # NOTA: Ajuste o endpoint conforme a documentação da API do IRIS
    # Pode ser /case/{id}/ioc/add, /ioc/add, /case/{id}/iocs, etc.
    ioc_endpoint = f"{IRIS_BASE_URL}{IRIS_API_PREFIX}/case/{case_id}/ioc/add"
    
    try:
        for ioc in iocs:
            response = requests.post(
                ioc_endpoint,
                json=ioc,
                headers=get_iris_headers(),
                timeout=10,
                verify=False,
            )
            
            if response.status_code not in (200, 201):
                print_colored(f"    [ERRO] Falha ao adicionar IOC {ioc.get('ioc_value', 'N/A')}: {response.status_code}", Colors.RED)
            else:
                print_colored(f"    [OK] IOC adicionado: {ioc.get('ioc_value', 'N/A')}", Colors.GREEN)
        
        return True
    except Exception as e:
        print_colored(f"  [ERRO] Erro ao adicionar IOCs: {e}", Colors.RED)
        return False

def add_ttps_to_case(case_id: str, ttps: List[Dict[str, Any]]) -> bool:
    """Adiciona TTPs a um caso existente no IRIS"""
    if not ttps:
        return False
    
    print_colored(f"  Adicionando {len(ttps)} TTP(s) ao caso...", Colors.CYAN)
    
    # Endpoint para adicionar TTPs
    # NOTA: Ajuste o endpoint conforme a documentação da API do IRIS
    # Pode ser /case/{id}/ttp/add, /ttp/add, /case/{id}/ttps, etc.
    ttp_endpoint = f"{IRIS_BASE_URL}{IRIS_API_PREFIX}/case/{case_id}/ttp/add"
    
    try:
        for ttp in ttps:
            response = requests.post(
                ttp_endpoint,
                json=ttp,
                headers=get_iris_headers(),
                timeout=10,
                verify=False,
            )
            
            if response.status_code not in (200, 201):
                print_colored(f"    [ERRO] Falha ao adicionar TTP {ttp.get('ttp_name', 'N/A')}: {response.status_code}", Colors.RED)
            else:
                print_colored(f"    [OK] TTP adicionado: {ttp.get('ttp_name', 'N/A')}", Colors.GREEN)
        
        return True
    except Exception as e:
        print_colored(f"  [ERRO] Erro ao adicionar TTPs: {e}", Colors.RED)
        return False

# =====================================================
# Main Function
# =====================================================

def main():
    """Main function to fetch alerts from Defender and create them in IRIS"""
    print_colored("=" * 70, Colors.CYAN)
    print_colored("Microsoft Defender -> IRIS Integration", Colors.CYAN)
    print_colored("=" * 70, Colors.CYAN)
    print()
    
    # Verificar se o customer ID está configurado e é válido
    if IRIS_DEFAULT_CUSTOMER_ID is None:
        print_colored("[AVISO] IRIS_DEFAULT_CUSTOMER_ID não está configurado.", Colors.YELLOW)
        print_colored("[INFO] Tentando encontrar um customer disponível...", Colors.CYAN)
        available_customer = find_available_customer_id()
        if available_customer:
            print_colored(f"[INFO] Customer disponível encontrado: ID {available_customer}", Colors.GREEN)
            print_colored(f"[INFO] Configure IRIS_DEFAULT_CUSTOMER_ID = {available_customer} no script", Colors.YELLOW)
        else:
            print_colored("[ERRO] Não foi possível encontrar um customer disponível.", Colors.RED)
            print_colored("[INFO] Verifique suas permissões no IRIS ou configure IRIS_DEFAULT_CUSTOMER_ID manualmente", Colors.YELLOW)
            return
    else:
        print_colored(f"[INFO] Usando Customer ID: {IRIS_DEFAULT_CUSTOMER_ID}", Colors.CYAN)
    
    # Step 1: Authenticate with Microsoft Defender
    print_colored("[1/3] Autenticando no Microsoft Defender...", Colors.YELLOW)
    token = get_defender_access_token()
    if not token:
        print_colored("[ERRO] Falha na autenticação. Encerrando.", Colors.RED)
        return
    
    print_colored("[OK] Autenticação bem-sucedida!", Colors.GREEN)
    print()
    
    # Step 2: Get alerts from Defender
    print_colored("[2/3] Buscando alertas 'New' no Microsoft Defender...", Colors.YELLOW)
    headers = get_defender_headers(token)
    alerts = get_new_alerts_from_defender(headers)
    
    if not alerts:
        print_colored("[INFO] Nenhum alerta 'New' encontrado no Microsoft Defender.", Colors.YELLOW)
        return
    
    print_colored(f"[OK] Encontrados {len(alerts)} alerta(s) com status 'New'", Colors.GREEN)
    print()
    
    # Step 3: Create alerts in IRIS
    print_colored("[3/3] Criando alertas no IRIS...", Colors.YELLOW)
    print()
    
    created_count = 0
    failed_count = 0
    
    for i, alert in enumerate(alerts, 1):
        alert_id = alert.get('id', 'N/A')
        alert_title = alert.get('title', 'N/A')
        
        print_colored(f"[{i}/{len(alerts)}] Processando alerta:", Colors.MAGENTA)
        print_colored(f"  ID: {alert_id}", Colors.WHITE)
        print_colored(f"  Título: {alert_title}", Colors.WHITE)
        print_colored(f"  Severidade: {alert.get('severity', 'N/A')}", Colors.WHITE)
        print_colored(f"  Categoria: {alert.get('category', 'N/A')}", Colors.WHITE)
        
        # Fetch full alert details to get all fields including mitreTechniques
        if alert_id != 'N/A':
            print_colored("  Buscando detalhes completos do alerta...", Colors.GRAY)
            alert_detail = get_alert_story(alert_id, headers)
            if alert_detail:
                # Merge alert detail data into alert (preserve existing data, add missing fields)
                for key, value in alert_detail.items():
                    if key not in alert or not alert.get(key):
                        alert[key] = value
                print_colored("  Detalhes completos obtidos!", Colors.GREEN)
                
                # Debug: mostrar MITRE techniques encontradas
                mitre_techniques = alert.get('mitreTechniques') or alert.get('mitreAttackTechniques') or alert.get('mitreTechniqueIds')
                if mitre_techniques:
                    mitre_str = ', '.join([str(t) for t in mitre_techniques]) if isinstance(mitre_techniques, list) else str(mitre_techniques)
                    print_colored(f"  MITRE ATT&CK encontrado: {mitre_str}", Colors.GREEN)
                else:
                    print_colored("  MITRE ATT&CK não encontrado nos detalhes", Colors.DARK_GRAY)
        
        # Fetch story timeline if not already present
        if 'storyTimeline' not in alert and alert_id != 'N/A':
            print_colored("  Buscando story timeline...", Colors.GRAY)
            story_timeline = get_alert_story_timeline(alert_id, headers)
            if story_timeline:
                alert['storyTimeline'] = story_timeline
                print_colored("  Story timeline encontrado!", Colors.GREEN)
            else:
                print_colored("  Story timeline não disponível", Colors.DARK_GRAY)
        
        # Create alert in IRIS
        iris_alert = create_iris_case(alert)
        
        if iris_alert:
            created_count += 1
        else:
            failed_count += 1
        
        print()
    
    # Summary
    print_colored("=" * 70, Colors.CYAN)
    print_colored("Resumo:", Colors.CYAN)
    print_colored(f"  Total de alertas processados: {len(alerts)}", Colors.WHITE)
    print_colored(f"  Alertas criados no IRIS: {created_count}", Colors.GREEN)
    print_colored(f"  Falhas: {failed_count}", Colors.RED if failed_count > 0 else Colors.WHITE)
    print_colored("=" * 70, Colors.CYAN)

if __name__ == "__main__":
    main()

