import re
from org.zaproxy.zap.extension.pscan import PluginPassiveScanner
from org.zaproxy.addon.commonlib.scanrules import ScanRuleMetadata

def getMetadata():
    # 1) Каждый скрипт, который представлен как правило сканирования должен иметь уникальный идентификатор, в противном случае он не будет загружен. 
    # Полный список идентификаторов сканирований и скриптов, хранятся в файле scanners.md( https://github.com/zaproxy/zaproxy/blob/main/docs/scanners.md ), в основном репозитории ZAP.
    # Обратите внимание - в ZAP уже есть правило с именем "Cookie set without HttpOnly flag" под идентификатором 10010, тем не менее ничто нам не мешает создать альтернативное правило но под другим идентификатором.
    # 2) Полный список полей вы сможете найти тут - https://github.com/zaproxy/zap-extensions/blob/839d5c7df7432c1f4748275daacd1d4e8812a51a/addOns/commonlib/src/main/java/org/zaproxy/addon/commonlib/scanrules/ScanRuleMetadata.java#L44
    return ScanRuleMetadata.fromYaml("""
id: 100010
name: Cookie set without HttpOnly flag
description: >
    Verify that cookie-based session tokens have the 'HttpOnly' attribute set.
solution: Add 'HttpOnly' attribute when sending cookie.
risk: high
confidence: low
cweId: 1004
status: alpha
references:
  - https://owasp.org/www-project-proactive-controls/#div-numbering
  - https://owasp.org/www-community/HttpOnly
  - https://cwe.mitre.org/data/definitions/1004.html
""")

def appliesToHistoryType(historyType):
  """
    Явно указываем что срикпт будет обрабатывать только проксируемый трафик и активными сканированиями. 
    Предлагаемиый скрипт не будет работать в модулях по типу Spider. Хотя вы можете это изменить....
  """
  from org.parosproxy.paros.model import HistoryReference as hr   
    
  return historyType in [hr.TYPE_PROXIED, hr.TYPE_SCANNER_TEMPORARY]


def scan(helper, msg, src):
  """
    Метод вдохнавлён скрпитами:
        https://github.com/BlazingWind/OWASP-ASVS-4.0-testing-guide/blob/main/ZAP-scripts/passive/3-4-2-cookie-httponly-attribute.py
        https://github.com/zaproxy/community-scripts/blob/main/passive/CookieHTTPOnly.js
  """
  set_cookie = msg.getResponseHeader().getHeaders("Set-Cookie")
  re_noflag = r"([Hh][Tt][Tt][Pp][Oo][Nn][Ll][Yy])";

  if set_cookie != None:
      # getHeaders возвращает класс Vector, как с ним работать описано тут - https://proglang.su/java/vector-class
      vEnum = set_cookie.elements()
      while(vEnum.hasMoreElements()):
          cookie = str(vEnum.nextElement())
          is_httpOnly = re.search(re_noflag, cookie)

          if(is_httpOnly == None):
            helper.newAlert().setMessage(msg).setEvidence(cookie).raise()
