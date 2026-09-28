"""Versioned parameter catalogue for the local experiment builder.

The panel OpenAPI describes the HTTP endpoints, but 3x-ui stores most Xray
settings as JSON objects.  Consequently the selectable values come from the
official Xray/3x-ui schemas, while ``current`` values are read from the live
source inbound through the panel API.
"""
from __future__ import annotations

import copy
import json
from typing import Any


def _p(title: str, group: str, kind: str, values: list[Any], path: list[str | int], *,
       help: str, target: str = "inbound", conditions: dict[str, Any] | None = None,
       value_conditions: list[dict[str, Any]] | None = None,
       source_path: list[str | int] | None = None, warning: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {
        "title": title, "group": group, "type": kind, "values": values,
        "path": path, "target": target, "help": help,
    }
    if conditions:
        result["conditions"] = conditions
    if value_conditions:
        result["value_conditions"] = value_conditions
    if source_path:
        result["source_path"] = source_path
    if warning:
        result["warning"] = warning
    return result


NETWORK = {"network": {"in": ["tcp", "kcp", "ws", "grpc", "httpupgrade", "xhttp"]}}
TLS = {"security": {"equals": "tls"}}
REALITY = {"security": {"equals": "reality"}}
MUX_ON = {"mux_enabled": {"equals": True}}


# Values mirror 3x-ui's inbound form and Xray 26.9.x. Free-form fields contain
# useful seeds; the browser also permits arbitrary additional values.
PARAMETERS: dict[str, dict[str, Any]] = {
    "network": _p("Транспорт / сеть", "Основные", "enum",
        ["tcp", "kcp", "ws", "grpc", "httpupgrade", "xhttp"],
        ["streamSettings", "network"], help="Все варианты транспорта Xray 26.9.x для VLESS."),
    "security": _p("Защита транспорта", "Основные", "enum", ["none", "tls", "reality"],
        ["streamSettings", "security"], help="Без защиты, TLS или REALITY.",
        value_conditions=[
            {"value": "tls", "conditions": {"any": [
                {"parameter": "network", "exists": False},
                {"parameter": "network", "in": ["tcp", "ws", "grpc", "httpupgrade", "xhttp"]},
            ]}},
            {"value": "reality", "conditions": {"any": [
                {"parameter": "network", "exists": False},
                {"parameter": "network", "in": ["tcp", "grpc", "xhttp"]},
            ]}},
        ]),
    "vless_flow": _p("Поток VLESS", "Основные", "enum", ["", "xtls-rprx-vision"],
        ["settings", "clients", 0, "flow"], help="XTLS Vision доступен для RAW с TLS/REALITY.",
        conditions={"all": [{"parameter": "network", "equals": "tcp"},
                            {"parameter": "security", "in": ["tls", "reality"]}]}),

    "tls_min_version": _p("Минимальная версия TLS", "TLS", "enum", ["1.0", "1.1", "1.2", "1.3"],
        ["streamSettings", "tlsSettings", "minVersion"], help="Минимальная разрешённая версия TLS.", conditions={"security": {"equals": "tls"}}),
    "tls_max_version": _p("Максимальная версия TLS", "TLS", "enum", ["1.0", "1.1", "1.2", "1.3"],
        ["streamSettings", "tlsSettings", "maxVersion"], help="Максимальная разрешённая версия TLS.", conditions={"security": {"equals": "tls"}}),
    "tls_alpn": _p("TLS ALPN", "TLS", "enum",
        [["h2", "http/1.1"], ["h2"], ["http/1.1"], []],
        ["streamSettings", "tlsSettings", "alpn"], help="Для gRPC требуется h2; ALPN передаётся как JSON-массив.",
        conditions={"security": {"equals": "tls"}}, value_conditions=[
            {"value": ["h2"], "conditions": {"network": {"not_in": ["ws", "httpupgrade"]}}},
            {"value": ["http/1.1"], "conditions": {"network": {"not_equals": "grpc"}}},
            {"value": [], "conditions": {"network": {"not_equals": "grpc"}}},
        ]),
    "tls_reject_unknown_sni": _p("Отклонять неизвестный SNI", "TLS", "boolean", [False, True],
        ["streamSettings", "tlsSettings", "rejectUnknownSni"], help="Отклонять SNI, отсутствующий в сертификатах.", conditions={"security": {"equals": "tls"}}),
    "tls_disable_system_root": _p("Не использовать системные корневые сертификаты", "TLS", "boolean", [False, True],
        ["streamSettings", "tlsSettings", "disableSystemRoot"], help="Не использовать системное хранилище CA.", conditions={"security": {"equals": "tls"}}),
    "tls_session_resumption": _p("Возобновление TLS-сессии", "TLS", "boolean", [False, True],
        ["streamSettings", "tlsSettings", "enableSessionResumption"], help="Возобновление TLS-сессий.", conditions={"security": {"equals": "tls"}}),
    "tls_fingerprint": _p("Отпечаток uTLS для TLS", "Клиент TLS", "enum",
        ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn", "unsafe"],
        ["outbounds", 0, "streamSettings", "tlsSettings", "fingerprint"], target="client",
        source_path=["streamSettings", "tlsSettings", "settings", "fingerprint"],
        help="Полный набор встроенных отпечатков Xray для TLS-клиента.", conditions=TLS),
    "reality_fingerprint": _p("Отпечаток uTLS для REALITY", "Клиент REALITY", "enum",
        ["chrome", "firefox", "safari", "ios", "android", "edge", "360", "qq", "random", "randomized", "randomizednoalpn"],
        ["outbounds", 0, "streamSettings", "realitySettings", "fingerprint"], target="client",
        source_path=["streamSettings", "realitySettings", "settings", "fingerprint"],
        help="Отпечаток TLS-клиента для REALITY.", conditions=REALITY),
    "tls_allow_insecure": _p("Разрешить недоверенный сертификат", "Клиент TLS / REALITY", "boolean", [False, True],
        ["outbounds", 0, "streamSettings", "tlsSettings", "allowInsecure"], target="client",
        help="Отключает стандартную проверку сертификата клиента.", conditions={"security": {"equals": "tls"}},
        warning="Используйте только для диагностического теста."),
    "tls_server_name": _p("SNI клиента", "Клиент TLS / REALITY", "string", ["example.com", ""],
        ["outbounds", 0, "streamSettings", "tlsSettings", "serverName"], target="client",
        source_path=["streamSettings", "tlsSettings", "serverName"], help="SNI локального Xray-клиента.", conditions=TLS),
    "reality_server_name": _p("SNI клиента REALITY", "Клиент REALITY", "string", ["", "example.com"],
        ["outbounds", 0, "streamSettings", "realitySettings", "serverName"], target="client",
        source_path=["streamSettings", "realitySettings", "settings", "serverName"],
        help="Имя сервера, которое клиент REALITY отправляет в TLS ClientHello.", conditions=REALITY),
    "reality_spider_x": _p("Путь spiderX", "Клиент REALITY", "string", ["/", "/robots.txt", "/favicon.ico"],
        ["outbounds", 0, "streamSettings", "realitySettings", "spiderX"], target="client",
        source_path=["streamSettings", "realitySettings", "settings", "spiderX"],
        help="Начальный путь обхода REALITY; рекомендуется различать клиентов.", conditions=REALITY),
    "reality_max_time_diff": _p("Допуск времени REALITY, мс", "REALITY", "integer", [0, 30000, 60000, 120000],
        ["streamSettings", "realitySettings", "maxTimeDiff"],
        help="Максимальное расхождение времени клиента и сервера; 0 отключает проверку.", conditions=REALITY),
    "tls_verify_peer_name": _p("Проверять сертификат по имени", "Клиент TLS / REALITY", "string", ["example.com", ""],
        ["outbounds", 0, "streamSettings", "tlsSettings", "verifyPeerCertByName"], target="client",
        source_path=["streamSettings", "tlsSettings", "settings", "verifyPeerCertByName"],
        help="Имя, по которому Xray проверяет сертификат удалённой стороны.", conditions={"security": {"equals": "tls"}}),

    "tcp_header": _p("Тип заголовка RAW", "RAW / TCP", "enum", ["none", "http"],
        ["streamSettings", "tcpSettings", "header", "type"], help="Без маскировки или с маскировкой под HTTP/1.1.", conditions={"network": {"equals": "tcp"}}),
    "tcp_accept_proxy_protocol": _p("Принимать PROXY protocol в RAW", "RAW / TCP", "boolean", [False, True],
        ["streamSettings", "tcpSettings", "acceptProxyProtocol"], help="Принимать PROXY protocol от вышестоящего узла.", conditions={"network": {"equals": "tcp"}}),

    "kcp_mtu": _p("mKCP MTU", "mKCP", "integer", [576, 1200, 1350, 1400, 1460],
        ["streamSettings", "kcpSettings", "mtu"], help="Допустимый Xray диапазон 576–1460.", conditions={"network": {"equals": "kcp"}}),
    "kcp_tti": _p("mKCP TTI (ms)", "mKCP", "integer", [10, 20, 30, 50, 100],
        ["streamSettings", "kcpSettings", "tti"], help="Допустимый диапазон 10–100 мс.", conditions={"network": {"equals": "kcp"}}),
    "kcp_uplink_capacity": _p("Скорость отправки mKCP, МБ/с", "mKCP", "integer", [0, 5, 10, 20, 50, 100],
        ["streamSettings", "kcpSettings", "uplinkCapacity"], help="Пропускная способность отправки.", conditions={"network": {"equals": "kcp"}}),
    "kcp_downlink_capacity": _p("Скорость приёма mKCP, МБ/с", "mKCP", "integer", [0, 20, 50, 100, 200],
        ["streamSettings", "kcpSettings", "downlinkCapacity"], help="Пропускная способность приёма.", conditions={"network": {"equals": "kcp"}}),
    "kcp_cwnd_multiplier": _p("Множитель окна перегрузки mKCP", "mKCP", "integer", [1, 2, 4, 8],
        ["streamSettings", "kcpSettings", "cwndMultiplier"], help="Множитель окна перегрузки; минимум 1.", conditions={"network": {"equals": "kcp"}}),
    "kcp_max_sending_window": _p("Максимальное окно отправки mKCP", "mKCP", "integer", [65536, 262144, 1048576, 2097152, 4194304],
        ["streamSettings", "kcpSettings", "maxSendingWindow"], help="Максимальное окно отправки в байтах.", conditions={"network": {"equals": "kcp"}}),

    "ws_path": _p("Путь WebSocket", "WebSocket", "string", ["/", "/ws", "/api"],
        ["streamSettings", "wsSettings", "path"], help="Путь WebSocket; можно добавить свой.", conditions={"network": {"equals": "ws"}}),
    "ws_host": _p("Заголовок Host WebSocket", "WebSocket", "string", ["", "example.com"],
        ["streamSettings", "wsSettings", "host"], help="Переопределение Host за CDN или обратным прокси.", conditions={"network": {"equals": "ws"}}),
    "ws_heartbeat": _p("Интервал heartbeat WebSocket", "WebSocket", "integer", [0, 10, 30, 60],
        ["streamSettings", "wsSettings", "heartbeatPeriod"], help="В секундах; 0 отключает heartbeat.", conditions={"network": {"equals": "ws"}}),
    "ws_accept_proxy_protocol": _p("Принимать PROXY protocol в WebSocket", "WebSocket", "boolean", [False, True],
        ["streamSettings", "wsSettings", "acceptProxyProtocol"], help="Принимать PROXY protocol.", conditions={"network": {"equals": "ws"}}),

    "grpc_service_name": _p("Имя службы gRPC", "gRPC", "string", ["", "grpc", "vless", "proxy"],
        ["streamSettings", "grpcSettings", "serviceName"], help="Секретный путь службы.", conditions={"network": {"equals": "grpc"}}),
    "grpc_authority": _p("Значение authority gRPC", "gRPC", "string", ["", "example.com"],
        ["streamSettings", "grpcSettings", "authority"], help="Переопределение HTTP/2 :authority.", conditions={"network": {"equals": "grpc"}}),
    "grpc_multi_mode": _p("Многопоточный режим gRPC", "gRPC", "boolean", [False, True],
        ["streamSettings", "grpcSettings", "multiMode"], help="Несколько потоков в одном соединении.", conditions={"network": {"equals": "grpc"}}),

    "httpupgrade_path": _p("Путь HTTPUpgrade", "HTTPUpgrade", "string", ["/", "/up", "/api"],
        ["streamSettings", "httpupgradeSettings", "path"], help="Путь HTTP Upgrade.", conditions={"network": {"equals": "httpupgrade"}}),
    "httpupgrade_host": _p("Заголовок Host HTTPUpgrade", "HTTPUpgrade", "string", ["", "example.com"],
        ["streamSettings", "httpupgradeSettings", "host"], help="Переопределение Host.", conditions={"network": {"equals": "httpupgrade"}}),
    "httpupgrade_accept_proxy_protocol": _p("Принимать PROXY protocol в HTTPUpgrade", "HTTPUpgrade", "boolean", [False, True],
        ["streamSettings", "httpupgradeSettings", "acceptProxyProtocol"], help="Принимать PROXY protocol.", conditions={"network": {"equals": "httpupgrade"}}),

    "xhttp_path": _p("Путь XHTTP", "XHTTP", "string", ["/", "/xhttp", "/api"],
        ["streamSettings", "xhttpSettings", "path"], help="Путь XHTTP.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_host": _p("Заголовок Host XHTTP", "XHTTP", "string", ["", "example.com"],
        ["streamSettings", "xhttpSettings", "host"], help="Переопределение Host.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_mode": _p("Режим XHTTP", "XHTTP", "enum", ["auto", "packet-up", "stream-up", "stream-one"],
        ["streamSettings", "xhttpSettings", "mode"], help="Все режимы XHTTP, доступные в 3x-ui.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_padding_bytes": _p("Размер заполнения XHTTP", "XHTTP", "string", ["100-1000", "0", "100-500", "500-1500"],
        ["streamSettings", "xhttpSettings", "xPaddingBytes"], help="Диапазон заполнения; допускается собственное выражение.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_uplink_method": _p("Метод отправки XHTTP", "XHTTP", "enum", ["", "POST", "PUT", "GET"],
        ["streamSettings", "xhttpSettings", "uplinkHTTPMethod"], help="GET применим только к packet-up.", conditions={"network": {"equals": "xhttp"}},
        value_conditions=[{"value": "GET", "conditions": {"any": [
            {"parameter": "xhttp_mode", "exists": False}, {"parameter": "xhttp_mode", "equals": "packet-up"}]}}]),
    "xhttp_no_sse_header": _p("Не отправлять заголовок SSE в XHTTP", "XHTTP", "boolean", [False, True],
        ["streamSettings", "xhttpSettings", "noSSEHeader"], help="Не отправлять заголовок SSE.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_max_buffered_posts": _p("Максимум буферизованных POST в XHTTP", "XHTTP", "integer", [0, 1, 10, 30, 64],
        ["streamSettings", "xhttpSettings", "scMaxBufferedPosts"], help="Максимум буферизованных POST.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_server_max_header_bytes": _p("Максимальный размер заголовка XHTTP", "XHTTP", "integer", [0, 4096, 8192, 16384, 32768],
        ["streamSettings", "xhttpSettings", "serverMaxHeaderBytes"], help="0 использует значение Xray по умолчанию.", conditions={"network": {"equals": "xhttp"}}),
    "xhttp_stream_up_secs": _p("Окно stream-up XHTTP", "XHTTP", "string", ["20-80", "10-30", "60-120"],
        ["streamSettings", "xhttpSettings", "scStreamUpServerSecs"],
        help="Диапазон секунд серверного окна stream-up.",
        conditions={"all": [{"network": {"equals": "xhttp"}}, {"xhttp_mode": {"equals": "stream-up"}}]}),
    "xhttp_each_post_bytes": _p("Лимит POST XHTTP", "XHTTP", "string", ["", "262144", "1048576", "524288-1048576"],
        ["streamSettings", "xhttpSettings", "scMaxEachPostBytes"],
        help="Размер одного POST; пустое значение оставляет значение Xray.",
        conditions={"all": [{"network": {"equals": "xhttp"}}, {"xhttp_mode": {"in": ["auto", "packet-up"]}}]}),
    "xhttp_post_interval": _p("Интервал POST XHTTP, мс", "XHTTP", "string", ["", "50-150", "100-300"],
        ["streamSettings", "xhttpSettings", "scMinPostsIntervalMs"],
        help="Интервал POST; пустое значение оставляет значение Xray.",
        conditions={"all": [{"network": {"equals": "xhttp"}}, {"xhttp_mode": {"in": ["auto", "packet-up"]}}]}),
    "xhttp_xmux": _p("Профиль XMUX", "XHTTP", "enum",
        [{"maxConcurrency": "16-32", "maxConnections": 0},
         {"maxConcurrency": "", "maxConnections": 6}],
        ["outbounds", 0, "streamSettings", "xhttpSettings", "xmux"], target="client",
        source_path=["streamSettings", "xhttpSettings", "xmux"],
        help="Взаимоисключающие стратегии XMUX; отсутствие параметра оставляет XMUX выключенным.",
        conditions={"network": {"equals": "xhttp"}}),

    "sockopt_tcp_fast_open": _p("Быстрое открытие TCP", "Параметры сокета", "boolean", [False, True],
        ["streamSettings", "sockopt", "tcpFastOpen"], help="TCP Fast Open для транспортного сокета.", conditions=NETWORK),
    "sockopt_tcp_congestion": _p("Управление перегрузкой TCP", "Параметры сокета", "enum", ["", "bbr", "cubic", "reno"],
        ["streamSettings", "sockopt", "tcpcongestion"], help="Алгоритм управления перегрузкой, если доступен в ОС.", conditions=NETWORK),
    "sockopt_domain_strategy": _p("Стратегия разрешения доменов", "Параметры сокета", "enum",
        ["AsIs", "UseIP", "UseIPv6v4", "UseIPv6", "UseIPv4v6", "UseIPv4", "ForceIP", "ForceIPv6v4", "ForceIPv6", "ForceIPv4v6", "ForceIPv4"],
        ["streamSettings", "sockopt", "domainStrategy"], help="Полный набор стратегий резолвинга Xray.", conditions=NETWORK),
    "sockopt_tproxy": _p("Режим TProxy", "Параметры сокета", "enum", ["off", "redirect", "tproxy"],
        ["streamSettings", "sockopt", "tproxy"], help="Режим прозрачного прокси.", conditions=NETWORK),
    "sockopt_accept_proxy_protocol": _p("Принимать PROXY protocol в сокете", "Параметры сокета", "boolean", [False, True],
        ["streamSettings", "sockopt", "acceptProxyProtocol"], help="Общий переключатель PROXY protocol.", conditions=NETWORK),
    "sockopt_penetrate": _p("Проникновение сокета", "Параметры сокета", "boolean", [False, True],
        ["streamSettings", "sockopt", "penetrate"], help="Параметр Xray для проникновения сокета.", conditions=NETWORK),
    "sockopt_v6_only": _p("Только IPv6", "Параметры сокета", "boolean", [False, True],
        ["streamSettings", "sockopt", "V6Only"], help="IPV6_V6ONLY для прослушивающего сокета.", conditions=NETWORK),
    "sockopt_tcp_user_timeout": _p("Пользовательский тайм-аут TCP, мс", "Параметры сокета", "integer", [0, 5000, 10000, 30000, 60000],
        ["streamSettings", "sockopt", "tcpUserTimeout"], help="0 оставляет системное значение.", conditions=NETWORK),
    "sockopt_tcp_window_clamp": _p("Ограничение окна TCP", "Параметры сокета", "integer", [0, 65535, 262144, 1048576],
        ["streamSettings", "sockopt", "tcpWindowClamp"], help="0 оставляет системное значение.", conditions=NETWORK),

    "mux_enabled": _p("Mux клиента", "Клиент Mux / XUDP", "boolean", [False, True],
        ["outbounds", 0, "mux", "enabled"], target="client", help="Mux включается только на локальном клиенте."),
    "mux_concurrency": _p("Параллельность Mux", "Клиент Mux / XUDP", "integer", [-1, 0, 1, 4, 8, 16, 32, 64, 128],
        ["outbounds", 0, "mux", "concurrency"], target="client", help="-1 отключает Mux для TCP, 0 использует значение по умолчанию 8, предел 128.", conditions=MUX_ON),
    "mux_xudp_concurrency": _p("Параллельность XUDP", "Клиент Mux / XUDP", "integer", [-1, 0, 1, 8, 16, 32, 64, 128, 256, 512, 1024],
        ["outbounds", 0, "mux", "xudpConcurrency"], target="client", help="-1 отключает XUDP, 0 следует настройке TCP, предел 1024.", conditions=MUX_ON),
    "mux_udp443": _p("Обработка XUDP UDP/443", "Клиент Mux / XUDP", "enum", ["reject", "allow", "skip"],
        ["outbounds", 0, "mux", "xudpProxyUDP443"], target="client", help="Обработка QUIC/UDP 443 в Mux.", conditions=MUX_ON),

    "sniffing_enabled": _p("Анализ протокола", "Анализ протокола", "boolean", [False, True],
        ["sniffing", "enabled"], help="Определение протокола назначения."),
    "sniffing_dest_override": _p("Переопределение назначения анализом", "Анализ протокола", "enum",
        [[], ["http"], ["tls"], ["quic"], ["http", "tls"], ["http", "tls", "quic", "fakedns"]],
        ["sniffing", "destOverride"], help="Наборы протоколов для переопределения назначения.", conditions={"sniffing_enabled": {"equals": True}}),
    "sniffing_metadata_only": _p("Анализировать только метаданные", "Анализ протокола", "boolean", [False, True],
        ["sniffing", "metadataOnly"], help="Анализировать только метаданные.", conditions={"sniffing_enabled": {"equals": True}}),
    "sniffing_route_only": _p("Использовать анализ только для маршрутизации", "Анализ протокола", "boolean", [False, True],
        ["sniffing", "routeOnly"], help="Использовать определённое назначение только для маршрутизации.", conditions={"sniffing_enabled": {"equals": True}}),
}


def _decode_sections(source: dict[str, Any]) -> dict[str, Any]:
    result = copy.deepcopy(source)
    for key in ("settings", "streamSettings", "sniffing"):
        value = result.get(key)
        if isinstance(value, str):
            try:
                result[key] = json.loads(value)
            except json.JSONDecodeError:
                pass
    return result


def _lookup(source: dict[str, Any], path: list[str | int]) -> tuple[bool, Any]:
    value: Any = source
    for part in path:
        try:
            value = value[part] if isinstance(part, int) else value[part]
        except (KeyError, IndexError, TypeError):
            return False, None
    return True, value


def parameter_registry(source: dict[str, Any] | None = None, *, panel_version: str | None = None,
                       xray_version: str | None = None, live_error: str | None = None) -> dict[str, Any]:
    parameters = copy.deepcopy(PARAMETERS)
    if source:
        decoded = _decode_sections(source)
        for spec in parameters.values():
            path = spec.get("source_path", spec["path"])
            found, value = _lookup(decoded, path)
            if found:
                spec["current"] = value
    result: dict[str, Any] = {
        "schema_version": 1,
        "compatibility": {
            "three_xui": panel_version or "3.8.x",
            "xray": xray_version or "26.9.x",
            "security_by_transport": {
                "tcp": ["none", "tls", "reality"], "kcp": ["none"],
                "ws": ["none", "tls"], "grpc": ["none", "tls", "reality"],
                "httpupgrade": ["none", "tls"], "xhttp": ["none", "tls", "reality"],
            },
            "all_xray_inbound_protocols": ["tunnel", "http", "shadowsocks", "socks", "trojan", "vless", "vmess", "wireguard", "hysteria", "tun"],
            "runner_client_protocols": ["vless", "vmess", "trojan", "shadowsocks"],
        },
        "sources": [
            "https://xtls.github.io/en/config/transport.html",
            "https://xtls.github.io/en/config/transports/tls.html",
            "https://xtls.github.io/en/config/transports/reality.html",
            "https://xtls.github.io/en/config/outbound.html",
            "https://github.com/MHSanaei/3x-ui/blob/main/docs/content/docs/en/config/transports.mdx",
            "https://github.com/MHSanaei/3x-ui/blob/main/frontend/src/schemas/protocols/stream/xhttp.ts",
        ],
        "parameters": parameters,
    }
    if source:
        result["source_inbound"] = {key: source.get(key) for key in ("id", "remark", "protocol", "port", "enable")}
    if live_error:
        result["live_error"] = live_error
    return result
