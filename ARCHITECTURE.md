# Архитектура 3xui-config-tester

## Назначение

Приложение последовательно проверяет конфигурации inbound в 3x-ui с помощью
локального Xray-клиента. В режиме `clone` исходный inbound используется как
образец и не обновляется. Режим `existing` обновляет исходный inbound во время
эксперимента и требует `inbound.allow_existing: true`.

Адаптер панели ориентирован на 3x-ui v3.8.0 и Xray v26.9.9. Перед запуском
эксперимента он загружает OpenAPI работающей панели и проверяет наличие
используемых путей API. Эта проверка не гарантирует совместимость всех
payload и не проверяет доступность адресов измерений.

## Компоненты

```text
app/web/{__init__,service,handler,server}.py + web_ui.html + static/{api,draft,render}.js + static/app.css (локальный UI)
          |
           app/testing/runner.py
             ├─ parameters/{models,generator,dependencies,compatibility,coverage,mapping}.py
             ├─ inbound/manager.py ── api/base.py ── api/three_xui.py
             ├─ xray/{config_builder,client}.py
             ├─ testing/{search,measurements,network}.py
             ├─ security/masking.py
             ├─ results/writer.py
             └─ state/checkpoint.py
```

| Компонент | Ответственность |
| --- | --- |
| `app/config.py` | Загрузка YAML, подстановка `${ENV_VAR}`, общие настройки эксперимента. |
| `app/api/three_xui.py` | Аутентификация, OpenAPI discovery, запросы к API панели. |
| `app/inbound/manager.py` | Снимок исходного inbound, создание и обновление клона, восстановление или удаление. |
| `app/parameters/` | Валидация параметров, условия, генерация комбинаций и применение JSON path к inbound или client config. |
| `app/xray/` | Построение клиентского конфига, проверка его валидности локальным ядром Xray, запуск и остановка локального Xray. |
| `app/testing/measurements.py` | TCP, ICMP и HTTP-измерения, включая ограниченную загрузку при включённом speed test. |
| `app/testing/search.py` | Чистый adaptive scheduler, exploration quota, active/pending trial и ресурсные бюджеты. |
| `app/testing/network.py` | Наблюдение физического IPv4-маршрута на Windows без изменения маршрутов из Web UI. |
| `app/security/masking.py` | Контекст известных секретов после раскрытия env и чтения панели; redaction строк и структур перед публичными sinks. |
| `app/results/writer.py` | Журнал повторов и производные JSON, CSV, XLSX-файлы; лист `Inbound` повторяет применённый inbound без учётных данных. |
| `app/state/checkpoint.py` | Атомарная запись `state.json` для возобновления. |
| `app/web/` | `service.py` — локальный HTTP API домена (сохранение YAML, фоновый запуск, статус, сводка, история запусков и отчёты); `handler.py` — маршрутизация и раздача страницы/статики; `server.py` — bootstrap, автосоздание `configs/local.yaml` и `main()`. |

Веб панель обслуживается только на `127.0.0.1`. `GET /api/config` удаляет поля
учётных данных из ответа; при сохранении backend возвращает их из исходного
YAML. Каждый запуск пишет в отдельный каталог `output.directory/runs/`.
`GET /api/runs` перечисляет эти каталоги, а скачивание ограничено заданными
именами отчётов и проверенным идентификатором запуска. Панель не имеет
собственной авторизации, поэтому для удалённого доступа нужен SSH-туннель.
Save, preview и run используют один `buildDraft()` в `static/draft.js`.
WebService резервирует запуск под lock до подготовки входных данных. Рабочий
поток управляется явно; shutdown сигнализирует остановку и ждёт cleanup.
Pending recovery после рестарта блокирует новые эксперименты; отдельный
`POST /api/runs/<id>/recover` проверяет panel identity и принадлежность ресурса.

## План и выполнение

1. `load_config` загружает параметры и значения из YAML. Preview плана в Web UI
   строит план локально без обращения к панели.
2. `ExperimentRunner.preflight` проверяет зависимости, аутентификацию,
   обязательные пути OpenAPI, исходный inbound, статус Xray на панели и наличие
   `testing.urls`. Он не отправляет запросы к этим URL. Снимок пишется в приватный
   `.recovery/source-snapshot.json`; для `existing` также сохраняется прежний
   `source-inbound-backup.json`. До первой мутации атомарно записываются очищенные
   `discovery.json` и `preflight.json`, source/core/topology/route context signature.
3. При запуске `InboundManager` создаёт клон или выбирает исходный inbound для
   режима `existing`. Durable manifest до create содержит уникальный marker,
   порт, протокол и `create_pending`: потерянный ответ API не означает, что клон
   не создан. Cleanup сверяет эти признаки и известный ID; неопределённое или
   неоднозначное владение сохраняет `cleanup_pending`.
4. Для каждого повтора runner применяет параметры к базовому payload, строит
   клиентский конфиг и проверяет его до сетевого этапа (см. ниже). Отклонённая
   конфигурация записывается как `SKIPPED` **до** обновления inbound и до
   запуска Xray. Затем runner обновляет тестовый inbound, запускает локальный
   Xray-клиент и измерения. Readback сравнивает ожидаемые inbound-секции и
   вложенные значения, включая WS/gRPC/KCP/XHTTP, TLS/REALITY; client-only пути
   не требуют присутствия в панели. JSON-string sections декодируются;
   произвольные преобразования панели не предполагаются, порядок списков
   не переставляется.
   После каждого повтора он добавляет запись в `results.jsonl`, а затем
   обновляет `state.json`. Неудачные повторы также пишутся в `errors.jsonl`.
5. В блоке `finally` runner пытается восстановить исходный inbound или удалить
   клон, сохраняет checkpoint и создаёт экспортные файлы из журнала.

`pairwise` заранее строит ограниченный план и исправляет пропуски pinned
witnesses: оба значения пары обязаны оставаться активными после normalize.
`exhaustive` использует dependency-aware DFS и не расширяет неактивные домены.
Трёхзначная оценка условий различает false и ещё не назначенный dependency;
циклические условия откладываются и проверяются в конечном состоянии.
`mutation` начинает с базовой конфигурации,
проверяет первое поколение и развивает успешные варианты в следующих
поколениях. Все стратегии ограничиваются `testing.max_combinations`;
`testing.max_failed_runs` может сократить число
повторов отдельной конфигурации.

Seed и neighbor pool для mutation ограничиваются до построения кандидатов:
domain sample ограничен, baseline сохраняется даже за sampled prefix,
`mutate: false` остаётся фиксированным, а отдельный construction budget
ограничивает repair/witness работу. `coverage_metadata` отмечает sampling и
truncation, `unknown_values` не выдаётся за точную оценку при неполной
информации, а `coverage_scope` называет план baseline плюс одиночные изменения.
Лимит соседей передаётся в генератор, поэтому runner не строит полный neighbor
pool перед тем, как его обрезать.

Фиксированные `mutate: false` поля сохраняют baseline во всех стратегиях.
У bounded pairwise есть budgets на witness nodes, общее построение, число
целей и размер семплируемого домена. Feasibility после cutoff остаётся unknown.
`coverage_metadata` отражает реальные активные пары и отдельные значения:
covered, известные feasible/infeasible, unknown, пропущенные feasible,
семплирование и причины ограничения. Raw-count не равен размеру плана и не
учитывает доступность подготовленной инфраструктуры.

`ParameterSpec.from_dict` проверяет конечность значений и числовых границ;
integer диапазоны требуют целые min/max/step и итерируются точными Python
целыми. При нормализации активные JSON paths не могут перекрываться внутри
одного target; пересечение родителя и дочернего поля приводит к явному
`ValueError`. Условия, делающие параметры взаимоисключающими, и разные targets
сохраняют независимую семантику.

Условия для транспорта сопоставляют семантическое имя по JSON path, не меняя
сохранённые значения комбинации: `raw`/`tcp`, `mkcp`/`kcp`,
`websocket`/`ws` и `splithttp`/`xhttp` считаются алиасами. Если в исходном
потоке заданы оба поля, Xray использует `method` раньше `network`. Два активных
пользовательских параметра, одновременно записывающих эти selectors в одном
target, отклоняются как конфликт. Для KCP compatibility допускает `none` и
TLS, но не REALITY; сам транспорт требует UDP на тестовом порту.

## Adaptive policy и уровни проверки

`adaptive` включается отдельным значением стратегии; прежние YAML не получают
новую семантику повторов автоматически. Начальный frontier сочетает явные
transport/security/flow-профили, pair witnesses, ограниченную rescue-подгруппу
троек и независимые joint samples. Нерабочий baseline не прекращает exploration.
Тройной rescue не означает полного 3-way coverage. Scheduler развивает
подтверждённых соседей и сохраняет `exploration_fraction` независимых выборов
при наличии обеих очередей; seen hashes не запускаются как новые кандидаты.

Переходы: local validation → screening → comparison → confirmation → optional
quality. Screening делает один ограниченный HTTP-запрос, comparison — несколько
запросов, confirmation — новые Xray-сессии в заданных окнах. При включённом
`speed_test` скорость замеряется на каждом измеряемом прогоне (comparison,
confirmation, quality) в пределах остатка бюджета трафика после response
allowance; без остатка прогон идёт без замера. Quality добавляет
дополнительную выборку подтверждённым финалистам (не более `speed_finalists`)
сверх уже замеренной скорости. При
одинаковом server payload очередной client-only вариант или повтор использует
кэш readback без лишнего update; клиентская сессия для измерения создаётся заново.

Time, request, response bytes, server applies и различные candidates имеют
отдельные лимиты; client starts учитываются отдельно. Повторы uncertain screening,
небольшой negative resampling и reference checks расходуют бюджет. Reference
проверки идут по системному маршруту машины: при активном VPN они не являются
прямым ISP control. Отказ ресурсов останавливает поиск как
`environment_unavailable`, а не устанавливает причину DPI.

Цели `first_confirmed`, `compare`, `research` отличаются условием ранней
остановки. Результат `confirmed_in_observed_windows` ограничен наблюдавшимися
окнами; он не даёт статистической гарантии долговременной надёжности. Фазы и
fidelity в сводках не смешиваются. Новые ресурсы `confirmation_urls` могут
использоваться отдельно от `testing.urls`; один URL создаёт общий источник
отказов, что отражается в предупреждениях.

Worst-case полный black-box поиск по-прежнему требует Ω(N) проверок. Экономия
ожидается от pruning, bounded exploration и selective promotion; benchmark
проверяет эти механизмы на моделях, а не измеряет ускорение обхода провайдера.

Traffic budget проверяется до следующего измерения по сумме caps фактически
выбранных URL и speed allowance. Полученный целиком HTTP chunk может превысить
sampling cap; счётчик включает overshoot, но не protocol overhead. При потере
частичных метрик из-за тайм-аута journal отмечает `reserved_on_timeout` и
консервативно учитывает зарезервированные запросы и payload allowance.
Прерванное или недовыполненное confirmation window не подтверждает кандидата.
Quality собирает не меньше заданного `min_successful_requests`; его провал
не отменяет ранее наблюдавшуюся достижимость, а фиксирует невыполнение gates
качества отдельно от qualification.

## Проверка клиентских конфигураций

Перед любым сетевым действием клиентский конфиг проверяется в два шага.
`check_client_config` в `app/xray/validation.py` выполняет структурные проверки
без запуска процессов: SOCKS-inbound, протокол outbound, наличие учётных данных,
значения `network` и `security`, совместимость `flow` (`xtls-rprx-vision` только
на TCP с TLS или REALITY), обязательные поля `realitySettings`, `mux`.
`ClientConfigValidator` затем запускает локальный бинарник из
`testing.xray_binary` в режиме `xray run -test -c <файл>`: ядро Xray само
сообщает о неизвестном транспорте или шифре, неверных параметрах REALITY и
недопустимом адресе назначения (например, VLESS без шифрования к публичному
адресу). Команда совпадает с той, которой runner запускает рабочий клиент,
поэтому вердикт соответствует следующему шагу; `-test` не открывает порты и не
выполняет сетевых запросов. Сторонние JSON-схемы конфигов Xray отстают от
версий ядра, поэтому источником истины выбрано само ядро, которое всё равно
требуется для запуска клиента.

Проверка вызывается в `_candidate_error` — до изменения inbound, поэтому
отклонённая конфигурация становится `SKIPPED` с кодом `client_config_*`, — и
повторно в `_one_run` для конфига, прочитанного из панели. Вердикт кэшируется по
эффективному конфигу и идентичности бинарника, а сырой вывод ядра никогда не
сохраняется: в результаты и ошибки попадают только стабильные коды причин.
Готовность бинарника проверяется один раз в preflight (`xray help run` должен
содержать `-test`). По умолчанию проверка обязательна: если бинарника нет, он не
поддерживает `-test`, не отвечает или не запускается, preflight останавливает
прогон до создания или обновления inbound. При ошибке проверки конкретного
конфига этот кандидат не применяется. Только явное `testing.validate_config:
false` оставляет структурную проверку без ядра; `timeouts.xray_config_test`
ограничивает один вызов. Стоимость — один процесс на уникальную пару
«эффективный конфиг + бинарник» (около 30 мс на Xray 26.9.9).

Offline preview не выполняет ни `run -test`, ни пробный inbound, поэтому
обозначается `validation_level: offline`. Успешный `run -test` подтверждает
только, что локальное ядро построило клиентский конфиг. Сквозной результат
появляется только после apply/readback, запуска клиента и сетевых измерений.
Если `help run` прошёл, но последующий `run -test` перестал отвечать, строгий
режим останавливает прогон с коротким кодом причины; неуспешный ответ не
кэшируется.

Сам inbound payload локальным ядром не проверяется: 3x-ui хранит `settings` и
`streamSettings` строками и добавляет собственные поля (`remark`, `enable`,
`expiryTime`, `clientStats`), которые ядро отклонит. Валидность inbound
подтверждает панель, а runner сверяет readback с ожидаемым payload
(`_readback_error`).

Автоматический client builder выбирает первого включённого account. Для legacy
Shadowsocks inbound cipher берётся из `settings.method`, а пароль — из этого
account. Проверка пары SS-2022 пока явно не поддерживается и возвращает
`shadowsocks_2022_pair_validation_unsupported` до изменения inbound.

## Порт и сеть

При запуске тестера на рабочей станции порт API 3x-ui можно пробросить с
сервера по SSH: тогда `panel.url` указывает на локальный конец туннеля.
Туннель передаёт только запросы управления к панели. Тестовый Xray-клиент
подключается отдельно к `testing.server_address` и порту тестового inbound;
для этих измерений требуется собственный сетевой маршрут.

Если задан `inbound.test_port`, менеджер проверяет, не занят ли он другим
inbound в панели. Иначе он берёт первый локально свободный порт из
`testing.ports` **на машине запуска тестера**; это список, а не интервал, потому
что открытые в firewall порты редко идут подряд. Порты, которые панель уже
слушает (включая исходный inbound), пропускаются: 3x-ui примет конфиг, но Xray
не забиндит порт, и копия не поднимется. `testing.port_range: [низ,
верх]` — прежняя форма, разворачивается в непрерывный интервал, если
`testing.ports` не задан. В Web UI поле «Порты тестовой копии» принимает список
через запятую («24443, 24500») или интервал («20000-21000») и пишет
соответствующий ключ. Для удалённой панели проверка не доказывает, что порт
свободен на сервере или открыт в firewall: перечисляйте только открытые порты.
Итоговую доступность определяют создание inbound и реальные измерения.
KCP/mKCP дополнительно требует доступного UDP на тестовом порту.

Клиентский конфиг использует `testing.server_address`; если поле не задано,
берётся hostname из `panel.url`. При reverse proxy и отдельном адресе Xray
задавайте `server_address` явно. HTTP-измерения идут через локальный SOCKS
Xray к адресам из `testing.urls`. ICMP-проверка идёт к адресу сервера и не
проходит через SOCKS.

Для единственного открытого серверного порта 9443 задаются
`inbound.test_port: 9443`, `testing.ports: [9443]`. Executor один: несколько
кандидатов не переустанавливают общий inbound одновременно. Диапазон портов
не включает параллелизм. UDP-инфраструктура для KCP проверяется отдельно.

`inbound.topology: direct` по умолчанию нормализует `acceptProxyProtocol: false`
у clone в sockopt и поддержанных transport sections. Нормализация применяется
до client validation, update, payload hash и readback. Direct clone получает
`listen: ""` — стандартный сетевой listener панели/Xray вместо унаследованного
loopback, конкретного интерфейса или Unix socket. Внешняя доступность всё равно
требует открытого выбранного порта и корректного firewall. Каждый clone имеет
`enable: true`, даже если source выключен. В `reverse_proxy` сохраняются исходный
listener и PROXY protocol; `existing` сохраняет также исходное `enable`.
Reverse-proxy profile требует
подготовленной схемы forwarding/TLS/PROXY; менеджер её не создаёт. Source snapshot
остаётся неизменным при direct clone.

`tools/Set-TesterDirectRoute.ps1` — отдельный операторский помощник для Windows:
Check наблюдает маршрут, Apply создаёт временные IPv4 `/32` routes через
активный физический gateway, Remove использует ledger созданных записей.
Глобальный default route VPN не меняется. Ledger и агрегированный status лежат
в `results/.network/`; адреса/gateway не нужны Web UI. Apply/Remove требуют
повышенных прав. `testing.require_direct_route` — optional preflight gate;
на Linux такой автоматической проверки нет. Физический маршрут сам по себе
не подтверждает сквозной туннель.

## Данные и восстановление

`results.jsonl` — основной журнал завершённых повторов. `state.json` хранит
метаданные эксперимента и ключи `<configuration-hash>:<run-number>`.
Hash прежних configuration values сохранён; phase/fidelity не добавляются
в него. Run-number монотонно растёт и при переходе screening → validation.
Adaptive records schema 2 дополнительно содержат policy version, phase,
fidelity/rung, profile id, qualification, selection reason, context signature,
environment epoch, effective configuration/server payload hashes, duration и
API/client/request/traffic counters. Старые записи читаются как `search`/`full`.
Метрики агрегируются по `(phase, fidelity, environment_epoch, hash)`.
Каждый запуск Web UI пишет в собственный каталог `output.directory/runs/`.
CSV, JSON-массив и XLSX пересоздаются из журнала по `output.formats`.
Рядом лежат диагностические файлы: `client-xray.log` — маскированный хвост лога
локального клиента Xray по неудачным кандидатам (в нём называется причина
провала рукопожатия, если она распознана; `client_xray_diagnostics` передаёт коды),
и `run-error.txt` — причина падения самого прогона до создания копии.

Checkpoint schema 2 хранит scheduler frontier/exploitation, seen и active/pending
trial, exploration selections, viable/confirmed, seed, policy version,
coverage и использованные бюджеты. Перед попыткой фиксируется pending trial,
затем дописывается журнал с flush/fsync, затем checkpoint завершённого ключа.
Runner resume восстанавливает завершённые JSONL-записи после crash между append
и checkpoint и отвергает изменённые search/context signatures или policy.
Бюджетные лимиты (`testing.max_combinations` и `testing.adaptive.*_budget`) в search
signature не входят: `POST /api/runs/<id>/continue` продолжает прогон, остановившийся
на `budget_exhausted`, в том же каталоге и чекпойнте. Переносятся счётчики бюджета,
frontier/exploitation, viable/confirmed и validated/screened pairs, а копия
поднимается заново обычным preflight/prepare; любое небюджетное изменение
конфигурации по-прежнему отвергается.
Web UI recovery восстанавливает ресурсы, а новый эксперимент создаёт новый журнал.
Reader JSONL учитывает только завершённые строки; partial tail дополняется
ровно один раз, а не дублируется при следующем poll.

Приватная `.recovery/` содержит полный `source-snapshot.json` и manifest
`inbound-recovery.json`. Downloads разрешают только публичные отчёты,
очищенные discovery/preflight и `recovery-status.json`; snapshot, checkpoint,
runtime/client config и REALITY credentials в allowlist не входят. Контекст
redactor регистрирует известные секреты до публикации строк, исключений и
артефактов. На Windows права `0600` не заменяют проверку ACL.

При штатной остановке runner делает cleanup. Аварийное прекращение процесса,
сбой сети или ошибка cleanup могут оставить тестовый inbound на панели.
Клоны имеют уникальную метку `[3xui-config-tester:...]` в `remark`. В режиме
`existing` файл `source-inbound-backup.json` также содержит полный payload исходного
inbound; его нужно защищать как секрет. На Ubuntu приватным файлам выставляются
права `0600`. При проверке на Windows используйте ACL файловой системы.
Новый эксперимент блокируется, пока pending cleanup не восстановлен. При
потерянной panel identity в старом checkpoint или изменённой ownership автоматическое
удаление запрещается; требуется ручное сопоставление ресурса. Ошибка recovery
остаётся pending и не выдаётся за успешную очистку.
