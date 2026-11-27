# shadowtunnel-proxy

Портативный многохоповый прокси и VPN (`HTTP/HTTPS`, `SOCKS5 + UDP`, `Linux L3 TUN`) на базе **ShadowTunnel** без единой внешней зависимости (только встроенные модули Node.js ≥ 20 и штатные средства ОС).

Поддерживает **произвольное количество промежуточных ретрансляторов (`0..N`)**, расширяемую систему режимов маршрутизации (`modes/onion.mjs`, `modes/ptp.mjs` + регистрация своих плагинов через `registerMode`), маскировку под HTTPS/WebSocket (`wss://` + `--fallback`) и **мультиплексирование потоков и датаграмм по умолчанию** (пул прогретых постоянных цепочек `--pool 2` с автопереподключением и ротацией сессионных ключей).

---

## Модульная структура

- `modes/` — подключаемые режимы построения цепочек (`onion.mjs`, `ptp.mjs`, реестр `modes/index.mjs`).
- `ingress/` — входные адаптеры (`ingress/http.mjs`, `ingress/socks5.mjs`, `ingress/tun.mjs`), разделяющие общий пул каналов `MuxCircuitPool`.
- `relay.mjs` / `exit.mjs` / `pool.mjs` — сервер-репитер, выходной узел (TCP + UDP + TUN/NAT) и пул мультиплексированных каналов.
- `crypto.mjs` / `transport.mjs` / `tunnel.mjs` / `mux.mjs` — базовые модули ядра **ShadowTunnel**.

---

## Режимы работы (`--mode`)

| Характеристика | `--mode onion` (Матрёшка) | `--mode ptp` (Point-to-Point) |
|---|---|---|
| **Шифрование** | Вложенное сквозное (`N+1` слоёв от Клиента до Exit) | 1 слой `AES-256-GCM` на каждом плече (перешифровка на репитере) |
| **Что видит репитер** | Только шифротекст и следующий `IP:порт` | Следующий хоп и внутренний поток (для HTTPS данные сайта всё равно закрыты TLS) |
| **Кто авторизуется на Exit** | Ключ самого **Клиента** (`client.pub`) | Ключ **последнего репитера** (`rN.pub`) |
| **Задержка и накладные расходы** | Растут с числом хопов на клиенте | Минимальные и линейные при любом числе хопов |
| **Задание маршрута** | Клиент задаёт весь список `--hop` | Либо клиент задаёт `--hop` (**Dynamic PTP**), либо знает только 1-й узел, а репитеры связаны флагом `--next` (**Static PTP**) |

Репитер с `--mode both` (по умолчанию) умеет одновременно обслуживать и `onion`, и динамические `ptp` подключения на одном порту. При указании `-m onion` или `-m ptp` узел разрешает только выбранный режим.

---

## Быстрый старт

### 1. Генерация ключей
```bash
node cli.mjs keygen -o ./keys/r1 -n relay-1
node cli.mjs keygen -o ./keys/r2 -n relay-2
node cli.mjs keygen -o ./keys/exit -n exit-server
node cli.mjs keygen -o ./keys/client -n my-laptop
```

### 2А. Запуск в режиме `onion` (сквозное шифрование Клиент ↔ Exit)
```bash
node cli.mjs relay  -m onion -l :6001 -k ./keys/r1.key -a ./keys/client.pub
node cli.mjs relay  -m onion -l :6002 -k ./keys/r2.key --open
node cli.mjs exit   -m onion -l :6009 -k ./keys/exit.key -a ./keys/client.pub

node cli.mjs client -m onion -l 127.0.0.1:8080 -k ./keys/client.key \
  --hop 198.51.100.1:6001,./keys/r1.pub \
  --hop 198.51.100.2:6002,./keys/r2.pub \
  --exit 203.0.113.9:6009,./keys/exit.pub
```

### 2Б. Запуск в режиме `ptp` (пошаговое шифрование между соседями)
```bash
node cli.mjs relay  -m ptp -l :6001 -k ./keys/r1.key -a ./keys/client.pub
node cli.mjs relay  -m ptp -l :6002 -k ./keys/r2.key -a ./keys/r1.pub
node cli.mjs exit   -m ptp -l :6009 -k ./keys/exit.key -a ./keys/r2.pub

node cli.mjs client -m ptp -l 127.0.0.1:8080 -k ./keys/client.key \
  --hop 198.51.100.1:6001,./keys/r1.pub \
  --hop 198.51.100.2:6002,./keys/r2.pub \
  --exit 203.0.113.9:6009,./keys/exit.pub
```

### 2В. Режим `ptp` со статическим мостом `--next` (клиент знает только 1-й репитер)
```bash
node cli.mjs exit  -m ptp -l :6009 -k ./keys/exit.key -a ./keys/r2.pub
node cli.mjs relay -m ptp -l :6002 -k ./keys/r2.key   -a ./keys/r1.pub     --next 203.0.113.9:6009,./keys/exit.pub
node cli.mjs relay -m ptp -l :6001 -k ./keys/r1.key   -a ./keys/client.pub --next 198.51.100.2:6002,./keys/r2.pub

# На клиенте указывается только первый репитер:
node cli.mjs client -m ptp -l 127.0.0.1:8080 -k ./keys/client.key -e 198.51.100.1:6001,./keys/r1.pub
```

### 3. Подключение браузера или консольных программ
```bash
curl -x http://127.0.0.1:8080 https://example.com
```

---

## Маскировка от DPI (`wss://` / `tls://` + `--fallback`)

На участке через провайдера с DPI первый репитер можно поднять на порту `443` под видом обычного HTTPS/WebSocket-сайта (или спрятать за Nginx / Cloudflare), а дальнейшие участки между зарубежными VPS оставить на чистом быстром TCP:

```bash
# На 1-м репитере (отдаёт обычный сайт сканерам на всех путях, кроме секретного /ws/example-path):
node cli.mjs relay -m ptp \
  -l wss://:443/ws/example-path \
  --tls-cert /etc/letsencrypt/live/example.com/fullchain.pem \
  --tls-key /etc/letsencrypt/live/example.com/privkey.pem \
  --fallback 127.0.0.1:3000 \
  -k ./keys/r1.key -a ./keys/authorized_keys

# На клиенте (1-й хоп идёт по wss://:443, а дальше до Exit — быстрый сырой TCP):
node cli.mjs client -m ptp -l 127.0.0.1:8080 -k ./keys/client.key \
  --hop wss://example.com:443/ws/example-path,./keys/r1.pub \
  -e 203.0.113.9:5001,./keys/exit.pub
```

---

## SOCKS5 + UDP (`-s / --socks`) — кроссплатформенно и без `root`

Клиент может одновременно держать локальный HTTP-прокси (`-l`) и SOCKS5-прокси с поддержкой `TCP CONNECT` и `UDP ASSOCIATE` (`-s`, для игр, звонков, QUIC/HTTP3 и DNS) поверх одних и тех же прогретых цепочек:

```bash
node cli.mjs client -m ptp \
  -l 127.0.0.1:8080 \
  -s 127.0.0.1:1080 \
  -k ./keys/client.key \
  --hop wss://example.com:443/ws/example-path,./keys/r1.pub \
  -e 203.0.113.9:5001,./keys/exit.pub

# Проверка через SOCKS5 (с резолвингом DNS на стороне Exit):
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me
```

---

## Системный L3 VPN на Linux (`--tun`)

В режиме `--tun` создаётся ядерный сетевой интерфейс `/dev/net/tun` без сторонних библиотек — через многохоповый туннель прозрачно проходят **любые IPv4-пакеты** (`ICMP ping`, `TCP`, `UDP`, `QUIC`), а Exit автоматически выдаёт клиенту свободный IP из пула и поднимает `MASQUERADE` (`--nat`):

```bash
# На Exit-сервере (Linux VPS):
sudo node cli.mjs exit -l :5001 -k ./keys/exit.key -a ./keys/r1.pub \
  --tun st0 --tun-cidr 10.99.0.1/24 --nat

# На клиенте (полный заворот трафика системы с авто-обходом IP входного репитера и списка исключений):
sudo "$(which node)" cli.mjs client -m ptp -k ./keys/client.key \
  --hop wss://example.com:443/ws/example-path,./keys/r1.pub \
  -e 203.0.113.9:5001,./keys/exit.pub \
  --no-http --tun st0 --tun-default-route \
  --tun-exclude ./bypass.txt
```

Формат файла для `--tun-exclude <файл>` и `--tun-route <файл>` (по одному IP, CIDR или домену на строку; если у домена несколько `A`-записей IPv4 — добавляются все, а IPv6 игнорируется; при остановке клиента все маршруты и таблица `nftables` на Exit автоматически удаляются):
```text
# Домашние/рабочие сети и прямые серверы
198.51.100.10
192.168.0.0/16
git.example.org
```

> **Запуск `--tun` без `root`:** можно один раз создать постоянный интерфейс от пользователя (`sudo ip tuntap add dev st0 mode tun user $USER && sudo ip addr add 10.99.0.2/24 dev st0 && sudo ip link set dev st0 mtu 1400 up`) и запускать клиент с флагом `--no-tun-config`.

---

## Конфигурационный файл JSON / JSONC (`-c / --config`)

Все роли (`client`, `relay`, `exit`) можно запускать одной командой `node cli.mjs -c config.json` (поддерживаются `//` и `/* */` комментарии, висячие запятые, строковые публичные ключи прямо внутри JSON и относительные пути от папки конфига; любые флаги CLI поверх `-c` имеют приоритет):

```json
{
  // Пример client.json
  "role": "client",
  "mode": "ptp",
  "key": "./keys/client.key",
  "pool": 2,

  "http": "127.0.0.1:8080",
  "socks": "127.0.0.1:1080",

  "tun": {
    "enabled": false,
    "name": "st0",
    "mtu": 1320,
    "defaultRoute": false,
    "exclude": ["./bypass.txt", "198.51.100.10"],
    "routes": []
  },

  "hops": [
    {
      "endpoint": "198.51.100.1:5001",
      "publicKey": "./keys/r1.pub"
    },
    {
      "endpoint": "wss://relay2.example.com:443/ws/example-path",
      "publicKey": "./keys/r2.pub"
    }
  ],

  "exit": {
    "endpoint": "203.0.113.9:5001",
    "publicKey": "./keys/exit.pub"
  }
}
```

```bash
# Запуск по конфигу (или быстрое переопределение режима флагом поверх конфига):
node cli.mjs -c ./client.json
node cli.mjs -c ./client.json -m onion
```

---

## Благодарности

Особая благодарность **[Jing Lee (@TES286_lijing)](https://t.me/TES286_lijing)** за архитектурное ревью и идеи, которые легли в основу обновления: поддержка `UDP` (`SOCKS5`), системный `TUN`-режим, пул мультиплексированных каналов и защита от активного пробинга DPI.
