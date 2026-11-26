# shadowtunnel-proxy

Портативный многохоповый HTTP / HTTPS (`CONNECT`) прокси на базе **ShadowTunnel** без внешних зависимостей (только встроенные модули Node.js ≥ 20).

Поддерживает **произвольное количество промежуточных ретрансляторов (`0..N`)** между клиентом и выходным сервером, а также выбор режима шифрования (`onion` или `ptp`).

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
