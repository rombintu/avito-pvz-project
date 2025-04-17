## Avito PVZ Project (Demo)

Покрытие тестами  
![coverage](profiles/coverage.svg)

### Документация системы управления ПВЗ
#### Обзор

Система управления пунктами выдачи заказов (ПВЗ) — это серверное приложение для управления:

    Пунктами выдачи заказов
    Приемками товаров
    Учетом продукции

Система предоставляет:

    REST API (основной интерфейс)
    gRPC API (для внутренних сервисов)
    Метрики Prometheus

#### Содержание

    Архитектура
    API
    Аутентификация
    Метрики
    Развертывание
    Разработка

### Архитектура

Архитектура системы

Компоненты системы:

    REST API (на Gin)
    gRPC API
    PostgreSQL (хранение данных)
    Prometheus (сбор метрик)
    JWT (аутентификация)

### API
Аутентификация
`POST /dummyLogin`
Генерация тестового JWT-токена.
Запрос:
```json

{
  "role": "employee|moderator"
}
```
Ответ:
```json
{
  "token": "jwt.token.here"
}
```

Регистрация нового пользователя.
`POST /register`

Запрос:
```json

{
  "email": "user@example.com",
  "password": "password123",
  "role": "employee|moderator"
}
```
Аутентификация пользователя.
`POST /login`
Запрос:
```json

{
  "email": "user@example.com",
  "password": "password123"
}
```

Управление ПВЗ
`POST /pvz` (Только модераторы)
Создание нового пункта выдачи.
Запрос:
```json

{
  "city": "Москва"
}
```

Получение списка ПВЗ.
`GET /pvz`
Параметры:

    limit - элементов на странице (по умолчанию 10)
    page - номер страницы (по умолчанию 1)

Работа с заказами
`POST /receptions` (Только сотрудники)
Создание приемки заказа.
Запрос:
```json
{
  "pvzId": "uuid-строки"
}
```

Добавление товара в приемку.
`POST /products` (Только сотрудники)
Запрос:
```json

{
  "type": "электроника|одежда|обувь",
  "pvzId": "uuid-строки"
}
```

`POST /pvz/:pvzId/close_last_reception`

Закрытие последней открытой приемки.
`POST /pvz/:pvzId/delete_last_product`

Удаление последнего добавленного товара (LIFO).
Аутентификация

Система использует JWT-токены с ролевой моделью:

Роли:

    Модераторы:
        Создание ПВЗ
        Просмотр всех данных
    Сотрудники:
        Управление приемками и товарами
        Просмотр данных

Заголовок запроса:
```
Authorization: Bearer <ваш_токен>
```

### Метрики

Метрики доступны по адресу :9000/metrics:
Технические метрики

    http_requests_total - Общее количество запросов
    http_response_time_seconds - Время выполнения запросов

Бизнес-метрики

    pvz_created_total - Созданные ПВЗ
    receptions_created_total - Созданные приемки
    products_added_total - Добавленные товары

## Развертывание
Требования

    Go 1.20+
    PostgreSQL 13+
    (Опционально) Prometheus + Grafana

### Предустановка
```
git clone https://github.com/rombintu/avito-pvz-project.git
cd avito-pvz-project
go mod tidy
cp .env.bak .env # Внесите изменения под ваше окружение
```

### Настройка
```bash
export DATABASE_URL="postgres://user:pass@host:port/dbname"
export JWT_SECRET="ваш-секретный-ключ"
```
### Запуск
```bash
# Основной сервер
go run cmd/main.go
```

### Разработка
Структура проекта

    internal/
        auth/         # Аутентификация
        config/       # Конфигурация
        metrics/      # Метрики
        models/       # Модели данных
        proto/        # gRPC-определения
        server/       # HTTP/gRPC серверы
        storage/      # Работа с БД
            drivers/    # Реализации для БД

### Тестирование
```bash
go test ./...
```

gRPC Интерфейс
```protobuf
service PVZService {
  rpc GetPVZList(GetPVZListRequest) returns (GetPVZListResponse);
}
```
### Мониторинг

Рекомендации для production:

    Разработать функции хеширования паролей
    Настроить Prometheus для сбора метрик
    Настроить алерты на:
        Высокую частоту ошибок
        Медленные запросы
        Аномалии в бизнес-метриках
    Создать Grafana-дашборды

### Безопасность

Рекомендации:

    Обязательно использовать HTTPS
    Регулярно менять JWT-секреты
    Ограничивать права доступа к БД
    Мониторить аномальную активность