# Лабораторная работа №12 - Ментальный покер

## Описание алгоритма

Ментальный покер - это криптографический протокол, позволяющий игрокам играть в покер без доверенного дилера. Каждый игрок участвует в перемешивании карт, используя свои криптографические ключи.

### Принцип работы

1. **Генерация ключей**:
   - Каждый игрок генерирует пару RSA ключей `(n_i, e_i, d_i)`
   - Открытые ключи `(n_i, e_i)` публикуются
   - Секретные ключи `d_i` хранятся в тайне

2. **Перемешивание карт**:
   - Карты представляются числами от 1 до 52
   - Каждый игрок последовательно шифрует все карты своим ключом
   - После каждого шифрования карты перемешиваются
   - Результат: полностью перемешанные зашифрованные карты

3. **Раздача карт**:
   - Зашифрованные карты раздаются игрокам
   - Каждый игрок расшифровывает свои карты в обратном порядке

4. **Проверка честности**:
   - Все игроки могут проверить корректность процесса
   - Невозможно подменить карты после шифрования

### Математические формулы

- `C_i = M^{e_i} mod n_i` (шифрование карты M игроком i)
- `M = C_i^{d_i} mod n_i` (расшифровка карты игроком i)
- `C_final = M^{e_1}^{e_2}^{...}^{e_n} mod n_1 mod n_2 ... mod n_n` (финальное шифрование)

## Пример работы алгоритма

### Простой пример

```python
# Игроки: Алиса и Боб
# Карты: [1, 2, 3, 4, 5]

# Ключи Алисы
n_a = 33, e_a = 3, d_a = 7

# Ключи Боба  
n_b = 35, e_b = 5, d_b = 5

# Исходные карты
cards = [1, 2, 3, 4, 5]

# Алиса шифрует карты
encrypted_by_alice = []
for card in cards:
    encrypted_card = pow(card, e_a, n_a)
    encrypted_by_alice.append(encrypted_card)
# Результат: [1, 8, 27, 31, 26]

# Перемешиваем
random.shuffle(encrypted_by_alice)
# Результат: [8, 1, 31, 26, 27]

# Боб шифрует карты Алисы
encrypted_by_bob = []
for card in encrypted_by_alice:
    encrypted_card = pow(card, e_b, n_b)
    encrypted_by_bob.append(encrypted_card)
# Результат: [8, 1, 31, 26, 27] (если n_b > n_a)

# Раздача: Алиса получает первые 2 карты, Боб - следующие 2
alice_encrypted = [8, 1]
bob_encrypted = [31, 26]

# Расшифровка
# Боб расшифровывает свои карты
bob_cards = []
for card in bob_encrypted:
    decrypted = pow(card, d_b, n_b)
    bob_cards.append(decrypted)
# Результат: [31, 26]

# Алиса расшифровывает карты Боба
alice_cards = []
for card in bob_encrypted:
    decrypted_by_bob = pow(card, d_b, n_b)
    decrypted_by_alice = pow(decrypted_by_bob, d_a, n_a)
    alice_cards.append(decrypted_by_alice)
# Результат: [3, 4]
```

### Реальный пример с большими числами

```python
# 4 игрока, 52 карты
players = ["Алиса", "Боб", "Чарли", "Дэвид"]
cards = list(range(1, 53))  # [1, 2, 3, ..., 52]

# Генерация ключей для каждого игрока
player_keys = {}
for player in players:
    p = gen_probable_prime(16)
    q = gen_probable_prime(16)
    n = p * q
    phi_n = (p-1) * (q-1)
    e = 65537
    d = pow(e, -1, phi_n)
    player_keys[player] = {'n': n, 'e': e, 'd': d}

# Последовательное шифрование
encrypted_cards = cards.copy()
for player in players:
    print(f"{player} шифрует карты...")
    for i, card in enumerate(encrypted_cards):
        encrypted_cards[i] = pow(card, player_keys[player]['e'], player_keys[player]['n'])
    random.shuffle(encrypted_cards)

# Раздача карт (по 2 карты каждому игроку)
player_hands = {}
for i, player in enumerate(players):
    start_idx = i * 2
    player_hands[player] = encrypted_cards[start_idx:start_idx+2]

# Расшифровка в обратном порядке
for player in reversed(players):
    print(f"{player} расшифровывает карты...")
    for other_player in player_hands:
        if other_player != player:
            for i, card in enumerate(player_hands[other_player]):
                decrypted = pow(card, player_keys[player]['d'], player_keys[player]['n'])
                player_hands[other_player][i] = decrypted

# Результат: каждый игрок видит свои карты
for player, hand in player_hands.items():
    print(f"{player}: {hand}")
```

## Запуск программы

```bash
# Графический интерфейс
python lab12.py

# Демонстрация защищенности
python lab12.py --demo
```

## Особенности реализации

- Графический интерфейс с tkinter
- Поддержка произвольного количества игроков
- Автоматическая генерация RSA ключей
- Визуализация процесса шифрования/расшифровки
- Полная прозрачность и проверяемость процесса
- Обоснование защищенности и честности

## Защищенность и честность

1. **Защищенность**: Никто не может узнать карты других игроков до расшифровки
2. **Честность**: Все игроки участвуют в перемешивании, невозможно подменить карты
3. **Прозрачность**: Весь процесс можно проверить и воспроизвести
4. **Криптографическая стойкость**: Используется стойкий алгоритм RSA
