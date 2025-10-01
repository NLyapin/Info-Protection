"""
Лабораторная работа №10 — алгоритм электронной подписи ГОСТ Р 34.10-94 (Python)

Реализация алгоритма электронной подписи ГОСТ Р 34.10-94 для подписания и проверки файлов.
Использует хеш-функцию SHA-256 (не слабее MD5) и подписывает каждый байт отдельно.
"""

import random
import sys
import argparse
import os
import hashlib
from typing import Tuple, List, Optional


def mod_pow(a: int, e: int, m: int) -> int:
    """Возведение a^e по модулю m — алгоритм быстрого возведения (square-and-multiply)."""
    if m == 1:
        return 0
    a %= m
    result = 1
    base = a
    exp = e
    while exp > 0:
        if exp & 1:
            result = (result * base) % m
        base = (base * base) % m
        exp >>= 1
    return result


def is_probable_prime_fermat(n: int, k: int = 8) -> bool:
    """Проверка простоты тестом Ферма с k испытаниями."""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0:
        return False

    for _ in range(k):
        a = random.randrange(2, n - 1)
        if mod_pow(a, n - 1, n) != 1:
            return False
    return True


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """Обобщённый алгоритм Евклида.
    Возвращает (g, x, y) такие, что g = gcd(a, b) и a*x + b*y = g."""
    old_r, r = abs(a), abs(b)
    old_s, s = 1 if a >= 0 else -1, 0
    old_t, t = 0, 1 if b >= 0 else -1

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s
        old_t, t = t, old_t - q * t

    g = old_r
    x = old_s if a >= 0 else -old_s
    y = old_t if b >= 0 else -old_t
    return g, x, y


def gen_probable_prime(bits: int = 32, k: int = 8) -> int:
    """Генерация вероятно-простого числа с указанным количеством битов."""
    if bits < 2:
        raise ValueError('bits must be >= 2')

    while True:
        candidate = random.getrandbits(bits) | 1
        candidate |= (1 << (bits - 1))
        if is_probable_prime_fermat(candidate, k=k):
            return candidate


def generate_gost_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int]:
    """Генерация ключей для алгоритма ГОСТ Р 34.10-94.

    Возвращает (p, q, a, x), где:
    - p - простое число (модуль)
    - q - простое число (порядок подгруппы)
    - a - элемент порядка q по модулю p
    - x - секретный ключ
    """
    # Генерируем простое число p
    p = gen_probable_prime(bits, fermat_k)

    # Генерируем простое число q тако
    # е, что q | (p-1)
    # Ищем q среди делителей p-1
    p_minus_1 = p - 1
    q_candidates = []

    # Проверяем простые делители p-1
    for i in range(2, min(1000, int(p_minus_1**0.5) + 1)):
        if p_minus_1 % i == 0 and is_probable_prime_fermat(i):
            q_candidates.append(i)
        if p_minus_1 % (p_minus_1 // i) == 0 and is_probable_prime_fermat(p_minus_1 // i):
            q_candidates.append(p_minus_1 // i)

    if not q_candidates:
        # Если не нашли подходящий q, генерируем новый p
        return generate_gost_keys(bits, fermat_k)

    q = max(q_candidates)  # Выбираем наибольший простой делитель

    # Находим элемент a порядка q
    print(f"Поиск элемента a порядка {q}...")

    # Сначала пробуем простые числа
    for candidate in [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31]:
        if candidate < p and mod_pow(candidate, q, p) == 1:
            a = candidate
            print(f" Найден элемент a = {a} (простое число)")
            break
    else:
        # Если простые не подошли, ищем случайно
        attempts = 0
        max_attempts = 5000  # Уменьшаем количество попыток

        while attempts < max_attempts:
            attempts += 1
            a = random.randint(2, min(p - 1, 1000))  # Ограничиваем диапазон
            if mod_pow(a, q, p) == 1:
                print(f"Найден элемент a = {a} (попытка #{attempts})")
                break

            # Показываем прогресс каждые 500 попыток
            if attempts % 500 == 0:
                print(f"Поиск элемента a... попытка #{attempts}")

        if attempts >= max_attempts:
            # Если не нашли за разумное время, генерируем новый p
            print(f"Не удалось найти элемент a за {max_attempts} попыток")
            print(f"Повторная генерация...")
            return generate_gost_keys(bits, fermat_k)

    # Генерируем секретный ключ x
    x = random.randint(1, q - 1)

    return p, q, a, x


def compute_file_hash(file_path: str) -> bytes:
    """Вычисление хеша файла с помощью SHA-256."""
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.digest()


def sign_file(input_file: str, signature_file: str, p: int, q: int, a: int, x: int) -> bool:
    """Подписание файла с помощью алгоритма ГОСТ Р 34.10-94."""
    try:
        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")

        # Подписываем каждый байт хеша отдельно
        signatures = []
        for byte in file_hash:
            # Генерируем случайное k
            k = random.randint(1, q - 1)

            # Вычисляем r = (a^k mod p) mod q
            r = mod_pow(a, k, p) % q
            if r == 0:
                # Если r = 0, выбираем другое k
                k = random.randint(1, q - 1)
                r = mod_pow(a, k, p) % q

            # Вычисляем s = (k * h + x * r) mod q
            s = (k * byte + x * r) % q
            if s == 0:
                # Если s = 0, выбираем другое k
                k = random.randint(1, q - 1)
                r = mod_pow(a, k, p) % q
                s = (k * byte + x * r) % q

            signatures.append((r, s))

        # Вычисляем открытый ключ y
        y = mod_pow(a, x, p)

        # Сохраняем подпись в текстовом формате (как для .sig, так и для других расширений)
        with open(signature_file, 'w') as f:
            f.write(f"# GOST R 34.10-94 Signature for {os.path.basename(input_file)}\n")
            f.write(f"# Hash: {file_hash.hex()}\n")
            f.write(f"# p: {p}\n")
            f.write(f"# q: {q}\n")
            f.write(f"# a: {a}\n")
            f.write(f"# y: {y}\n")
            f.write("# Signatures (r, s) pairs:\n")
            for r, s in signatures:
                f.write(f"{r} {s}\n")

        if signature_file.lower().endswith('.sig'):
            print(f"Подпись сохранена в файл .sig: {signature_file}")
        else:
            print(f"Подпись сохранена в текстовый файл: {signature_file}")

        return True
    except Exception as e:
        print(f"Ошибка при подписании: {e}")
        return False


def verify_signature(input_file: str, signature_file: str, p: int, q: int, a: int, y: int) -> bool:
    """Проверка подписи файла."""
    try:
        # Читаем подпись из текстового формата
        with open(signature_file, 'r') as f:
            lines = f.readlines()

        # Извлекаем подписи и параметры (пропускаем комментарии)
        signatures = []
        sig_p, sig_q, sig_a, sig_y, stored_hash = None, None, None, None, None

        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) == 2:
                    r, s = int(parts[0]), int(parts[1])
                    signatures.append((r, s))
            elif line.startswith('# p:'):
                sig_p = int(line.split(':')[1].strip())
            elif line.startswith('# q:'):
                sig_q = int(line.split(':')[1].strip())
            elif line.startswith('# a:'):
                sig_a = int(line.split(':')[1].strip())
            elif line.startswith('# y:'):
                sig_y = int(line.split(':')[1].strip())
            elif line.startswith('# Hash:'):
                stored_hash = bytes.fromhex(line.split(':')[1].strip())

        # Используем параметры из файла подписи, если они есть
        if sig_p is not None and sig_q is not None and sig_a is not None and sig_y is not None:
            print(f"Используются параметры из файла подписи:")
            print(f"  p = {sig_p}")
            print(f"  q = {sig_q}")
            print(f"  a = {sig_a}")
            print(f"  y = {sig_y}")
            p, q, a, y = sig_p, sig_q, sig_a, sig_y
        else:
            print(f"Используются переданные параметры:")
            print(f"  p = {p}")
            print(f"  q = {q}")
            print(f"  a = {a}")
            print(f"  y = {y}")

        if signature_file.lower().endswith('.sig'):
            print(f"Подпись загружена из файла .sig: {signature_file}")
        else:
            print(f"Подпись загружена из текстового файла: {signature_file}")

        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")

        # Проверяем соответствие хешей, если есть сохраненный хеш
        if stored_hash is not None:
            if file_hash == stored_hash:
                print("Хеш файла совпадает с хешем в подписи")
            else:
                print("Хеш файла НЕ совпадает с хешем в подписи!")
                print(f"Файл: {file_hash.hex()}")
                print(f"Подпись: {stored_hash.hex()}")

        # Проверяем каждую подпись
        if len(signatures) != len(file_hash):
            print(f"Ошибка: количество подписей ({len(signatures)}) не совпадает с длиной хеша ({len(file_hash)})")
            return False

        for i, ((r, s), byte) in enumerate(zip(signatures, file_hash)):
            # Проверяем, что byte и q взаимно просты
            gcd_byte_q, _, _ = extended_gcd(byte, q)
            if gcd_byte_q != 1:
                print(f"Ошибка: байт {i} ({byte}) и q не взаимно просты")
                return False

            # Проверка подписи: v = h^(-1) mod q, z1 = (s * v) mod q, z2 = (r * v) mod q
            # u = (a^z1 * y^z2 mod p) mod q
            _, h_inv, _ = extended_gcd(byte, q)
            h_inv = h_inv % q

            z1 = (s * h_inv) % q
            z2 = ((q - r) * h_inv) % q

            u = (mod_pow(a, z1, p) * mod_pow(y, z2, p)) % p % q

            if u != r:
                print(f"Ошибка проверки подписи для байта {i}: ожидалось {r}, получено {u}")
                return False

        print("Подпись корректна!")
        return True
    except Exception as e:
        print(f"Ошибка при проверке подписи: {e}")
        return False


def gost_signature_demo(p: int, q: int, a: int, x: int, y: int):
    """Демонстрация работы алгоритма электронной подписи ГОСТ Р 34.10-94."""
    print("=== Демонстрация алгоритма электронной подписи ГОСТ Р 34.10-94 ===")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"a = {a}")
    print(f"x = {x}")
    print(f"y = {y}")
    print()

    # Тестируем на нескольких байтах хеша
    test_hash_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c

    print("Тестирование подписания/проверки:")
    for h in test_hash_bytes:
        # Проверяем, что h и q взаимно просты
        gcd_h_q, _, _ = extended_gcd(h, q)
        if gcd_h_q != 1:
            print(f"h={h} -> пропуск (h и q не взаимно просты)")
            continue

        # Генерируем случайное k
        k = random.randint(1, q - 1)

        # Подписание
        r = mod_pow(a, k, p) % q
        s = (k * h + x * r) % q

        # Проверка
        _, h_inv, _ = extended_gcd(h, q)
        h_inv = h_inv % q

        z1 = (s * h_inv) % q
        z2 = ((q - r) * h_inv) % q

        u = (mod_pow(a, z1, p) * mod_pow(y, z2, p)) % p % q

        print(f"h={h} -> r={r}, s={s} -> проверка: {r} == {u} {'✓' if r == u else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Алгоритм электронной подписи ГОСТ Р 34.10-94')
    parser.add_argument('--mode', choices=['sign', 'verify', 'demo'], default='demo',
                        help='Режим работы: sign — подписание, verify — проверка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--signature', type=str, help='Файл подписи')
    parser.add_argument('--bits', type=int, default=16, help='Число бит для генерации простого числа')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()

    print('=== Лабораторная работа №10: Алгоритм электронной подписи ГОСТ Р 34.10-94 ===')
    print('Поддерживаемые форматы файлов подписи:')
    print('   • .sig — текстовый формат (рекомендуется)')
    print('   • .txt — текстовый формат (для совместимости)')

    # Выбор режима генерации ключей
    key_mode = input("Выберите режим генерации ключей (input — ввод с клавиатуры, rand — генерация): ").strip().lower()

    if key_mode == 'input':
        try:
            p = int(input('Введите простое число p: ').strip())
            q = int(input('Введите простое число q: ').strip())
            a = int(input('Введите элемент a: ').strip())
            x = int(input('Введите секретный ключ x: ').strip())

            # Проверяем корректность p и q
            if not is_probable_prime_fermat(p) or not is_probable_prime_fermat(q):
                print("Ошибка: p и q должны быть простыми числами")
                sys.exit(1)

            if (p - 1) % q != 0:
                print("Ошибка: q должно делить p-1")
                sys.exit(1)

            # Вычисляем открытый ключ y
            y = mod_pow(a, x, p)

        except Exception as e:
            print('Ошибка ввода:', e)
            sys.exit(1)
    elif key_mode == 'rand':
        p, q, a, x = generate_gost_keys(args.bits, args.fermat_k)
        y = mod_pow(a, x, p)
        print(f"Сгенерированы ключи: p={p}, q={q}, a={a}, x={x}, y={y}")
    else:
        print("Неподдерживаемый режим, выход.")
        sys.exit(1)

    print()

    if args.mode == 'demo':
        gost_signature_demo(p, q, a, x, y)
    elif args.mode == 'sign':
        if not args.input or not args.signature:
            print("Для подписания необходимо указать --input и --signature")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)

        print(f"Подписание файла {args.input}")
        print(f"Файл подписи: {args.signature}")

        # Определяем формат по расширению
        if args.signature.lower().endswith('.sig'):
            print("Формат: текстовый (.sig)")
        else:
            print("Формат: текстовый")

        if sign_file(args.input, args.signature, p, q, a, x):
            print("Подписание завершено успешно")
        else:
            print("Ошибка при подписании")
    elif args.mode == 'verify':
        if not args.input or not args.signature:
            print("Для проверки необходимо указать --input и --signature")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        if not os.path.exists(args.signature):
            print(f"Файл подписи {args.signature} не найден")
            sys.exit(1)

        print(f"Проверка подписи файла {args.input}")
        print(f"Файл подписи: {args.signature}")

        # Определяем формат по расширению
        if args.signature.lower().endswith('.sig'):
            print("Формат: текстовый (.sig)")
        else:
            print("Формат: текстовый")

        if verify_signature(args.input, args.signature, p, q, a, y):
            print("Проверка завершена успешно")
        else:
            print("Ошибка при проверке подписи")

    print('\nГотово.')
