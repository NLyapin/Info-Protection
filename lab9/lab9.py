"""
Лабораторная работа №9 — алгоритм электронной подписи Эль-Гамаля (Python)

Реализация алгоритма электронной подписи Эль-Гамаля для подписания и проверки файлов.
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


def gen_safe_prime(bits: int = 32, k: int = 8) -> Tuple[int, int]:
    """Генерация безопасного простого p = 2*q + 1."""
    if bits < 3:
        raise ValueError('bits must be >= 3 для генерации безопасного простого')

    while True:
        q = gen_probable_prime(bits - 1, k)
        p = 2 * q + 1
        if is_probable_prime_fermat(p, k=k):
            return p, q


def find_primitive_root(p: int, q: int) -> int:
    """Поиск первообразного корня g по модулю безопасного простого p."""
    g = 2
    while g < p:
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g
        g += 1
    raise ValueError("Не удалось найти первообразный корень")


def generate_elgamal_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int]:
    """Генерация ключей для алгоритма Эль-Гамаля.

    Возвращает (p, g, x, y), где:
    - p - простое число
    - g - первообразный корень по модулю p
    - x - секретный ключ
    - y - открытый ключ (g^x mod p)
    """
    # Генерируем безопасное простое число p
    p, q = gen_safe_prime(bits, fermat_k)

    # Находим первообразный корень g
    g = find_primitive_root(p, q)

    # Генерируем секретный ключ x
    x = random.randint(2, p - 2)

    # Вычисляем открытый ключ y
    y = mod_pow(g, x, p)

    return p, g, x, y


def compute_file_hash(file_path: str) -> bytes:
    """Вычисление хеша файла с помощью SHA-256."""
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.digest()


def sign_file(input_file: str, signature_file: str, p: int, g: int, x: int) -> bool:
    """Подписание файла с помощью алгоритма Эль-Гамаля."""
    try:
        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")

        # Подписываем каждый байт хеша отдельно
        signatures = []
        for byte in file_hash:
            # Генерируем случайное k для каждого байта
            while True:
                k = random.randint(2, p - 2)
                g_k, _, _ = extended_gcd(k, p - 1)
                if g_k == 1:  # k и (p-1) взаимно просты
                    break

            # Вычисляем r = g^k mod p
            r = mod_pow(g, k, p)

            # Вычисляем s = k^(-1) * (h - x*r) mod (p-1)
            _, k_inv, _ = extended_gcd(k, p - 1)
            k_inv = k_inv % (p - 1)

            s = (k_inv * (byte - x * r)) % (p - 1)

            signatures.append((r, s))

        # Сохраняем подпись
        with open(signature_file, 'w') as f:
            f.write(f"# ElGamal Signature for {os.path.basename(input_file)}\n")
            f.write(f"# Hash: {file_hash.hex()}\n")
            f.write(f"# p: {p}\n")
            f.write(f"# g: {g}\n")
            f.write("# Signatures (r, s) pairs:\n")
            for r, s in signatures:
                f.write(f"{r} {s}\n")

        print(f"Подпись сохранена в файл: {signature_file}")
        return True
    except Exception as e:
        print(f"Ошибка при подписании: {e}")
        return False


def verify_signature(input_file: str, signature_file: str, p: int, g: int, y: int) -> bool:
    """Проверка подписи файла."""
    try:
        # Читаем подпись
        with open(signature_file, 'r') as f:
            lines = f.readlines()

        # Извлекаем подписи (пропускаем комментарии)
        signatures = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                parts = line.split()
                if len(parts) == 2:
                    r, s = int(parts[0]), int(parts[1])
                    signatures.append((r, s))

        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")

        # Проверяем каждую подпись
        if len(signatures) != len(file_hash):
            print(f"Ошибка: количество подписей ({len(signatures)}) не совпадает с длиной хеша ({len(file_hash)})")
            return False

        for i, ((r, s), byte) in enumerate(zip(signatures, file_hash)):
            # Проверка подписи: g^h = y^r * r^s mod p
            left_side = mod_pow(g, byte, p)
            right_side = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p

            if left_side != right_side:
                print(f"Ошибка проверки подписи для байта {i}: ожидалось {left_side}, получено {right_side}")
                return False

        print("Подпись корректна!")
        return True
    except Exception as e:
        print(f"Ошибка при проверке подписи: {e}")
        return False


def elgamal_signature_demo(p: int, g: int, x: int, y: int):
    """Демонстрация работы алгоритма электронной подписи Эль-Гамаля."""
    print("=== Демонстрация алгоритма электронной подписи Эль-Гамаля ===")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"x = {x}")
    print(f"y = {y}")
    print()

    # Тестируем на нескольких байтах хеша
    test_hash_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c

    print("Тестирование подписания/проверки:")
    for h in test_hash_bytes:
        # Генерируем случайное k
        while True:
            k = random.randint(2, p - 2)
            g_k, _, _ = extended_gcd(mod_pow(g, k, p), p)
            if g_k == 1:
                break

        # Подписание
        r = mod_pow(g, k, p)
        _, k_inv, _ = extended_gcd(k, p - 1)
        k_inv = k_inv % (p - 1)
        s = (k_inv * (h - x * r)) % (p - 1)

        # Проверка
        left_side = mod_pow(g, h, p)
        right_side = (mod_pow(y, r, p) * mod_pow(r, s, p)) % p

        print(f"h={h} -> r={r}, s={s} -> проверка: {left_side} == {right_side} {'✓' if left_side == right_side else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Алгоритм электронной подписи Эль-Гамаля')
    parser.add_argument('--mode', choices=['sign', 'verify', 'demo'], default='demo',
                        help='Режим работы: sign — подписание, verify — проверка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--signature', type=str, help='Файл подписи')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простого числа')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()

    print('=== Лабораторная работа №9: Алгоритм электронной подписи Эль-Гамаля ===')

    # Выбор режима генерации ключей
    key_mode = input("Выберите режим генерации ключей (input — ввод с клавиатуры, rand — генерация): ").strip().lower()

    if key_mode == 'input':
        try:
            p = int(input('Введите простое число p: ').strip())
            g = int(input('Введите первообразный корень g: ').strip())
            x = int(input('Введите секретный ключ x: ').strip())

            # Проверяем корректность p
            if not is_probable_prime_fermat(p):
                print("Ошибка: p должно быть простым числом")
                sys.exit(1)

            # Вычисляем открытый ключ y
            y = mod_pow(g, x, p)

        except Exception as e:
            print('Ошибка ввода:', e)
            sys.exit(1)
    elif key_mode == 'rand':
        p, g, x, y = generate_elgamal_keys(args.bits, args.fermat_k)
        print(f"Сгенерированы ключи: p={p}, g={g}, x={x}, y={y}")
    else:
        print("Неподдерживаемый режим, выход.")
        sys.exit(1)

    print()

    if args.mode == 'demo':
        elgamal_signature_demo(p, g, x, y)
    elif args.mode == 'sign':
        if not args.input or not args.signature:
            print("Для подписания необходимо указать --input и --signature")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)

        print(f"Подписание файла {args.input}")
        if sign_file(args.input, args.signature, p, g, x):
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
        if verify_signature(args.input, args.signature, p, g, y):
            print("Проверка завершена успешно")
        else:
            print("Ошибка при проверке подписи")

    print('\nГотово.')
