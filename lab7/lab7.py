"""
Лабораторная работа №7 — шифр Вернама (Python)

Реализация шифра Вернама для шифрования и расшифровки файлов.
Ключ K генерируется с использованием метода Диффи-Хеллмана.
"""

import random
import sys
import argparse
import os
import hashlib
from typing import Tuple, Optional


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


def generate_diffie_hellman_key(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int, int]:
    """Генерация общего ключа по схеме Диффи-Хеллмана.
    
    Возвращает (p, g, xa, xb, K), где:
    - p - простое число
    - g - первообразный корень
    - xa, xb - секретные ключи абонентов
    - K - общий секретный ключ
    """
    # Генерируем безопасное простое число p
    p, q = gen_safe_prime(bits, fermat_k)
    
    # Находим первообразный корень g
    g = find_primitive_root(p, q)
    
    # Генерируем секретные ключи абонентов
    xa = random.randint(2, p - 2)
    xb = random.randint(2, p - 2)
    
    # Вычисляем открытые ключи
    ya = mod_pow(g, xa, p)
    yb = mod_pow(g, xb, p)
    
    # Вычисляем общий секретный ключ
    K = mod_pow(yb, xa, p)  # или mod_pow(ya, xb, p)
    
    return p, g, xa, xb, K


def generate_vernam_key_from_dh(K: int, key_length: int) -> bytes:
    """Генерация ключа для шифра Вернама на основе ключа Диффи-Хеллмана."""
    # Используем хеш-функцию для получения ключа нужной длины
    key_bytes = K.to_bytes((K.bit_length() + 7) // 8, 'big')
    
    # Генерируем ключ нужной длины с помощью хеширования
    key = b''
    counter = 0
    while len(key) < key_length:
        data = key_bytes + counter.to_bytes(4, 'big')
        hash_obj = hashlib.sha256(data)
        key += hash_obj.digest()
        counter += 1
    
    return key[:key_length]


def vernam_encrypt_file(input_file: str, output_file: str, key: bytes) -> bool:
    """Шифрование файла с помощью шифра Вернама."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Проверяем, что ключ достаточно длинный
        if len(key) < len(data):
            print(f"Ошибка: ключ слишком короткий ({len(key)} байт), нужно {len(data)} байт")
            return False
        
        # Шифруем данные
        encrypted_data = bytearray()
        for i, byte in enumerate(data):
            encrypted_byte = byte ^ key[i]
            encrypted_data.append(encrypted_byte)
        
        with open(output_file, 'wb') as f:
            f.write(encrypted_data)
        
        return True
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")
        return False


def vernam_decrypt_file(input_file: str, output_file: str, key: bytes) -> bool:
    """Расшифровка файла с помощью шифра Вернама."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        # Проверяем, что ключ достаточно длинный
        if len(key) < len(data):
            print(f"Ошибка: ключ слишком короткий ({len(key)} байт), нужно {len(data)} байт")
            return False
        
        # Расшифровываем данные (операция XOR обратима)
        decrypted_data = bytearray()
        for i, byte in enumerate(data):
            decrypted_byte = byte ^ key[i]
            decrypted_data.append(decrypted_byte)
        
        with open(output_file, 'wb') as f:
            f.write(decrypted_data)
        
        return True
    except Exception as e:
        print(f"Ошибка при расшифровке: {e}")
        return False


def vernam_demo(K: int):
    """Демонстрация работы шифра Вернама."""
    print("=== Демонстрация шифра Вернама ===")
    print(f"Общий ключ Диффи-Хеллмана K = {K}")
    
    # Генерируем ключ для демонстрации
    demo_text = b"Hello, World!"
    key = generate_vernam_key_from_dh(K, len(demo_text))
    print(f"Сгенерированный ключ: {key.hex()}")
    
    # Шифруем
    encrypted = bytearray()
    for i, byte in enumerate(demo_text):
        encrypted.append(byte ^ key[i])
    
    # Расшифровываем
    decrypted = bytearray()
    for i, byte in enumerate(encrypted):
        decrypted.append(byte ^ key[i])
    
    print(f"Исходный текст: {demo_text}")
    print(f"Зашифрованный: {encrypted.hex()}")
    print(f"Расшифрованный: {decrypted}")
    print(f"Корректность: {'✓' if demo_text == decrypted else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Шифр Вернама — шифрование и расшифровка файлов')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt', 'demo'], default='demo',
                        help='Режим работы: encrypt — шифрование, decrypt — расшифровка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--output', type=str, help='Выходной файл')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простого числа')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()
    
    print('=== Лабораторная работа №7: Шифр Вернама ===')
    
    # Генерируем общий ключ по схеме Диффи-Хеллмана
    print("Генерация общего ключа по схеме Диффи-Хеллмана...")
    p, g, xa, xb, K = generate_diffie_hellman_key(args.bits, args.fermat_k)
    
    print(f"Параметры Диффи-Хеллмана:")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"Секретный ключ Алисы xa = {xa}")
    print(f"Секретный ключ Боба xb = {xb}")
    print(f"Общий секретный ключ K = {K}")
    print()
    
    if args.mode == 'demo':
        vernam_demo(K)
    elif args.mode == 'encrypt':
        if not args.input or not args.output:
            print("Для шифрования необходимо указать --input и --output")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        # Определяем длину ключа на основе размера файла
        file_size = os.path.getsize(args.input)
        key = generate_vernam_key_from_dh(K, file_size)
        
        print(f"Шифрование файла {args.input} -> {args.output}")
        print(f"Размер файла: {file_size} байт")
        print(f"Длина ключа: {len(key)} байт")
        
        if vernam_encrypt_file(args.input, args.output, key):
            print("Шифрование завершено успешно")
        else:
            print("Ошибка при шифровании")
    elif args.mode == 'decrypt':
        if not args.input or not args.output:
            print("Для расшифровки необходимо указать --input и --output")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        # Определяем длину ключа на основе размера файла
        file_size = os.path.getsize(args.input)
        key = generate_vernam_key_from_dh(K, file_size)
        
        print(f"Расшифровка файла {args.input} -> {args.output}")
        print(f"Размер файла: {file_size} байт")
        print(f"Длина ключа: {len(key)} байт")
        
        if vernam_decrypt_file(args.input, args.output, key):
            print("Расшифровка завершена успешно")
        else:
            print("Ошибка при расшифровке")
    
    print('\nГотово.')
