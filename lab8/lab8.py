"""
Лабораторная работа №8 — алгоритм электронной подписи RSA (Python)

Реализация алгоритма электронной подписи RSA для подписания и проверки файлов.
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


def generate_rsa_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int, int]:
    """Генерация ключей для алгоритма RSA.
    
    Возвращает (n, e, d, p, q), где:
    - n = p * q - модуль
    - e - открытый ключ (экспонента шифрования)
    - d - секретный ключ (экспонента расшифровки)
    - p, q - простые числа
    """
    # Генерируем два различных простых числа
    p = gen_probable_prime(bits // 2, fermat_k)
    q = gen_probable_prime(bits // 2, fermat_k)
    
    # Убеждаемся, что p != q
    while p == q:
        q = gen_probable_prime(bits // 2, fermat_k)
    
    # Вычисляем n и φ(n)
    n = p * q
    phi_n = (p - 1) * (q - 1)
    
    # Выбираем открытый ключ e (обычно 65537 или случайное взаимно простое с φ(n))
    e = 65537
    if e >= phi_n or extended_gcd(e, phi_n)[0] != 1:
        # Если 65537 не подходит, ищем случайное взаимно простое число
        while True:
            e = random.randint(3, phi_n - 1)
            if extended_gcd(e, phi_n)[0] == 1:
                break
    
    # Вычисляем секретный ключ d
    _, d, _ = extended_gcd(e, phi_n)
    d = d % phi_n
    
    return n, e, d, p, q


def compute_file_hash(file_path: str) -> bytes:
    """Вычисление хеша файла с помощью SHA-256."""
    hash_obj = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_obj.update(chunk)
    return hash_obj.digest()


def sign_file(input_file: str, signature_file: str, n: int, d: int, e: int) -> bool:
    """Подписание файла с помощью алгоритма RSA."""
    try:
        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")
        
        # Подписываем каждый байт хеша отдельно
        signatures = []
        for byte in file_hash:
            # Подпись байта: s = h^d mod n
            signature = mod_pow(byte, d, n)
            signatures.append(signature)
        
        # Сохраняем подпись
        with open(signature_file, 'w') as f:
            f.write(f"# RSA Signature for {os.path.basename(input_file)}\n")
            f.write(f"# Hash: {file_hash.hex()}\n")
            f.write(f"# Modulus: {n}\n")
            f.write(f"# Public exponent: {e}\n")
            f.write("# Signatures (one per hash byte):\n")
            for i, sig in enumerate(signatures):
                f.write(f"{sig}\n")
        
        print(f"Подпись сохранена в файл: {signature_file}")
        return True
    except Exception as e:
        print(f"Ошибка при подписании: {e}")
        return False


def verify_signature(input_file: str, signature_file: str) -> bool:
    """Проверка подписи файла."""
    try:
        # Читаем подпись
        with open(signature_file, 'r') as f:
            lines = f.readlines()
        
        # Извлекаем ключи и подписи
        n = None
        e = None
        signatures = []
        
        for line in lines:
            line = line.strip()
            if line.startswith('# Modulus:'):
                n = int(line.split(':')[1].strip())
            elif line.startswith('# Public exponent:'):
                e = int(line.split(':')[1].strip())
            elif line and not line.startswith('#'):
                signatures.append(int(line))
        
        if n is None or e is None:
            print("Ошибка: не найдены ключи в файле подписи")
            return False
        
        # Вычисляем хеш файла
        file_hash = compute_file_hash(input_file)
        print(f"Хеш файла (SHA-256): {file_hash.hex()}")
        
        # Проверяем каждую подпись
        if len(signatures) != len(file_hash):
            print(f"Ошибка: количество подписей ({len(signatures)}) не совпадает с длиной хеша ({len(file_hash)})")
            return False
        
        for i, (byte, signature) in enumerate(zip(file_hash, signatures)):
            # Проверка подписи: h' = s^e mod n
            recovered_hash_byte = mod_pow(signature, e, n)
            if recovered_hash_byte != byte:
                print(f"Ошибка проверки подписи для байта {i}: ожидалось {byte}, получено {recovered_hash_byte}")
                return False
        
        print("Подпись корректна!")
        return True
    except Exception as e:
        print(f"Ошибка при проверке подписи: {e}")
        return False


def rsa_signature_demo(n: int, e: int, d: int, p: int, q: int):
    """Демонстрация работы алгоритма электронной подписи RSA."""
    print("=== Демонстрация алгоритма электронной подписи RSA ===")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"d = {d}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"φ(n) = {(p-1)*(q-1)}")
    print()
    
    # Тестируем на нескольких байтах хеша
    test_hash_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c
    
    print("Тестирование подписания/проверки:")
    for h in test_hash_bytes:
        # Подписание
        s = mod_pow(h, d, n)
        
        # Проверка
        h_recovered = mod_pow(s, e, n)
        
        print(f"h={h} -> s={s} -> h'={h_recovered} {'✓' if h == h_recovered else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Алгоритм электронной подписи RSA')
    parser.add_argument('--mode', choices=['sign', 'verify', 'demo'], default='demo',
                        help='Режим работы: sign — подписание, verify — проверка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--signature', type=str, help='Файл подписи')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простых чисел')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()
    
    print('=== Лабораторная работа №8: Алгоритм электронной подписи RSA ===')
    
    # Выбор режима генерации ключей
    key_mode = input("Выберите режим генерации ключей (input — ввод с клавиатуры, rand — генерация): ").strip().lower()
    
    if key_mode == 'input':
        try:
            p = int(input('Введите простое число p: ').strip())
            q = int(input('Введите простое число q: ').strip())
            e = int(input('Введите открытый ключ e: ').strip())
            
            # Проверяем корректность p и q
            if not is_probable_prime_fermat(p) or not is_probable_prime_fermat(q):
                print("Ошибка: p и q должны быть простыми числами")
                sys.exit(1)
            
            if p == q:
                print("Ошибка: p и q должны быть различными")
                sys.exit(1)
            
            # Вычисляем n и φ(n)
            n = p * q
            phi_n = (p - 1) * (q - 1)
            
            # Проверяем корректность e
            if extended_gcd(e, phi_n)[0] != 1:
                print("Ошибка: e должно быть взаимно просто с φ(n)")
                sys.exit(1)
            
            # Вычисляем секретный ключ d
            _, d, _ = extended_gcd(e, phi_n)
            d = d % phi_n
            
        except Exception as e:
            print('Ошибка ввода:', e)
            sys.exit(1)
    elif key_mode == 'rand':
        n, e, d, p, q = generate_rsa_keys(args.bits, args.fermat_k)
        print(f"Сгенерированы ключи: n={n}, e={e}, d={d}, p={p}, q={q}")
    else:
        print("Неподдерживаемый режим, выход.")
        sys.exit(1)
    
    print()
    
    if args.mode == 'demo':
        rsa_signature_demo(n, e, d, p, q)
    elif args.mode == 'sign':
        if not args.input or not args.signature:
            print("Для подписания необходимо указать --input и --signature")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        print(f"Подписание файла {args.input}")
        if sign_file(args.input, args.signature, n, d, e):
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
        if verify_signature(args.input, args.signature):
            print("Проверка завершена успешно")
        else:
            print("Ошибка при проверке подписи")
    
    print('\nГотово.')
