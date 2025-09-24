"""
Лабораторная работа №6 — шифр RSA (Python)

Реализация шифра RSA для шифрования и расшифровки файлов.
Шифр RSA использует ключи: p, q (простые числа), C2 (открытый ключ), D2 (секретный ключ).
"""

import random
import sys
import argparse
import os
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


def generate_rsa_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int, int]:
    """Генерация ключей для шифра RSA.
    
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


def rsa_encrypt_file(input_file: str, output_file: str, n: int, e: int) -> bool:
    """Шифрование файла с помощью шифра RSA."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = []
        for byte in data:
            # Шифруем каждый байт
            # C = M^e mod n
            C = mod_pow(byte, e, n)
            encrypted_data.append(C)
        
        with open(output_file, 'w') as f:
            # Сохраняем ключи и зашифрованные данные
            f.write(f"# RSA Encrypted File\n")
            f.write(f"# n={n}\n")
            f.write(f"# e={e}\n")
            f.write(f"# d={d}\n")
            f.write("# Encrypted data:\n")
            for encrypted_value in encrypted_data:
                f.write(f"{encrypted_value}\n")
        
        return True
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")
        return False


def rsa_decrypt_file(input_file: str, output_file: str) -> bool:
    """Расшифровка файла с помощью шифра RSA."""
    try:
        with open(input_file, 'r') as f:
            lines = f.readlines()
        
        # Извлекаем ключи
        n = None
        d = None
        
        for line in lines:
            line = line.strip()
            if line.startswith('# n='):
                n = int(line.split('=')[1])
            elif line.startswith('# d='):
                d = int(line.split('=')[1])
        
        if n is None or d is None:
            print("Ошибка: не найдены ключи в файле")
            return False
        
        # Читаем зашифрованные данные
        encrypted_data = []
        for line in lines:
            line = line.strip()
            if line and not line.startswith('#'):
                encrypted_data.append(int(line))
        
        decrypted_data = []
        for encrypted_byte in encrypted_data:
            # Расшифровываем
            # M = C^d mod n
            M = mod_pow(encrypted_byte, d, n)
            decrypted_data.append(M)
        
        with open(output_file, 'wb') as f:
            f.write(bytes(decrypted_data))
        
        return True
    except Exception as e:
        print(f"Ошибка при расшифровке: {e}")
        return False


def rsa_demo(n: int, e: int, d: int, p: int, q: int):
    """Демонстрация работы шифра RSA."""
    print("=== Демонстрация шифра RSA ===")
    print(f"n = {n}")
    print(f"e = {e}")
    print(f"d = {d}")
    print(f"p = {p}")
    print(f"q = {q}")
    print(f"φ(n) = {(p-1)*(q-1)}")
    print()
    
    # Тестируем на нескольких байтах
    test_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c
    
    print("Тестирование шифрования/расшифровки:")
    for M in test_bytes:
        # Шифрование
        C = mod_pow(M, e, n)
        
        # Расшифровка
        M_decrypted = mod_pow(C, d, n)
        
        print(f"M={M} -> C={C} -> M'={M_decrypted} {'✓' if M == M_decrypted else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Шифр RSA — шифрование и расшифровка файлов')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt', 'demo'], default='demo',
                        help='Режим работы: encrypt — шифрование, decrypt — расшифровка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--output', type=str, help='Выходной файл')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простых чисел')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()
    
    print('=== Лабораторная работа №6: Шифр RSA ===')
    
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
        rsa_demo(n, e, d, p, q)
    elif args.mode == 'encrypt':
        if not args.input or not args.output:
            print("Для шифрования необходимо указать --input и --output")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        print(f"Шифрование файла {args.input} -> {args.output}")
        if rsa_encrypt_file(args.input, args.output, n, e):
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
        
        print(f"Расшифровка файла {args.input} -> {args.output}")
        if rsa_decrypt_file(args.input, args.output):
            print("Расшифровка завершена успешно")
        else:
            print("Ошибка при расшифровке")
    
    print('\nГотово.')
