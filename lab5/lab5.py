"""
Лабораторная работа №5 — шифр Эль-Гамаля (Python)

Реализация шифра Эль-Гамаля для шифрования и расшифровки файлов.
Шифр Эль-Гамаля использует ключи: p (простое число), g (первообразный корень), C2 (секретный ключ).
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


def gen_safe_prime(bits: int = 32, k: int = 8) -> Tuple[int, int]:
    """Генерация безопасного простого p = 2*q + 1.
    
    Возвращает (p, q), где p и q — вероятно-простые.
    """
    if bits < 3:
        raise ValueError('bits must be >= 3 для генерации безопасного простого')
    
    while True:
        # Генерируем q с длиной на 1 бит меньше, чтобы p имел нужную длину
        q = gen_probable_prime(bits - 1, k)
        p = 2 * q + 1
        if is_probable_prime_fermat(p, k=k):
            return p, q


def find_primitive_root(p: int, q: int) -> int:
    """Поиск первообразного корня g по модулю безопасного простого p.
    
    Используется тот факт, что для безопасного простого p = 2q + 1,
    число g является первообразным корнем, если g^2 != 1 (mod p) и g^q != 1 (mod p).
    """
    g = 2
    while g < p:
        # Условия для того, чтобы g было первообразным корнем
        if mod_pow(g, 2, p) != 1 and mod_pow(g, q, p) != 1:
            return g
        g += 1
    raise ValueError("Не удалось найти первообразный корень")


def generate_elgamal_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int]:
    """Генерация ключей для шифра Эль-Гамаля.
    
    Возвращает (p, g, C2, D2), где:
    - p - простое число
    - g - первообразный корень по модулю p
    - C2 - секретный ключ для шифрования
    - D2 - секретный ключ для расшифровки
    """
    # Генерируем безопасное простое число p
    p, q = gen_safe_prime(bits, fermat_k)
    
    # Находим первообразный корень g
    g = find_primitive_root(p, q)
    
    # Генерируем секретный ключ C2
    C2 = random.randint(2, p - 2)
    
    # Вычисляем открытый ключ D2 = g^C2 mod p
    D2 = mod_pow(g, C2, p)
    
    return p, g, C2, D2


def elgamal_encrypt_file(input_file: str, output_file: str, p: int, g: int, D2: int) -> bool:
    """Шифрование файла с помощью шифра Эль-Гамаля."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = []
        for byte in data:
            # Генерируем случайное k для каждого байта
            k = random.randint(2, p - 2)
            
            # Шифруем байт
            # Шаг 1: r = g^k mod p
            r = mod_pow(g, k, p)
            # Шаг 2: e = M * D2^k mod p
            e = (byte * mod_pow(D2, k, p)) % p
            
            encrypted_data.extend([r, e])
        
        with open(output_file, 'wb') as f:
            # Сохраняем зашифрованные данные
            for encrypted_value in encrypted_data:
                if encrypted_value > 255:
                    # Для больших чисел используем 4 байта
                    f.write(encrypted_value.to_bytes(4, 'big'))
                else:
                    f.write(bytes([encrypted_value]))
        
        return True
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")
        return False


def elgamal_decrypt_file(input_file: str, output_file: str, p: int, C2: int) -> bool:
    """Расшифровка файла с помощью шифра Эль-Гамаля."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        decrypted_data = []
        i = 0
        while i < len(data):
            # Читаем пару (r, e)
            if i + 4 <= len(data):
                # Проверяем, является ли это 4-байтовым числом
                r = int.from_bytes(data[i:i+4], 'big')
                if r > 255:
                    # Это 4-байтовое число
                    i += 4
                else:
                    # Это обычный байт
                    r = data[i]
                    i += 1
            else:
                # Обычный байт
                r = data[i]
                i += 1
            
            # Читаем e
            if i + 4 <= len(data):
                e = int.from_bytes(data[i:i+4], 'big')
                if e > 255:
                    i += 4
                else:
                    e = data[i]
                    i += 1
            else:
                e = data[i]
                i += 1
            
            # Расшифровываем
            # M = e * r^(-C2) mod p
            r_inv = mod_pow(r, p - 1 - C2, p)
            M = (e * r_inv) % p
            decrypted_data.append(M)
        
        with open(output_file, 'wb') as f:
            f.write(bytes(decrypted_data))
        
        return True
    except Exception as e:
        print(f"Ошибка при расшифровке: {e}")
        return False


def elgamal_demo(p: int, g: int, C2: int, D2: int):
    """Демонстрация работы шифра Эль-Гамаля."""
    print("=== Демонстрация шифра Эль-Гамаля ===")
    print(f"p = {p}")
    print(f"g = {g}")
    print(f"C2 = {C2}")
    print(f"D2 = {D2}")
    print()
    
    # Тестируем на нескольких байтах
    test_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c
    
    print("Тестирование шифрования/расшифровки:")
    for M in test_bytes:
        # Генерируем случайное k
        k = random.randint(2, p - 2)
        
        # Шифрование
        r = mod_pow(g, k, p)
        e = (M * mod_pow(D2, k, p)) % p
        
        # Расшифровка
        r_inv = mod_pow(r, p - 1 - C2, p)
        M_decrypted = (e * r_inv) % p
        
        print(f"M={M} -> r={r}, e={e} -> M'={M_decrypted} {'✓' if M == M_decrypted else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Шифр Эль-Гамаля — шифрование и расшифровка файлов')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt', 'demo'], default='demo',
                        help='Режим работы: encrypt — шифрование, decrypt — расшифровка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--output', type=str, help='Выходной файл')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простого числа')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()
    
    print('=== Лабораторная работа №5: Шифр Эль-Гамаля ===')
    
    # Выбор режима генерации ключей
    key_mode = input("Выберите режим генерации ключей (input — ввод с клавиатуры, rand — генерация): ").strip().lower()
    
    if key_mode == 'input':
        try:
            p = int(input('Введите простое число p: ').strip())
            g = int(input('Введите первообразный корень g: ').strip())
            C2 = int(input('Введите секретный ключ C2: ').strip())
            
            # Проверяем корректность p
            if not is_probable_prime_fermat(p):
                print("Ошибка: p должно быть простым числом")
                sys.exit(1)
            
            # Вычисляем открытый ключ D2
            D2 = mod_pow(g, C2, p)
            
        except Exception as e:
            print('Ошибка ввода:', e)
            sys.exit(1)
    elif key_mode == 'rand':
        p, g, C2, D2 = generate_elgamal_keys(args.bits, args.fermat_k)
        print(f"Сгенерированы ключи: p={p}, g={g}, C2={C2}, D2={D2}")
    else:
        print("Неподдерживаемый режим, выход.")
        sys.exit(1)
    
    print()
    
    if args.mode == 'demo':
        elgamal_demo(p, g, C2, D2)
    elif args.mode == 'encrypt':
        if not args.input or not args.output:
            print("Для шифрования необходимо указать --input и --output")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        print(f"Шифрование файла {args.input} -> {args.output}")
        if elgamal_encrypt_file(args.input, args.output, p, g, D2):
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
        if elgamal_decrypt_file(args.input, args.output, p, C2):
            print("Расшифровка завершена успешно")
        else:
            print("Ошибка при расшифровке")
    
    print('\nГотово.')
