"""
Лабораторная работа №4 — шифр Шамира (Python)

Реализация шифра Шамира для шифрования и расшифровки файлов.
Шифр Шамира использует три ключа: p (простое число), C1, C2 (секретные ключи).
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


def generate_shamir_keys(bits: int = 32, fermat_k: int = 8) -> Tuple[int, int, int, int, int]:
    """Генерация ключей для шифра Шамира.
    
    Возвращает (p, C1, C2, D1, D2), где:
    - p - простое число
    - C1, C2 - секретные ключи для шифрования
    - D1, D2 - секретные ключи для расшифровки
    """
    # Генерируем простое число p
    p = gen_probable_prime(bits, fermat_k)
    
    # Генерируем C1 и C2 такие, что gcd(C1, p-1) = 1 и gcd(C2, p-1) = 1
    while True:
        C1 = random.randint(2, p - 2)
        g1, _, _ = extended_gcd(C1, p - 1)
        if g1 == 1:
            break
    
    while True:
        C2 = random.randint(2, p - 2)
        g2, _, _ = extended_gcd(C2, p - 1)
        if g2 == 1:
            break
    
    # Вычисляем D1 и D2 как обратные элементы
    _, D1, _ = extended_gcd(C1, p - 1)
    D1 = D1 % (p - 1)
    
    _, D2, _ = extended_gcd(C2, p - 1)
    D2 = D2 % (p - 1)
    
    return p, C1, C2, D1, D2


def shamir_encrypt_file(input_file: str, output_file: str, p: int, C1: int, C2: int) -> bool:
    """Шифрование файла с помощью шифра Шамира."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        encrypted_data = []
        for byte in data:
            # Шифруем каждый байт
            # Шаг 1: x1 = M^C1 mod p
            x1 = mod_pow(byte, C1, p)
            # Шаг 2: x2 = x1^C2 mod p
            x2 = mod_pow(x1, C2, p)
            encrypted_data.append(x2)
        
        with open(output_file, 'wb') as f:
            # Сохраняем зашифрованные данные как байты
            for encrypted_byte in encrypted_data:
                # Преобразуем в байт, учитывая что результат может быть больше 255
                if encrypted_byte > 255:
                    # Для больших чисел используем 4 байта
                    f.write(encrypted_byte.to_bytes(4, 'big'))
                else:
                    f.write(bytes([encrypted_byte]))
        
        return True
    except Exception as e:
        print(f"Ошибка при шифровании: {e}")
        return False


def shamir_decrypt_file(input_file: str, output_file: str, p: int, D1: int, D2: int) -> bool:
    """Расшифровка файла с помощью шифра Шамира."""
    try:
        with open(input_file, 'rb') as f:
            data = f.read()
        
        decrypted_data = []
        i = 0
        while i < len(data):
            # Читаем зашифрованный байт
            if i + 4 <= len(data):
                # Проверяем, является ли это 4-байтовым числом
                encrypted_byte = int.from_bytes(data[i:i+4], 'big')
                if encrypted_byte > 255:
                    # Это 4-байтовое число
                    i += 4
                else:
                    # Это обычный байт
                    encrypted_byte = data[i]
                    i += 1
            else:
                # Обычный байт
                encrypted_byte = data[i]
                i += 1
            
            # Расшифровываем
            # Шаг 1: y1 = x2^D2 mod p
            y1 = mod_pow(encrypted_byte, D2, p)
            # Шаг 2: M = y1^D1 mod p
            M = mod_pow(y1, D1, p)
            decrypted_data.append(M)
        
        with open(output_file, 'wb') as f:
            f.write(bytes(decrypted_data))
        
        return True
    except Exception as e:
        print(f"Ошибка при расшифровке: {e}")
        return False


def shamir_demo(p: int, C1: int, C2: int, D1: int, D2: int):
    """Демонстрация работы шифра Шамира."""
    print("=== Демонстрация шифра Шамира ===")
    print(f"p = {p}")
    print(f"C1 = {C1}, C2 = {C2}")
    print(f"D1 = {D1}, D2 = {D2}")
    print()
    
    # Тестируем на нескольких байтах
    test_bytes = [65, 66, 67, 97, 98, 99]  # A, B, C, a, b, c
    
    print("Тестирование шифрования/расшифровки:")
    for M in test_bytes:
        # Шифрование
        x1 = mod_pow(M, C1, p)
        x2 = mod_pow(x1, C2, p)
        
        # Расшифровка
        y1 = mod_pow(x2, D2, p)
        M_decrypted = mod_pow(y1, D1, p)
        
        print(f"M={M} -> x1={x1} -> x2={x2} -> y1={y1} -> M'={M_decrypted} {'✓' if M == M_decrypted else '✗'}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Шифр Шамира — шифрование и расшифровка файлов')
    parser.add_argument('--mode', choices=['encrypt', 'decrypt', 'demo'], default='demo',
                        help='Режим работы: encrypt — шифрование, decrypt — расшифровка, demo — демонстрация')
    parser.add_argument('--input', type=str, help='Входной файл')
    parser.add_argument('--output', type=str, help='Выходной файл')
    parser.add_argument('--bits', type=int, default=32, help='Число бит для генерации простого числа')
    parser.add_argument('--fermat-k', type=int, default=8, help='Число испытаний для теста Ферма')
    args = parser.parse_args()
    
    print('=== Лабораторная работа №4: Шифр Шамира ===')
    
    # Выбор режима генерации ключей
    key_mode = input("Выберите режим генерации ключей (input — ввод с клавиатуры, rand — генерация): ").strip().lower()
    
    if key_mode == 'input':
        try:
            p = int(input('Введите простое число p: ').strip())
            C1 = int(input('Введите C1: ').strip())
            C2 = int(input('Введите C2: ').strip())
            
            # Проверяем корректность p
            if not is_probable_prime_fermat(p):
                print("Ошибка: p должно быть простым числом")
                sys.exit(1)
            
            # Проверяем корректность C1 и C2
            g1, _, _ = extended_gcd(C1, p - 1)
            g2, _, _ = extended_gcd(C2, p - 1)
            if g1 != 1 or g2 != 1:
                print("Ошибка: C1 и C2 должны быть взаимно просты с p-1")
                sys.exit(1)
            
            # Вычисляем D1 и D2
            _, D1, _ = extended_gcd(C1, p - 1)
            D1 = D1 % (p - 1)
            
            _, D2, _ = extended_gcd(C2, p - 1)
            D2 = D2 % (p - 1)
            
        except Exception as e:
            print('Ошибка ввода:', e)
            sys.exit(1)
    elif key_mode == 'rand':
        p, C1, C2, D1, D2 = generate_shamir_keys(args.bits, args.fermat_k)
        print(f"Сгенерированы ключи: p={p}, C1={C1}, C2={C2}, D1={D1}, D2={D2}")
    else:
        print("Неподдерживаемый режим, выход.")
        sys.exit(1)
    
    print()
    
    if args.mode == 'demo':
        shamir_demo(p, C1, C2, D1, D2)
    elif args.mode == 'encrypt':
        if not args.input or not args.output:
            print("Для шифрования необходимо указать --input и --output")
            sys.exit(1)
        if not os.path.exists(args.input):
            print(f"Файл {args.input} не найден")
            sys.exit(1)
        
        print(f"Шифрование файла {args.input} -> {args.output}")
        if shamir_encrypt_file(args.input, args.output, p, C1, C2):
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
        if shamir_decrypt_file(args.input, args.output, p, D1, D2):
            print("Расшифровка завершена успешно")
        else:
            print("Ошибка при расшифровке")
    
    print('\nГотово.')
