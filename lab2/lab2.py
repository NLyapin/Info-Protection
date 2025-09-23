import math

def is_prime(n):
    """Проверка простого числа (аналог Farm)"""
    if n <= 1:
        return False
    if n <= 3:
        return True
    if n % 2 == 0 or n % 3 == 0:
        return False
    i = 5
    while i * i <= n:
        if n % i == 0 or n % (i + 2) == 0:
            return False
        i += 6
    return True

def baby_step_giant_step(y, a, p):
    if y >= p or not is_prime(p):
        print("Ошибка y >= p или p не простое число")
        return

    k = math.ceil(math.sqrt(p))

    A = []
    B = []

    # Заполнение массивов A и B
    for i in range(k):
        A.append([y * pow(a, i, p) % p, i])
        B.append([pow(a, (i + 1) * k, p) % p, i + 1])

    # Сортировка массивов
    A.sort(key=lambda x: x[0])
    B.sort(key=lambda x: x[0])

    # Вывод массивов для проверки
    print("A[0]:", [x[0] for x in A])
    print("A[1]:", [x[1] for x in A])
    print("B[0]:", [x[0] for x in B])
    print("B[1]:", [x[1] for x in B])

    print("\nx = ", end='')

    i = 0
    j = 0
    while i < k and j < k:
        if A[i][0] == B[j][0]:
            x = B[j][1] * k - A[i][1]
            print(x, end=' ')
            # Обработка повторяющихся значений
            if i + 1 < k and A[i][0] == A[i + 1][0]:
                i += 1
            else:
                j += 1
        elif A[i][0] > B[j][0]:
            j += 1
        else:
            i += 1

# Пример использования:
baby_step_giant_step(y=4, a=5, p=7)
